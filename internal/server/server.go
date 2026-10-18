package server

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"panbox/internal/core"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	DB           *sql.DB
	WebDir       string
	SecureCookie bool
}
type principal struct {
	UserID, TokenID, RepoID, Kind string
	Scopes                        map[string]bool
	Admin                         bool
	AdminOwner                    bool
	Session                       bool
}
type ctxKey struct{}

var permissions = []string{"repos:read", "repos:write", "scans:read", "scans:write", "findings:read", "findings:recast", "reports:export", "rbac:manage", "tokens:manage", "audit:read"}
var secretPattern = regexp.MustCompile(`(?i)(glpat-[a-z0-9_-]{12,}|gh[pousr]_[a-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:password|secret|token)\s*[:=]\s*[^\s,;]{8,})`)

func containsSecret(s string) bool { return secretPattern.MatchString(s) }

func Open(dsn, webDir string, secureCookie bool) (*Server, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		return nil, err
	}
	s := &Server{db, webDir, secureCookie}
	if err = s.migrate(ctx); err != nil {
		return nil, err
	}
	if err = s.seed(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) migrate(ctx context.Context) error {
	dir := os.Getenv("PANBOX_MIGRATIONS_DIR")
	if dir == "" {
		dir = "migrations"
	}
	files, err := filepath.Glob(filepath.Join(dir, "[0-9][0-9][0-9]_*.sql"))
	if err != nil || len(files) == 0 {
		return errors.New("migration files unavailable")
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if _, err = s.DB.ExecContext(ctx, string(b)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) seed(ctx context.Context) error {
	roles := map[string][]string{
		"admin":             permissions,
		"security_reviewer": {"repos:read", "scans:read", "findings:read", "findings:recast", "reports:export", "audit:read"},
		"developer":         {"repos:read", "scans:read", "findings:read", "reports:export"},
		"executive_viewer":  {"repos:read", "scans:read", "reports:export"},
		"scanner_ci":        {"scans:write"},
	}
	for name, perms := range roles {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO roles(name,built_in) VALUES($1,true) ON CONFLICT DO NOTHING`, name); err != nil {
			return err
		}
		for _, perm := range perms {
			if _, err := s.DB.ExecContext(ctx, `INSERT INTO role_permissions(role_name,permission) VALUES($1,$2) ON CONFLICT DO NOTHING`, name, perm); err != nil {
				return err
			}
		}
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	email := os.Getenv("PANBOX_BOOTSTRAP_EMAIL")
	password := os.Getenv("PANBOX_BOOTSTRAP_PASSWORD")
	if email == "" || len(password) < 12 {
		return errors.New("set PANBOX_BOOTSTRAP_EMAIL and PANBOX_BOOTSTRAP_PASSWORD (12+ characters) for first start")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	id := core.ID()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)`, id, strings.ToLower(email), string(hash)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_name) VALUES($1,'admin')`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	jsonOut(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		fail(w, 400, "unexpected trailing JSON")
		return false
	}
	return true
}
func who(r *http.Request) principal     { p, _ := r.Context().Value(ctxKey{}).(principal); return p }
func has(p principal, perm string) bool { return p.Admin || p.Scopes[perm] }
func require(w http.ResponseWriter, r *http.Request, perm string) bool {
	if !has(who(r), perm) {
		fail(w, 403, "permission denied: "+perm)
		return false
	}
	return true
}
func (s *Server) repoAllowed(ctx context.Context, p principal, repo string) bool {
	if p.RepoID != "" && p.RepoID != repo {
		return false
	}
	if p.Admin || p.AdminOwner {
		return true
	}
	var ok bool
	_ = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM repository_members m JOIN repositories r ON r.id=m.repository_id WHERE m.repository_id=$1 AND m.user_id=$2 AND r.archived_at IS NULL)`, repo, p.UserID).Scan(&ok)
	return ok
}
func (s *Server) audit(ctx context.Context, actor, action, target string, detail any) {
	b, _ := json.Marshal(detail)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target,detail) VALUES($1,$2,$3,$4,$5)`, core.ID(), actor, action, target, string(b))
	if err != nil {
		log.Printf("audit insert failed: %v", err)
	}
}

func (s *Server) authenticate(r *http.Request) (principal, error) {
	ctx := r.Context()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer != "" && bearer != r.Header.Get("Authorization") {
		var p principal
		var scopesJSON []byte
		var expired bool
		err := s.DB.QueryRowContext(ctx, `SELECT c.id,c.owner_id,c.kind,COALESCE(c.repository_id,''),c.scopes, (c.expires_at IS NOT NULL AND c.expires_at<now()) OR c.revoked_at IS NOT NULL, EXISTS(SELECT 1 FROM user_roles WHERE user_id=c.owner_id AND role_name='admin') FROM credentials c JOIN users u ON u.id=c.owner_id WHERE c.secret_hash=$1 AND NOT u.disabled`, core.Hash(bearer)).Scan(&p.TokenID, &p.UserID, &p.Kind, &p.RepoID, &scopesJSON, &expired, &p.AdminOwner)
		if err != nil || expired {
			return p, errors.New("invalid credential")
		}
		var scopes []string
		_ = json.Unmarshal(scopesJSON, &scopes)
		p.Scopes = map[string]bool{}
		for _, x := range scopes {
			p.Scopes[x] = true
		}
		if !p.AdminOwner {
			rows, err := s.DB.QueryContext(ctx, `SELECT DISTINCT rp.permission FROM user_roles ur JOIN role_permissions rp ON rp.role_name=ur.role_name WHERE ur.user_id=$1`, p.UserID)
			if err != nil {
				return p, err
			}
			defer rows.Close()
			current := map[string]bool{}
			for rows.Next() {
				var permission string
				if rows.Scan(&permission) == nil {
					current[permission] = true
				}
			}
			for permission := range p.Scopes {
				if !current[permission] {
					delete(p.Scopes, permission)
				}
			}
		}
		p.Admin = false // token scopes are always bounded, even for admin owners
		return p, nil
	}
	cookie, err := r.Cookie("panbox_session")
	if err != nil {
		return principal{}, errors.New("login required")
	}
	var p principal
	var csrfHash string
	err = s.DB.QueryRowContext(ctx, `SELECT s.user_id,s.csrf_hash, EXISTS(SELECT 1 FROM user_roles WHERE user_id=s.user_id AND role_name='admin') FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.secret_hash=$1 AND s.expires_at>now() AND NOT u.disabled`, core.Hash(cookie.Value)).Scan(&p.UserID, &csrfHash, &p.Admin)
	if err != nil {
		return p, errors.New("session expired")
	}
	p.Session = true
	p.Scopes = map[string]bool{}
	rows, err := s.DB.QueryContext(ctx, `SELECT DISTINCT rp.permission FROM user_roles ur JOIN role_permissions rp ON rp.role_name=ur.role_name WHERE ur.user_id=$1`, p.UserID)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var x string
		if rows.Scan(&x) == nil {
			p.Scopes[x] = true
		}
	}
	if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
		origin := r.Header.Get("Origin")
		if origin != "" && !strings.HasSuffix(origin, "://"+r.Host) {
			return p, errors.New("origin rejected")
		}
		if subtle.ConstantTimeCompare([]byte(core.Hash(r.Header.Get("X-CSRF-Token"))), []byte(csrfHash)) != 1 {
			return p, errors.New("CSRF token required")
		}
	}
	return p, nil
}

func (s *Server) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			fail(w, 401, err.Error())
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.DB.PingContext(r.Context()); err != nil {
			fail(w, 503, "database unavailable")
			return
		}
		jsonOut(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/logout", s.protected(s.logout))
	mux.HandleFunc("GET /v1/me", s.protected(s.me))
	mux.HandleFunc("GET /v1/roles", s.protected(s.roles))
	mux.HandleFunc("PUT /v1/roles/{name}", s.protected(s.putRole))
	mux.HandleFunc("POST /v1/users", s.protected(s.createUser))
	mux.HandleFunc("PUT /v1/users/{id}/roles", s.protected(s.assignRoles))
	mux.HandleFunc("GET /v1/users", s.protected(s.users))
	mux.HandleFunc("POST /v1/credentials", s.protected(s.createCredential))
	mux.HandleFunc("GET /v1/credentials", s.protected(s.credentials))
	mux.HandleFunc("DELETE /v1/credentials/{id}", s.protected(s.revokeCredential))
	mux.HandleFunc("POST /v1/credentials/{id}/rotate", s.protected(s.rotateCredential))
	mux.HandleFunc("GET /v1/repos", s.protected(s.repos))
	mux.HandleFunc("GET /v1/scm-connections", s.protected(s.listConnections))
	mux.HandleFunc("POST /v1/scm-connections", s.protected(s.saveConnection))
	mux.HandleFunc("PUT /v1/scm-connections/{id}", s.protected(s.saveConnection))
	mux.HandleFunc("DELETE /v1/scm-connections/{id}", s.protected(s.deleteConnection))
	mux.HandleFunc("GET /v1/scm-connections/{id}/repositories", s.protected(s.discoverConnection))
	mux.HandleFunc("POST /v1/scm-connections/{id}/sync", s.protected(s.syncConnection))
	mux.HandleFunc("POST /v1/scm-connections/{id}/reinclude", s.protected(s.allowSCMReimport))
	mux.HandleFunc("POST /v1/repos/inspect", s.protected(s.inspectRepo))
	mux.HandleFunc("POST /v1/repos", s.protected(s.createRepo))
	mux.HandleFunc("GET /v1/repos/{id}", s.protected(s.repoDetail))
	mux.HandleFunc("PUT /v1/repos/{id}", s.protected(s.updateRepo))
	mux.HandleFunc("DELETE /v1/repos/{id}", s.protected(s.deleteRepo))
	mux.HandleFunc("POST /v1/repos/{id}/restore", s.protected(s.restoreRepo))
	mux.HandleFunc("POST /v1/repos/{id}/recheck-scm", s.protected(s.recheckRepoSCM))
	mux.HandleFunc("POST /v1/repos/{id}/scan-tokens", s.protected(s.scanToken))
	mux.HandleFunc("GET /v1/repos/{id}/scan-config", s.protected(s.getScanConfig))
	mux.HandleFunc("PUT /v1/repos/{id}/scan-config", s.protected(s.putScanConfig))
	mux.HandleFunc("PUT /v1/repos/{id}/members/{user}", s.protected(s.addRepoMember))
	mux.HandleFunc("DELETE /v1/repos/{id}/members/{user}", s.protected(s.removeRepoMember))
	mux.HandleFunc("GET /v1/scans", s.protected(s.scans))
	mux.HandleFunc("POST /v1/scans", s.protected(s.ingest))
	mux.HandleFunc("GET /v1/scans/{id}", s.protected(s.scan))
	mux.HandleFunc("GET /v1/scans/{id}/findings", s.protected(s.scanFindings))
	mux.HandleFunc("GET /v1/findings", s.protected(s.findings))
	mux.HandleFunc("GET /v1/findings/{id}", s.protected(s.findingDetail))
	mux.HandleFunc("POST /v1/findings/{id}/disposition", s.protected(s.setFindingDisposition))
	mux.HandleFunc("GET /v1/findings/{id}/dispositions", s.protected(s.findingDispositionHistory))
	mux.HandleFunc("POST /v1/findings/{id}/recast", s.protected(s.recastFinding))
	mux.HandleFunc("GET /v1/findings/{id}/recasts", s.protected(s.findingRecasts))
	mux.HandleFunc("GET /v1/metrics/overview", s.protected(s.overview))
	mux.HandleFunc("GET /v1/reports/technical", s.protected(s.report))
	mux.HandleFunc("GET /v1/audit-events", s.protected(s.auditEvents))
	mux.HandleFunc("GET /v1/meta", s.protected(func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, 200, map[string]any{"permissions": permissions, "version": "0.1.0"})
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			fail(w, 404, "not found")
			return
		}
		clean := strings.TrimPrefix(filepath.Clean(r.URL.Path), string(filepath.Separator))
		path := filepath.Join(s.WebDir, clean)
		if r.URL.Path == "/" {
			path = filepath.Join(s.WebDir, "index.html")
		}
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join(s.WebDir, "index.html")
		}
		http.ServeFile(w, r, path)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if !decode(w, r, &in) {
		return
	}
	var id, hash string
	err := s.DB.QueryRowContext(r.Context(), `SELECT id,password_hash FROM users WHERE email=$1 AND NOT disabled`, strings.ToLower(in.Email)).Scan(&id, &hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		fail(w, 401, "invalid login")
		return
	}
	secret := core.Secret("pb_s_")
	csrf := core.Secret("pb_c_")
	_, err = s.DB.ExecContext(r.Context(), `INSERT INTO sessions(secret_hash,user_id,csrf_hash,expires_at) VALUES($1,$2,$3,now()+interval '12 hours')`, core.Hash(secret), id, core.Hash(csrf))
	if err != nil {
		fail(w, 500, "session unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "panbox_session", Value: secret, Path: "/", HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	s.audit(r.Context(), id, "login", id, map[string]any{})
	jsonOut(w, 200, map[string]string{"csrf_token": csrf})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("panbox_session"); err == nil {
		_, _ = s.DB.ExecContext(r.Context(), `DELETE FROM sessions WHERE secret_hash=$1`, core.Hash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "panbox_session", Path: "/", MaxAge: -1, HttpOnly: true})
	jsonOut(w, 200, map[string]string{"status": "logged out"})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	var email string
	_ = s.DB.QueryRowContext(r.Context(), `SELECT email FROM users WHERE id=$1`, p.UserID).Scan(&email)
	jsonOut(w, 200, map[string]any{"id": p.UserID, "email": email, "admin": p.Admin, "permissions": p.Scopes, "kind": p.Kind})
}

func (s *Server) roles(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "rbac:manage") {
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT name,description,built_in FROM roles ORDER BY name`)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var name, desc string
		var builtin bool
		_ = rows.Scan(&name, &desc, &builtin)
		pr, _ := s.DB.QueryContext(r.Context(), `SELECT permission FROM role_permissions WHERE role_name=$1 ORDER BY permission`, name)
		ps := []string{}
		if pr != nil {
			for pr.Next() {
				var p string
				_ = pr.Scan(&p)
				ps = append(ps, p)
			}
			pr.Close()
		}
		out = append(out, map[string]any{"name": name, "description": desc, "built_in": builtin, "permissions": ps})
	}
	jsonOut(w, 200, out)
}
func validPerms(ps []string) bool {
	for _, p := range ps {
		ok := false
		for _, x := range permissions {
			if x == p {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func (s *Server) putRole(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "rbac:manage") {
		return
	}
	name := r.PathValue("name")
	if name == "admin" {
		fail(w, 403, "admin is immutable")
		return
	}
	if len(name) < 2 || len(name) > 40 || strings.ContainsAny(name, " /\\") {
		fail(w, 400, "invalid role name")
		return
	}
	var in struct {
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !validPerms(in.Permissions) {
		fail(w, 400, "unknown permission")
		return
	}
	for _, permission := range in.Permissions {
		if permission == "rbac:manage" {
			fail(w, 403, "rbac:manage is admin-only")
			return
		}
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO roles(name,description) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET description=$2`, name, in.Description)
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `DELETE FROM role_permissions WHERE role_name=$1`, name)
	}
	for _, p := range in.Permissions {
		if err != nil {
			break
		}
		_, err = tx.ExecContext(r.Context(), `INSERT INTO role_permissions(role_name,permission) VALUES($1,$2)`, name, p)
	}
	if err != nil || tx.Commit() != nil {
		fail(w, 500, "database error")
		return
	}
	s.audit(r.Context(), who(r).UserID, "role.update", name, in)
	jsonOut(w, 200, map[string]string{"name": name})
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "rbac:manage") {
		return
	}
	var in struct{ Email, Password, Role string }
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) < 12 || in.Role == "admin" {
		fail(w, 400, "password must be 12+ characters; admin assignment is separate")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	id := core.ID()
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)`, id, strings.ToLower(in.Email), string(hash))
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO user_roles(user_id,role_name) VALUES($1,$2)`, id, in.Role)
	}
	if err != nil || tx.Commit() != nil {
		fail(w, 400, "user or role invalid")
		return
	}
	s.audit(r.Context(), who(r).UserID, "user.create", id, map[string]string{"email": in.Email, "role": in.Role})
	jsonOut(w, 201, map[string]string{"id": id})
}
func (s *Server) assignRoles(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "rbac:manage") {
		return
	}
	id := r.PathValue("id")
	var in struct {
		Roles []string `json:"roles"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Roles) == 0 {
		fail(w, 400, "at least one role required")
		return
	}
	for _, x := range in.Roles {
		if x == "admin" {
			fail(w, 403, "admin role cannot be assigned via API")
			return
		}
	}
	var isAdmin bool
	_ = s.DB.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1 AND role_name='admin')`, id).Scan(&isAdmin)
	if isAdmin {
		fail(w, 403, "admin role cannot be removed")
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `DELETE FROM user_roles WHERE user_id=$1`, id)
	for _, x := range in.Roles {
		if err != nil {
			break
		}
		_, err = tx.ExecContext(r.Context(), `INSERT INTO user_roles(user_id,role_name) VALUES($1,$2)`, id, x)
	}
	if err != nil || tx.Commit() != nil {
		fail(w, 400, "invalid role or user")
		return
	}
	s.audit(r.Context(), who(r).UserID, "user.roles", id, in)
	jsonOut(w, 200, map[string]any{"roles": in.Roles})
}
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "rbac:manage") {
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT u.id,u.email,COALESCE(array_to_json(array_agg(ur.role_name) FILTER(WHERE ur.role_name IS NOT NULL))::text,'[]') FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id GROUP BY u.id ORDER BY u.email`)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, email, raw string
		_ = rows.Scan(&id, &email, &raw)
		var roles []string
		_ = json.Unmarshal([]byte(raw), &roles)
		members := []string{}
		memberRows, err := s.DB.QueryContext(r.Context(), `SELECT repository_id FROM repository_members WHERE user_id=$1 ORDER BY repository_id`, id)
		if err == nil {
			for memberRows.Next() {
				var repo string
				_ = memberRows.Scan(&repo)
				members = append(members, repo)
			}
			memberRows.Close()
		}
		out = append(out, map[string]any{"id": id, "email": email, "roles": roles, "repositories": members})
	}
	jsonOut(w, 200, out)
}

type credentialInput struct {
	Kind         string   `json:"kind"`
	Label        string   `json:"label"`
	RepositoryID string   `json:"repository_id"`
	Scopes       []string `json:"scopes"`
	ExpiresHours int      `json:"expires_hours"`
}

func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "tokens:manage") {
		return
	}
	var in credentialInput
	if !decode(w, r, &in) {
		return
	}
	if in.Kind != "api" && in.Kind != "access" && in.Kind != "scan" {
		fail(w, 400, "invalid key kind")
		return
	}
	if in.Kind == "scan" && (in.RepositoryID == "" || len(in.Scopes) != 1 || in.Scopes[0] != "scans:write") {
		fail(w, 400, "scan key requires one repo and scans:write")
		return
	}
	if in.Kind == "access" {
		for _, scope := range in.Scopes {
			switch scope {
			case "repos:read", "scans:read", "findings:read", "reports:export", "audit:read":
			default:
				fail(w, 400, "access key must be read-only")
				return
			}
		}
	}
	if !validPerms(in.Scopes) || len(in.Scopes) == 0 || in.ExpiresHours < 1 || in.ExpiresHours > 8760 {
		fail(w, 400, "invalid scopes or expiry")
		return
	}
	for _, scope := range in.Scopes {
		if !has(who(r), scope) {
			fail(w, 403, "cannot grant scope outside own permissions")
			return
		}
	}
	if in.RepositoryID != "" && !s.repoAllowed(r.Context(), who(r), in.RepositoryID) {
		fail(w, 403, "repository denied")
		return
	}
	secret := core.Secret("pb_" + in.Kind + "_")
	id := core.ID()
	scopes, _ := json.Marshal(in.Scopes)
	_, err := s.DB.ExecContext(r.Context(), `INSERT INTO credentials(id,owner_id,kind,label,secret_hash,scopes,repository_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),now()+($8 || ' hours')::interval)`, id, who(r).UserID, in.Kind, in.Label, core.Hash(secret), string(scopes), in.RepositoryID, strconv.Itoa(in.ExpiresHours))
	if err != nil {
		fail(w, 400, "invalid credential")
		return
	}
	s.audit(r.Context(), who(r).UserID, "credential.create", id, map[string]any{"kind": in.Kind, "scopes": in.Scopes, "repository_id": in.RepositoryID})
	jsonOut(w, 201, map[string]string{"id": id, "secret": secret})
}
func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "tokens:manage") {
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT id,kind,label,scopes::text,COALESCE(repository_id,''),expires_at,revoked_at IS NOT NULL FROM credentials WHERE ($1 OR owner_id=$2) ORDER BY created_at DESC LIMIT 100`, who(r).Admin, who(r).UserID)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, kind, label, scopes, repo string
		var expiry time.Time
		var revoked bool
		_ = rows.Scan(&id, &kind, &label, &scopes, &repo, &expiry, &revoked)
		out = append(out, map[string]any{"id": id, "kind": kind, "label": label, "scopes": json.RawMessage(scopes), "repository_id": repo, "expires_at": expiry, "revoked": revoked})
	}
	jsonOut(w, 200, out)
}
func (s *Server) revokeCredential(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "tokens:manage") {
		return
	}
	id := r.PathValue("id")
	result, err := s.DB.ExecContext(r.Context(), `UPDATE credentials SET revoked_at=now() WHERE id=$1 AND ($2 OR owner_id=$3)`, id, who(r).Admin, who(r).UserID)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		fail(w, 404, "credential not found")
		return
	}
	s.audit(r.Context(), who(r).UserID, "credential.revoke", id, map[string]any{})
	jsonOut(w, 200, map[string]string{"status": "revoked"})
}

func (s *Server) repos(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:read") {
		return
	}
	includeArchived := who(r).Admin && r.URL.Query().Get("include_archived") == "1"
	rows, err := s.DB.QueryContext(r.Context(), `SELECT id,name,provider,provider_project_id,scm_base_url,default_branch,default_branch_source,owner,scm_check_status,archived_at,COALESCE(scm_connection_id,''),COALESCE((SELECT enabled FROM repository_scan_configs WHERE repository_id=repositories.id),true),(SELECT max(created_at) FROM scans WHERE repository_id=repositories.id) FROM repositories WHERE archived_at IS NULL OR $1 ORDER BY name`, includeArchived)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, name, provider, project, baseURL, branch, branchSource, owner, checkStatus, connectionID string
		var archived sql.NullTime
		var lastScan sql.NullTime
		var scanEnabled bool
		if err := rows.Scan(&id, &name, &provider, &project, &baseURL, &branch, &branchSource, &owner, &checkStatus, &archived, &connectionID, &scanEnabled, &lastScan); err != nil {
			fail(w, 500, "repository list failed")
			return
		}
		if s.repoAllowed(r.Context(), who(r), id) {
			var lastScanAt any
			if lastScan.Valid {
				lastScanAt = lastScan.Time
			}
			item := map[string]any{"id": id, "name": name, "provider": provider, "provider_project_id": project, "scm_base_url": baseURL, "default_branch": branch, "default_branch_source": branchSource, "owner": owner, "scm_check_status": checkStatus, "scm_connection_id": connectionID, "scan_enabled": scanEnabled, "archived": archived.Valid, "last_scan_at": lastScanAt}
			out = append(out, item)
		}
	}
	jsonOut(w, 200, out)
}
func (s *Server) createRepo(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:write") {
		return
	}
	var in repoInput
	if !decode(w, r, &in) {
		return
	}
	if err := normalizeRepoInput(&in); err != nil {
		fail(w, 400, err.Error())
		return
	}
	check, err := s.inspectConnectedSCM(r.Context(), in.Provider, in.ProviderProjectID, in.SCMBaseURL, in.SCMConnectionID)
	if err != nil {
		fail(w, 500, "SCM inspection failed")
		return
	}
	if in.BranchMode == "auto" {
		if check.Status == "verified" {
			in.DefaultBranch = check.DefaultBranch
		} else {
			in.DefaultBranch = ""
			in.BranchMode = "ci_pending"
		}
	}
	if in.Owner == "" && check.Status == "verified" {
		in.Owner = check.Owner
	}
	if in.BranchMode != "ci_pending" && !validBranch(in.DefaultBranch) {
		fail(w, 422, "a valid default branch is required")
		return
	}
	id := core.ID()
	_, err = s.DB.ExecContext(r.Context(), `INSERT INTO repositories(id,name,provider,provider_project_id,scm_base_url,default_branch,default_branch_source,owner,scm_check_status,scm_checked_at,scm_connection_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),NULLIF($10,''))`, id, in.Name, in.Provider, in.ProviderProjectID, in.SCMBaseURL, in.DefaultBranch, in.BranchMode, in.Owner, check.Status, check.ConnectionID)
	if err != nil {
		fail(w, 400, "repository already enrolled or invalid")
		return
	}
	_, _ = s.DB.ExecContext(r.Context(), `INSERT INTO repository_members(repository_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, who(r).UserID)
	s.audit(r.Context(), who(r).UserID, "repo.enroll", id, map[string]any{"provider_project_id": in.ProviderProjectID, "scm_check_status": check.Status})
	jsonOut(w, 201, map[string]string{"id": id, "default_branch": in.DefaultBranch, "owner": in.Owner, "scm_check_status": check.Status})
}
func (s *Server) scanToken(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "tokens:manage") {
		return
	}
	if !has(who(r), "scans:write") {
		fail(w, 403, "scan token issuance requires scans:write")
		return
	}
	repo := r.PathValue("id")
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	if _, err := s.scanConfigFor(repo); err != nil {
		fail(w, 404, "active repository not found")
		return
	}
	var in struct {
		Label        string `json:"label"`
		ExpiresHours int    `json:"expires_hours"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.ExpiresHours < 1 || in.ExpiresHours > 8760 {
		fail(w, 400, "expiry 1..8760 hours required")
		return
	}
	secret := core.Secret("pb_scan_")
	id := core.ID()
	_, err := s.DB.ExecContext(r.Context(), `INSERT INTO credentials(id,owner_id,kind,label,secret_hash,scopes,repository_id,expires_at) VALUES($1,$2,'scan',$3,$4,'["scans:write"]',$5,now()+($6 || ' hours')::interval)`, id, who(r).UserID, in.Label, core.Hash(secret), repo, strconv.Itoa(in.ExpiresHours))
	if err != nil {
		fail(w, 400, "repository invalid")
		return
	}
	s.audit(r.Context(), who(r).UserID, "scan_token.create", id, map[string]string{"repository_id": repo})
	jsonOut(w, 201, map[string]string{"id": id, "secret": secret})
}
func (s *Server) addRepoMember(w http.ResponseWriter, r *http.Request) {
	if !who(r).Admin || !who(r).Session {
		fail(w, 403, "admin session required")
		return
	}
	repo, user := r.PathValue("id"), r.PathValue("user")
	_, err := s.DB.ExecContext(r.Context(), `INSERT INTO repository_members(repository_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, repo, user)
	if err != nil {
		fail(w, 400, "invalid repo or user")
		return
	}
	s.audit(r.Context(), who(r).UserID, "repo.member.add", repo, map[string]string{"user_id": user})
	jsonOut(w, 200, map[string]string{"status": "added"})
}
func (s *Server) removeRepoMember(w http.ResponseWriter, r *http.Request) {
	if !who(r).Admin || !who(r).Session {
		fail(w, 403, "admin session required")
		return
	}
	repo, user := r.PathValue("id"), r.PathValue("user")
	_, err := s.DB.ExecContext(r.Context(), `DELETE FROM repository_members WHERE repository_id=$1 AND user_id=$2`, repo, user)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	s.audit(r.Context(), who(r).UserID, "repo.member.remove", repo, map[string]string{"user_id": user})
	jsonOut(w, 200, map[string]string{"status": "removed"})
}
