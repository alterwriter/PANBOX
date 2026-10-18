package server

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"panbox/internal/core"
)

type scmConnection struct {
	ID         string     `json:"id"`
	Provider   string     `json:"provider"`
	Label      string     `json:"label"`
	BaseURL    string     `json:"base_url"`
	Enabled    bool       `json:"enabled"`
	AutoEnroll bool       `json:"auto_enroll"`
	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
}

type scmConnectionInput struct {
	Provider       string `json:"provider"`
	Label          string `json:"label"`
	BaseURL        string `json:"base_url"`
	Enabled        bool   `json:"enabled"`
	AutoEnroll     bool   `json:"auto_enroll"`
	Token          string `json:"token"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKey     string `json:"private_key"`
}

type scmSecret struct {
	Token          string `json:"token,omitempty"`
	AppID          int64  `json:"app_id,omitempty"`
	InstallationID int64  `json:"installation_id,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
}

type discoveredRepo struct {
	Path          string `json:"path"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	Owner         string `json:"owner"`
	PANBOXID      string `json:"panbox_id,omitempty"`
	Ignored       bool   `json:"ignored,omitempty"`
}

type scmAuthTransport struct {
	base     http.RoundTripper
	provider string
	token    string
}

var scmTransport http.RoundTripper = http.DefaultTransport

func (t scmAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copyReq := req.Clone(req.Context())
	if t.provider == "gitlab" {
		copyReq.Header.Set("PRIVATE-TOKEN", t.token)
	} else {
		copyReq.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(copyReq)
}

func (s *Server) inspectConnectedSCM(ctx context.Context, provider, project, baseURL, preferredID string) (scmInspection, error) {
	// Validate the destination before looking up a credential. Credentials are
	// only sent to an exact configured provider and HTTPS origin.
	if _, _, err := inspectionURL(provider, project, baseURL); err != nil {
		return scmInspection{Status: "manual_required", Message: err.Error()}, nil
	}
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	query := `SELECT id FROM scm_connections WHERE provider=$1 AND base_url=$2 AND enabled=true ORDER BY updated_at DESC`
	args := []any{provider, baseURL}
	if preferredID != "" {
		query = `SELECT id FROM scm_connections WHERE provider=$1 AND base_url=$2 AND enabled=true AND id=$3`
		args = append(args, preferredID)
	}
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return scmInspection{}, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return scmInspection{}, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if preferredID != "" && len(ids) == 0 {
		return scmInspection{Status: "manual_required", Message: "selected SCM connection is disabled or does not match this provider and host"}, nil
	}
	for _, id := range ids {
		c, secret, loadErr := s.connection(ctx, id)
		if loadErr != nil {
			return scmInspection{Status: "manual_required", Message: "SCM connection credential unavailable"}, nil
		}
		token, tokenErr := scmBearer(ctx, c, secret)
		if tokenErr != nil {
			continue
		}
		transport := scmTransport
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: scmAuthTransport{base: transport, provider: c.Provider, token: token}}
		result, inspectErr := inspectSCMWithClient(ctx, provider, project, baseURL, client)
		if inspectErr == nil && result.Status == "verified" {
			result.ConnectionID = id
			result.Message = "Private or public repository verified through the SCM connection; runner delivery is a separate check"
			return result, nil
		}
	}
	if len(ids) > 0 {
		return scmInspection{Status: "manual_required", Message: "Connected SCM credentials could not read this repository; check connection scope and repository access"}, nil
	}
	return inspectSCM(ctx, provider, project, baseURL)
}

func scmCipher() (cipher.AEAD, error) {
	raw := strings.TrimSpace(getenv("PANBOX_SCM_ENCRYPTION_KEY"))
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("configure PANBOX_SCM_ENCRYPTION_KEY as 64 random hex characters")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Keep provider credentials out of the PANBOX API and audit log. This key must be
// backed up with PostgreSQL; losing it makes the stored SCM connections unusable.
func sealSCM(secret scmSecret) ([]byte, error) {
	aead, err := scmCipher()
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, nil), nil
}
func openSCM(ciphertext []byte) (scmSecret, error) {
	var secret scmSecret
	aead, err := scmCipher()
	if err != nil {
		return secret, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return secret, errors.New("invalid SCM secret")
	}
	plain, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], nil)
	if err != nil {
		return secret, errors.New("SCM credential cannot be decrypted")
	}
	err = json.Unmarshal(plain, &secret)
	return secret, err
}

func normalizeSCMConnection(in *scmConnectionInput, old scmSecret) (scmSecret, error) {
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	in.Label = strings.TrimSpace(in.Label)
	in.BaseURL = strings.TrimSuffix(strings.TrimSpace(in.BaseURL), "/")
	if in.Provider != "github" && in.Provider != "gitlab" {
		return old, errors.New("choose GitHub or GitLab")
	}
	if in.Label == "" || len(in.Label) > 120 {
		return old, errors.New("connection label is required (max 120 characters)")
	}
	if in.BaseURL != "" {
		base, err := customSCMBase(in.BaseURL)
		if err != nil {
			return old, err
		}
		in.BaseURL = base
	}
	if in.Provider == "gitlab" {
		if in.Token != "" {
			old = scmSecret{Token: strings.TrimSpace(in.Token)}
		}
		if old.Token == "" {
			return old, errors.New("GitLab service account token is required")
		}
	} else {
		if in.PrivateKey != "" {
			old.PrivateKey = in.PrivateKey
		}
		if in.AppID != 0 {
			old.AppID = in.AppID
		}
		if in.InstallationID != 0 {
			old.InstallationID = in.InstallationID
		}
		old.Token = ""
		if old.AppID < 1 || old.InstallationID < 1 || old.PrivateKey == "" {
			return old, errors.New("GitHub App ID, installation ID and private key are required")
		}
		if _, err := parseAppKey(old.PrivateKey); err != nil {
			return old, errors.New("invalid GitHub App private key")
		}
	}
	return old, nil
}

func parseAppKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("RSA private key required")
	}
	return key, nil
}

func githubAppJWT(secret scmSecret) (string, error) {
	key, err := parseAppKey(secret.PrivateKey)
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{"iat": now - 60, "exp": now + 540, "iss": strconv.FormatInt(secret.AppID, 10)})
	message := head + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func scmHTTPClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: scmTransport}
}

func scmAPIRoot(c scmConnection) string {
	if c.Provider == "github" {
		if c.BaseURL == "" {
			return "https://api.github.com"
		}
		return c.BaseURL + "/api/v3"
	}
	if c.BaseURL == "" {
		return "https://gitlab.com/api/v4"
	}
	return c.BaseURL + "/api/v4"
}

func scmBearer(ctx context.Context, c scmConnection, secret scmSecret) (string, error) {
	if c.Provider == "gitlab" {
		return secret.Token, nil
	}
	jwt, err := githubAppJWT(secret)
	if err != nil {
		return "", err
	}
	url := scmAPIRoot(c) + "/app/installations/" + strconv.FormatInt(secret.InstallationID, 10) + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := scmHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return "", fmt.Errorf("GitHub App installation returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("GitHub App returned no installation token")
	}
	return out.Token, nil
}

func scmRequest(ctx context.Context, c scmConnection, bearer, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scmAPIRoot(c)+path, nil)
	if err != nil {
		return nil, err
	}
	if c.Provider == "gitlab" {
		req.Header.Set("PRIVATE-TOKEN", bearer)
	} else {
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	req.Header.Set("User-Agent", "PANBOX-SCM-check/0.1")
	return scmHTTPClient().Do(req)
}

func listSCMRepositories(ctx context.Context, c scmConnection, secret scmSecret) ([]discoveredRepo, bool, error) {
	bearer, err := scmBearer(ctx, c, secret)
	if err != nil {
		return nil, false, err
	}
	out := []discoveredRepo{}
	for page := 1; page <= 5; page++ {
		path := fmt.Sprintf("/projects?membership=true&per_page=100&page=%d", page)
		if c.Provider == "github" {
			path = fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page)
		}
		resp, err := scmRequest(ctx, c, bearer, path)
		if err != nil {
			return nil, false, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, false, fmt.Errorf("%s repository listing returned HTTP %d", c.Provider, resp.StatusCode)
		}
		var list []struct {
			Path          string `json:"path_with_namespace"`
			Name          string `json:"name"`
			DefaultBranch string `json:"default_branch"`
			Namespace     struct {
				FullPath string `json:"full_path"`
			} `json:"namespace"`
		}
		var github struct {
			Repositories []struct {
				FullName      string `json:"full_name"`
				Name          string `json:"name"`
				DefaultBranch string `json:"default_branch"`
				Owner         struct {
					Login string `json:"login"`
				} `json:"owner"`
			} `json:"repositories"`
		}
		decoder := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
		if c.Provider == "github" {
			err = decoder.Decode(&github)
		} else {
			err = decoder.Decode(&list)
		}
		resp.Body.Close()
		if err != nil {
			return nil, false, err
		}
		if c.Provider == "github" {
			for _, r := range github.Repositories {
				if r.FullName != "" {
					out = append(out, discoveredRepo{Path: r.FullName, Name: r.Name, DefaultBranch: r.DefaultBranch, Owner: r.Owner.Login})
				}
			}
			if len(github.Repositories) < 100 {
				return out, false, nil
			}
		} else {
			for _, r := range list {
				if r.Path != "" {
					out = append(out, discoveredRepo{Path: r.Path, Name: r.Name, DefaultBranch: r.DefaultBranch, Owner: r.Namespace.FullPath})
				}
			}
			if len(list) < 100 {
				return out, false, nil
			}
		}
	}
	return out, true, nil
}

func (s *Server) connection(ctx context.Context, id string) (scmConnection, scmSecret, error) {
	var c scmConnection
	var raw []byte
	var last sql.NullTime
	err := s.DB.QueryRowContext(ctx, `SELECT id,provider,label,base_url,enabled,auto_enroll,secret_ciphertext,last_sync_at FROM scm_connections WHERE id=$1`, id).Scan(&c.ID, &c.Provider, &c.Label, &c.BaseURL, &c.Enabled, &c.AutoEnroll, &raw, &last)
	if err != nil {
		return c, scmSecret{}, err
	}
	if last.Valid {
		c.LastSyncAt = &last.Time
	}
	secret, err := openSCM(raw)
	return c, secret, err
}

func adminSCM(w http.ResponseWriter, r *http.Request) bool {
	if !who(r).Admin || !who(r).Session {
		fail(w, 403, "admin browser session required for SCM connections")
		return false
	}
	return true
}

func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	if !adminSCM(w, r) {
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT id,provider,label,base_url,enabled,auto_enroll,last_sync_at FROM scm_connections ORDER BY label`)
	if err != nil {
		fail(w, 500, "connection list failed")
		return
	}
	defer rows.Close()
	out := []scmConnection{}
	for rows.Next() {
		var c scmConnection
		var last sql.NullTime
		if err = rows.Scan(&c.ID, &c.Provider, &c.Label, &c.BaseURL, &c.Enabled, &c.AutoEnroll, &last); err != nil {
			fail(w, 500, "connection list failed")
			return
		}
		if last.Valid {
			c.LastSyncAt = &last.Time
		}
		out = append(out, c)
	}
	jsonOut(w, 200, out)
}

func (s *Server) saveConnection(w http.ResponseWriter, r *http.Request) {
	if !adminSCM(w, r) {
		return
	}
	var in scmConnectionInput
	if !decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	var old scmSecret
	var prior scmConnection
	if id != "" {
		var err error
		prior, old, err = s.connection(r.Context(), id)
		if err != nil {
			fail(w, 404, "SCM connection not found or encryption key unavailable")
			return
		}
		if prior.Provider != strings.ToLower(strings.TrimSpace(in.Provider)) || prior.BaseURL != strings.TrimSuffix(strings.TrimSpace(in.BaseURL), "/") {
			fail(w, 400, "provider and host cannot be changed; create another connection")
			return
		}
	}
	secret, err := normalizeSCMConnection(&in, old)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	probe := scmConnection{ID: id, Provider: in.Provider, Label: in.Label, BaseURL: in.BaseURL, Enabled: in.Enabled, AutoEnroll: in.AutoEnroll}
	var discovered []discoveredRepo
	var truncated bool
	if in.Enabled {
		discovered, truncated, err = listSCMRepositories(r.Context(), probe, secret)
		if err != nil {
			fail(w, 422, "SCM connection test failed: "+err.Error())
			return
		}
	}
	sealed, err := sealSCM(secret)
	if err != nil {
		fail(w, 503, err.Error())
		return
	}
	if id == "" {
		id = core.ID()
		_, err = s.DB.ExecContext(r.Context(), `INSERT INTO scm_connections(id,provider,label,base_url,enabled,auto_enroll,secret_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, in.Provider, in.Label, in.BaseURL, in.Enabled, in.AutoEnroll, sealed)
	} else {
		_, err = s.DB.ExecContext(r.Context(), `UPDATE scm_connections SET label=$2,enabled=$3,auto_enroll=$4,secret_ciphertext=$5,updated_at=now() WHERE id=$1`, id, in.Label, in.Enabled, in.AutoEnroll, sealed)
	}
	if err != nil {
		fail(w, 500, "SCM connection save failed")
		return
	}
	s.audit(r.Context(), who(r).UserID, "scm_connection.save", id, map[string]any{"provider": in.Provider, "enabled": in.Enabled})
	status := "disabled"
	if in.Enabled {
		status = "verified"
	}
	response := map[string]any{"id": id, "status": status}
	if in.Enabled && in.AutoEnroll {
		probe.ID = id
		stats, syncErr := s.importDiscoveredRepos(r.Context(), probe, discovered, truncated, who(r).UserID)
		if syncErr != nil {
			response["sync_error"] = "repository import failed; use Sync to retry"
		} else {
			response["sync"] = stats
		}
	}
	jsonOut(w, 200, response)
}

func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request) {
	if !adminSCM(w, r) {
		return
	}
	id := r.PathValue("id")
	res, err := s.DB.ExecContext(r.Context(), `DELETE FROM scm_connections WHERE id=$1`, id)
	if err != nil {
		fail(w, 500, "SCM connection removal failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		fail(w, 404, "SCM connection not found")
		return
	}
	s.audit(r.Context(), who(r).UserID, "scm_connection.delete", id, map[string]any{})
	jsonOut(w, 200, map[string]string{"status": "deleted"})
}

func (s *Server) discoverConnection(w http.ResponseWriter, r *http.Request) {
	if !adminSCM(w, r) {
		return
	}
	c, secret, err := s.connection(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "SCM connection unavailable")
		return
	}
	if !c.Enabled {
		fail(w, 409, "enable the SCM connection first")
		return
	}
	repos, truncated, err := listSCMRepositories(r.Context(), c, secret)
	if err != nil {
		fail(w, 502, "SCM discovery failed: "+err.Error())
		return
	}
	for i := range repos {
		_ = s.DB.QueryRowContext(r.Context(), `SELECT id FROM repositories WHERE provider=$1 AND scm_base_url=$2 AND provider_project_id=$3 AND archived_at IS NULL LIMIT 1`, c.Provider, c.BaseURL, repos[i].Path).Scan(&repos[i].PANBOXID)
		_ = s.DB.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM scm_ignored_repositories WHERE connection_id=$1 AND provider_project_id=$2)`, c.ID, repos[i].Path).Scan(&repos[i].Ignored)
	}
	jsonOut(w, 200, map[string]any{"repositories": repos, "truncated": truncated})
}

func (s *Server) syncConnection(w http.ResponseWriter, r *http.Request) {
	if !adminSCM(w, r) {
		return
	}
	c, secret, err := s.connection(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "SCM connection unavailable")
		return
	}
	if !c.Enabled || !c.AutoEnroll {
		fail(w, 409, "enable connection and automatic enrollment before syncing")
		return
	}
	stats, err := s.syncSCMRepositories(r.Context(), c, secret, who(r).UserID)
	if err != nil {
		fail(w, 502, "SCM sync failed: "+err.Error())
		return
	}
	jsonOut(w, 200, stats)
}

func (s *Server) syncSCMRepositories(ctx context.Context, c scmConnection, secret scmSecret, actor string) (map[string]any, error) {
	repos, truncated, err := listSCMRepositories(ctx, c, secret)
	if err != nil {
		return nil, err
	}
	return s.importDiscoveredRepos(ctx, c, repos, truncated, actor)
}

func (s *Server) importDiscoveredRepos(ctx context.Context, c scmConnection, repos []discoveredRepo, truncated bool, actor string) (map[string]any, error) {
	created := 0
	existing := 0
	ignored := 0
	for _, repo := range repos {
		maxParts := 10
		if c.Provider == "github" {
			maxParts = 2
		}
		if _, pathErr := pathParts(repo.Path, 2, maxParts); pathErr != nil || (repo.DefaultBranch != "" && !validBranch(repo.DefaultBranch)) {
			ignored++
			continue
		}
		var excluded bool
		if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scm_ignored_repositories WHERE connection_id=$1 AND provider_project_id=$2)`, c.ID, repo.Path).Scan(&excluded); err != nil {
			return nil, err
		}
		if excluded {
			ignored++
			continue
		}
		var existingID string
		updateErr := s.DB.QueryRowContext(ctx, `UPDATE repositories SET scm_connection_id=$4,default_branch=CASE WHEN default_branch_source<>'manual' AND $5<>'' THEN $5 ELSE default_branch END,default_branch_source=CASE WHEN default_branch_source<>'manual' AND $5<>'' THEN 'auto' ELSE default_branch_source END,owner=CASE WHEN owner='' THEN $6 ELSE owner END,scm_check_status=CASE WHEN $5='' THEN 'reachable_no_branch' ELSE 'verified' END,scm_checked_at=now() WHERE provider=$1 AND scm_base_url=$2 AND provider_project_id=$3 AND archived_at IS NULL AND (scm_connection_id IS NULL OR scm_connection_id=$4) RETURNING id`, c.Provider, c.BaseURL, repo.Path, c.ID, repo.DefaultBranch, repo.Owner).Scan(&existingID)
		if updateErr == nil {
			existing++
			continue
		}
		if !errors.Is(updateErr, sql.ErrNoRows) {
			return nil, updateErr
		}
		var already bool
		if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM repositories WHERE provider=$1 AND scm_base_url=$2 AND provider_project_id=$3)`, c.Provider, c.BaseURL, repo.Path).Scan(&already); err != nil {
			return nil, err
		}
		if already {
			existing++
			continue
		}
		branch := repo.DefaultBranch
		source := "auto"
		if branch == "" {
			source = "ci_pending"
		}
		name := repo.Name
		if name == "" {
			name = repo.Path
		}
		if len(name) > 120 {
			name = name[:120]
		}
		id := core.ID()
		res, insertErr := s.DB.ExecContext(ctx, `INSERT INTO repositories(id,name,provider,provider_project_id,scm_base_url,default_branch,default_branch_source,owner,scm_check_status,scm_checked_at,scm_connection_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $6='' THEN 'reachable_no_branch' ELSE 'verified' END,now(),$9) ON CONFLICT DO NOTHING`, id, name, c.Provider, repo.Path, c.BaseURL, branch, source, repo.Owner, c.ID)
		if insertErr != nil {
			return nil, insertErr
		}
		if n, _ := res.RowsAffected(); n > 0 {
			created++
			_, _ = s.DB.ExecContext(ctx, `INSERT INTO repository_members(repository_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, actor)
		} else {
			existing++
		}
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE scm_connections SET last_sync_at=now() WHERE id=$1`, c.ID)
	stats := map[string]any{"created": created, "existing": existing, "ignored": ignored, "truncated": truncated}
	s.audit(ctx, actor, "scm_connection.sync", c.ID, stats)
	return stats, nil
}

func (s *Server) allowSCMReimport(w http.ResponseWriter, r *http.Request) {
	if !adminSCM(w, r) {
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if !decode(w, r, &in) {
		return
	}
	if _, err := pathParts(in.Path, 2, 10); err != nil {
		fail(w, 400, "invalid repository path")
		return
	}
	_, err := s.DB.ExecContext(r.Context(), `DELETE FROM scm_ignored_repositories WHERE connection_id=$1 AND provider_project_id=$2`, r.PathValue("id"), in.Path)
	if err != nil {
		fail(w, 500, "reimport update failed")
		return
	}
	s.audit(r.Context(), who(r).UserID, "scm_connection.reinclude", r.PathValue("id"), map[string]any{"path": in.Path})
	jsonOut(w, 200, map[string]string{"status": "eligible"})
}

// This small indirection keeps the encryption key out of error messages.
func getenv(key string) string { return strings.TrimSpace(strings.Trim(os.Getenv(key), "\r\n")) }
