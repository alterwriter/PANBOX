package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"panbox/internal/core"
)

func TestRejectSecretInBundle(t *testing.T) {
	in := scanInput{SchemaVersion: "1.0", ClientScanID: "x", Scope: "repo", RepositoryID: "r"}
	in.Git.Branch = "main"
	in.Git.CommitSHA = "a"
	in.Modules = []moduleInput{{Name: "vaccin", Status: "complete"}}
	f := findingInput{Module: "vaccin", RuleID: "r", RawSeverity: "high", Message: "token=glpat-abcdefghijklmnop"}
	in.Findings = []findingInput{f}
	if err := validScan(in); err == nil {
		t.Fatal("secret-like evidence accepted")
	}
	in.Findings[0].Message = "safe finding"
	if err := validScan(in); err != nil {
		t.Fatal(err)
	}
}

func TestIngestScopeIdempotencyAndReport(t *testing.T) {
	dsn := os.Getenv("PANBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PANBOX_TEST_DATABASE_URL unset")
	}
	t.Setenv("PANBOX_BOOTSTRAP_EMAIL", "test@panbox.local")
	t.Setenv("PANBOX_BOOTSTRAP_PASSWORD", "test-password-123456")
	t.Setenv("PANBOX_MIGRATIONS_DIR", "../../migrations")
	s, err := Open(dsn, "../../web/dist", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var user string
	if err := s.DB.QueryRow(`SELECT id FROM users WHERE email='test@panbox.local'`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	repoA, repoB := core.ID(), core.ID()
	for _, r := range []string{repoA, repoB} {
		_, err = s.DB.Exec(`INSERT INTO repositories(id,name,provider,provider_project_id) VALUES($1,$2,'gitlab',$3)`, r, r, r)
		if err != nil {
			t.Fatal(err)
		}
	}
	secret := core.Secret("pb_scan_")
	_, err = s.DB.Exec(`INSERT INTO credentials(id,owner_id,kind,label,secret_hash,scopes,repository_id,expires_at) VALUES($1,$2,'scan','test',$3,'["scans:write"]',$4,now()+interval '1 hour')`, core.ID(), user, core.Hash(secret), repoA)
	if err != nil {
		t.Fatal(err)
	}
	readSecret := core.Secret("pb_api_")
	_, err = s.DB.Exec(`INSERT INTO credentials(id,owner_id,kind,label,secret_hash,scopes,expires_at) VALUES($1,$2,'api','test',$3,'["reports:export","findings:read","scans:read","repos:read"]',now()+interval '1 hour')`, core.ID(), user, core.Hash(readSecret))
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	makeBundle := func(repo, client, branch, commit, base string, findings []map[string]any) []byte {
		b, _ := json.Marshal(map[string]any{"schema_version": "1.0", "client_scan_id": client, "scope": "repo", "repository_id": repo, "git": map[string]string{"branch": branch, "commit_sha": commit, "base_sha": base}, "modules": []map[string]string{{"name": "vaccin", "engine": "panbox-native", "version": "0.1.0", "status": "complete"}}, "findings": findings})
		return b
	}
	finding := func(fp, severity string) map[string]any {
		return map[string]any{"module": "vaccin", "rule_id": "rule", "raw_severity": severity, "fingerprint": fp, "location": map[string]any{"path": "a.go", "line": 10}, "message": "safe summary"}
	}
	wrong := call("POST", "/v1/scans", secret, makeBundle(repoB, "wrong", "main", "b1", "", nil))
	if wrong.Code != 403 {
		t.Fatalf("wrong repository status %d: %s", wrong.Code, wrong.Body.String())
	}
	main := makeBundle(repoA, "main-1", "main", "a1", "", []map[string]any{finding("same", "medium"), finding("main-high", "high")})
	first := call("POST", "/v1/scans", secret, main)
	if first.Code != 201 {
		t.Fatalf("first status %d: %s", first.Code, first.Body.String())
	}
	again := call("POST", "/v1/scans", secret, main)
	if again.Code != 200 {
		t.Fatalf("retry status %d: %s", again.Code, again.Body.String())
	}
	feature := makeBundle(repoA, "feature-1", "feature/test", "a2", "a1", []map[string]any{finding("same", "medium"), finding("new", "high")})
	result := call("POST", "/v1/scans", secret, feature)
	if result.Code != 201 || !strings.Contains(result.Body.String(), `"new":1`) || !strings.Contains(result.Body.String(), `"gate_pass":false`) {
		t.Fatalf("feature result %d: %s", result.Code, result.Body.String())
	}
	unknown := makeBundle(repoA, "feature-2", "feature/unknown", "a3", "missing", []map[string]any{finding("new", "high")})
	u := call("POST", "/v1/scans", secret, unknown)
	if !strings.Contains(u.Body.String(), `"baseline_unknown":1`) {
		t.Fatal(u.Body.String())
	}
	report := call("GET", "/v1/reports/technical?format=csv&repository_id="+repoA, readSecret, nil)
	if report.Code != 200 || !strings.Contains(report.Body.String(), "raw_severity,effective_severity") || !strings.Contains(report.Body.String(), "medium,medium") {
		t.Fatalf("report mismatch %d: %s", report.Code, report.Body.String())
	}
	var partial map[string]any
	_ = json.Unmarshal(makeBundle(repoA, "main-2", "main", "a4", "a1", nil), &partial)
	partial["modules"] = []map[string]string{{"name": "vaccin", "status": "error"}, {"name": "enetron", "status": "complete"}}
	partialJSON, _ := json.Marshal(partial)
	pResult := call("POST", "/v1/scans", secret, partialJSON)
	if pResult.Code != 201 || !strings.Contains(pResult.Body.String(), `"status":"partial"`) {
		t.Fatalf("partial ingest %d: %s", pResult.Code, pResult.Body.String())
	}
	posture := call("GET", "/v1/metrics/overview?repository_id="+repoA, readSecret, nil)
	if posture.Code != 200 || !strings.Contains(posture.Body.String(), `"covered":0`) || !strings.Contains(posture.Body.String(), `"ark":1`) {
		t.Fatalf("partial scan changed posture incorrectly: %d %s", posture.Code, posture.Body.String())
	}
}

func TestAdminCanIssueAndRevokeScopedKey(t *testing.T) {
	dsn := os.Getenv("PANBOX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PANBOX_TEST_DATABASE_URL unset")
	}
	t.Setenv("PANBOX_MIGRATIONS_DIR", "../../migrations")
	t.Setenv("PANBOX_BOOTSTRAP_EMAIL", "test@panbox.local")
	t.Setenv("PANBOX_BOOTSTRAP_PASSWORD", "test-password-123456")
	s, err := Open(dsn, "../../web/dist", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	call := func(method, path, body string, cookie *http.Cookie, csrf, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	login := call("POST", "/v1/auth/login", `{"email":"test@panbox.local","password":"test-password-123456"}`, nil, "", "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	var auth struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &auth)
	cookie := login.Result().Cookies()[0]
	role := call("PUT", "/v1/roles/custom_auditor", `{"description":"read only","permissions":["repos:read","findings:read"]}`, cookie, auth.CSRF, "")
	if role.Code != 200 {
		t.Fatalf("role %d: %s", role.Code, role.Body.String())
	}
	badRole := call("PUT", "/v1/roles/custom_auditor", `{"permissions":["rbac:manage"]}`, cookie, auth.CSRF, "")
	if badRole.Code != 403 {
		t.Fatalf("admin-only permission accepted: %d", badRole.Code)
	}
	create := call("POST", "/v1/credentials", `{"kind":"api","label":"test-scoped","scopes":["scans:read"],"expires_hours":1}`, cookie, auth.CSRF, "")
	if create.Code != 201 {
		t.Fatalf("key %d: %s", create.Code, create.Body.String())
	}
	var key struct{ ID, Secret string }
	_ = json.Unmarshal(create.Body.Bytes(), &key)
	if got := call("GET", "/v1/scans", "", nil, "", key.Secret); got.Code != 200 {
		t.Fatalf("scans read %d", got.Code)
	}
	if got := call("GET", "/v1/repos", "", nil, "", key.Secret); got.Code != 403 {
		t.Fatalf("key escaped scope %d", got.Code)
	}
	if got := call("POST", "/v1/credentials", `{"kind":"access","label":"bad-write","scopes":["scans:write"],"expires_hours":1}`, cookie, auth.CSRF, ""); got.Code != 400 {
		t.Fatalf("access key accepted write scope: %d", got.Code)
	}
	revoke := call("DELETE", "/v1/credentials/"+key.ID, "", cookie, auth.CSRF, "")
	if revoke.Code != 200 {
		t.Fatalf("revoke %d", revoke.Code)
	}
	if got := call("GET", "/v1/scans", "", nil, "", key.Secret); got.Code != 401 {
		t.Fatalf("revoked key accepted %d", got.Code)
	}
	unique := core.ID()
	enroll := call("POST", "/v1/repos", `{"name":"membership-test","provider":"gitlab","provider_project_id":"`+unique+`","default_branch":"main"}`, cookie, auth.CSRF, "")
	if enroll.Code != 201 {
		t.Fatalf("enroll %d: %s", enroll.Code, enroll.Body.String())
	}
	var enrolled struct{ ID string }
	_ = json.Unmarshal(enroll.Body.Bytes(), &enrolled)
	userEmail := "member-" + unique + "@test.local"
	member := call("POST", "/v1/users", `{"email":"`+userEmail+`","password":"member-password-123456","role":"developer"}`, cookie, auth.CSRF, "")
	if member.Code != 201 {
		t.Fatalf("member create %d: %s", member.Code, member.Body.String())
	}
	var created struct{ ID string }
	_ = json.Unmarshal(member.Body.Bytes(), &created)
	memberPath := "/v1/repos/" + enrolled.ID + "/members/" + created.ID
	if got := call("PUT", memberPath, "", cookie, auth.CSRF, ""); got.Code != 200 {
		t.Fatalf("membership grant %d", got.Code)
	}
	memberLogin := call("POST", "/v1/auth/login", `{"email":"`+userEmail+`","password":"member-password-123456"}`, nil, "", "")
	if memberLogin.Code != 200 {
		t.Fatalf("member login %d", memberLogin.Code)
	}
	memberCookie := memberLogin.Result().Cookies()[0]
	if got := call("GET", "/v1/repos", "", memberCookie, "", ""); got.Code != 200 || !strings.Contains(got.Body.String(), enrolled.ID) {
		t.Fatalf("member cannot see granted repo: %s", got.Body.String())
	}
	memberKey := core.Secret("pb_api_")
	_, err = s.DB.Exec(`INSERT INTO credentials(id,owner_id,kind,label,secret_hash,scopes,expires_at) VALUES($1,$2,'api','member',$3,'["findings:read"]',now()+interval '1 hour')`, core.ID(), created.ID, core.Hash(memberKey))
	if err != nil {
		t.Fatal(err)
	}
	if got := call("GET", "/v1/findings", "", nil, "", memberKey); got.Code != 200 {
		t.Fatalf("member token should read findings: %d", got.Code)
	}
	if got := call("PUT", "/v1/users/"+created.ID+"/roles", `{"roles":["executive_viewer"]}`, cookie, auth.CSRF, ""); got.Code != 200 {
		t.Fatalf("role change %d", got.Code)
	}
	if got := call("GET", "/v1/findings", "", nil, "", memberKey); got.Code != 403 {
		t.Fatalf("token retained revoked role permission: %d", got.Code)
	}
	if got := call("DELETE", memberPath, "", cookie, auth.CSRF, ""); got.Code != 200 {
		t.Fatalf("membership remove %d", got.Code)
	}
	if got := call("GET", "/v1/repos", "", memberCookie, "", ""); strings.Contains(got.Body.String(), enrolled.ID) {
		t.Fatalf("member still sees removed repo: %s", got.Body.String())
	}
}
