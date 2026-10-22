package server

import (
	"database/sql"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"panbox/internal/core"
)

var commitPattern = regexp.MustCompile(`^[a-fA-F0-9]{7,64}$`)

// Guidance links are curated public references. No finding content is sent to them.
func findingGuidance(module, ruleID string) (string, string) {
	reference, remediation := findingAdvice(module, ruleID)
	if reference == "" && module == "vaccin" {
		reference = guidanceReference(ruleID)
	}
	return reference, remediation
}

func guidanceReference(ruleID string) string {
	const base = "https://cheatsheetseries.owasp.org/cheatsheets/"
	switch {
	case strings.Contains(ruleID, "csrf"):
		return base + "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
	case strings.Contains(ruleID, "sql"):
		return base + "SQL_Injection_Prevention_Cheat_Sheet.html"
	case strings.Contains(ruleID, "ssrf"), strings.Contains(ruleID, "request-url"), strings.Contains(ruleID, "http-request-url"), strings.Contains(ruleID, "axios-request-url"):
		return base + "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
	case strings.Contains(ruleID, "redirect"), strings.Contains(ruleID, "location-header"):
		return base + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
	case strings.Contains(ruleID, "html"), strings.Contains(ruleID, "xss"), strings.Contains(ruleID, "template-safe"), strings.Contains(ruleID, "autoescape"):
		return base + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
	case strings.Contains(ruleID, "shell"), strings.Contains(ruleID, "command"), strings.Contains(ruleID, "exec"):
		return base + "OS_Command_Injection_Defense_Cheat_Sheet.html"
	case strings.Contains(ruleID, "eval"):
		return base + "Secure_Code_Review_Cheat_Sheet.html"
	case strings.Contains(ruleID, "pickle"), strings.Contains(ruleID, "deserialize"), strings.Contains(ruleID, "jsonpickle"), strings.Contains(ruleID, "dill"), strings.Contains(ruleID, "yaml"):
		return base + "Deserialization_Cheat_Sheet.html"
	case strings.Contains(ruleID, "jwt"):
		return base + "JSON_Web_Token_Cheat_Sheet.html"
	case strings.Contains(ruleID, "tls"), strings.Contains(ruleID, "ssl"), strings.Contains(ruleID, "hostname"):
		return base + "Transport_Layer_Security_Cheat_Sheet.html"
	case strings.Contains(ruleID, "cookie"), strings.Contains(ruleID, "session"):
		return base + "Session_Management_Cheat_Sheet.html"
	case strings.Contains(ruleID, "hash"), strings.Contains(ruleID, "cipher"), strings.Contains(ruleID, "random"):
		return base + "Cryptographic_Storage_Cheat_Sheet.html"
	case strings.Contains(ruleID, "path"), strings.Contains(ruleID, "file"):
		return base + "Input_Validation_Cheat_Sheet.html"
	case strings.HasPrefix(ruleID, "panbox.python.django-"), strings.HasPrefix(ruleID, "panbox.django."):
		return "https://docs.djangoproject.com/en/5.2/topics/security/"
	default:
		return base + "Secure_Code_Review_Cheat_Sheet.html"
	}
}

func findingAdvice(module, ruleID string) (string, string) {
	if module == "enetron" {
		if len(ruleID) > 120 {
			return "", "Review the affected package and upgrade to a version outside the advisory's affected range; regenerate the lockfile and test."
		}
		return "https://osv.dev/vulnerability/" + url.PathEscape(ruleID), "Open the advisory, find an unaffected package version, upgrade the direct or transitive dependency, regenerate the lockfile, and rerun the scan. Verify the fix against the advisory's affected range."
	}
	switch ruleID {
	case "panbox.python.flask-debug":
		return "", "Disable Flask debug mode in deployed configurations. Keep debug settings in development-only configuration and verify production startup flags."
	case "panbox.python.shell-true":
		return "", "Avoid shell=True with untrusted input. Pass an argument array, validate inputs, and review command construction at this call site."
	case "panbox.javascript.eval", "panbox.typescript.eval":
		return "", "Replace eval with explicit parsing or a bounded dispatch table. Treat untrusted strings as data rather than executable code."
	case "panbox.go.shell-command":
		return "", "Avoid sh -c/bash -c when arguments may include external input. Execute a fixed binary with separate validated arguments."
	case "panbox.python.django-debug":
		return "", "Set DEBUG=False in deployed settings. Keep development overrides separate and confirm the effective setting at startup."
	case "panbox.python.django-hardcoded-secret", "panbox.python.django-hardcoded-credential":
		return "", "Rotate the exposed value, remove it from tracked source, and load the replacement from a protected runtime secret. Check prior commits and logs for exposure."
	case "panbox.python.django-weak-password-hasher":
		return "", "Use Django's supported adaptive password hashers, keep a strong default first, and plan a password rehash path for existing users."
	case "panbox.python.django-pickle-session":
		return "", "Use Django's JSON session serializer and invalidate or migrate existing serialized sessions before rollout. Protect and rotate SECRET_KEY if exposed."
	case "panbox.python.django-csrf-middleware-missing", "panbox.python.django-csrf-disabled":
		return "", "Enable CsrfViewMiddleware and remove unnecessary csrf_exempt decorators. Include CSRF tokens in state-changing forms and verify POST requests reject missing tokens."
	case "panbox.python.django-sql-interpolation", "panbox.python.sql-format", "panbox.python.sql-fstring":
		return "", "Pass the SQL statement and values separately using bound parameters, or use the Django ORM. Never format request data into SQL text; add a regression test with quotes and special characters."
	case "panbox.python.django-open-redirect":
		return "", "Validate the redirect target against permitted hosts and schemes, or map input to a fixed local route. Fall back to a safe path when validation fails."
	case "panbox.django.template-safe", "panbox.django.autoescape-off":
		return "", "Keep Django autoescaping enabled and remove safe from untrusted values. If rich HTML is required, sanitize it with an explicit allowlist before rendering."
	case "panbox.python.django-host-wildcard":
		return "", "Set ALLOWED_HOSTS to the exact production hostnames and test that unexpected Host headers are rejected."
	case "panbox.python.django-frame-protection":
		return "", "Set X_FRAME_OPTIONS to DENY or SAMEORIGIN and confirm the response header is present on sensitive pages."
	default:
		if strings.Contains(ruleID, "sql") {
			return "", "Trace input into this query, replace string construction with bound parameters or a safe query API, and rerun the scan with an injection regression test."
		}
		if strings.Contains(ruleID, "shell") || strings.Contains(ruleID, "command") || strings.Contains(ruleID, "exec") {
			return "", "Check whether external input reaches this execution call. Prefer a fixed executable with separate validated arguments, then test unexpected input."
		}
		if strings.Contains(ruleID, "html") || strings.Contains(ruleID, "xss") || strings.Contains(ruleID, "template") {
			return "", "Keep context-aware output encoding enabled. Remove raw HTML insertion for untrusted data, or sanitize markup with an explicit allowlist and test unsafe characters."
		}
		if strings.Contains(ruleID, "ssrf") || strings.Contains(ruleID, "redirect") {
			return "", "Validate the destination URL against an explicit host and scheme allowlist, reject private or unexpected targets where applicable, and test crafted URLs."
		}
		if strings.Contains(ruleID, "pickle") || strings.Contains(ruleID, "deserialize") {
			return "", "Avoid deserializing untrusted data with executable object formats. Use a constrained data format, validate its schema, and test malformed input."
		}
		if strings.Contains(ruleID, "path") || strings.Contains(ruleID, "traversal") {
			return "", "Resolve the requested path against a fixed base directory, reject paths escaping that base, and test traversal and encoded separators."
		}
		if strings.Contains(ruleID, "cookie") || strings.Contains(ruleID, "tls") {
			return "", "Enable the relevant transport or cookie security setting in deployed configuration and verify the effective runtime behavior."
		}
		return "", "Inspect the matched code and its input path. Apply the smallest safe change, add a regression test for the risky behavior, then rerun PANBOX to verify the finding."
	}
}

func findingSourceURL(provider, project, baseURL, commit, path string, line int) string {
	if !commitPattern.MatchString(commit) || path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || len(path) > 500 {
		return ""
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ""
		}
	}
	encodedPath := escaped(parts...)
	if baseURL != "" {
		var err error
		baseURL, err = customSCMBase(baseURL)
		if err != nil {
			return ""
		}
	}
	if baseURL == "" {
		switch provider {
		case "github":
			baseURL = "https://github.com"
		case "gitlab":
			baseURL = "https://gitlab.com"
		case "bitbucket":
			baseURL = "https://bitbucket.org"
		case "azure":
			baseURL = "https://dev.azure.com"
		case "gitea", "generic":
			u, err := url.Parse(project)
			if err != nil || u.Scheme != "https" {
				return ""
			}
			baseURL, err = customSCMBase("https://" + u.Host)
			if err != nil {
				return ""
			}
			project = strings.Trim(u.Path, "/")
		default:
			return ""
		}
	}
	if provider == "azure" {
		p, err := pathParts(project, 3, 3)
		if err != nil {
			return ""
		}
		q := url.Values{"path": {"/" + path}, "version": {"GC" + commit}}
		if line > 0 {
			q.Set("line", strconv.Itoa(line))
		}
		return baseURL + "/" + escaped(p[0], p[1]) + "/_git/" + url.PathEscape(p[2]) + "?" + q.Encode()
	}
	p, err := pathParts(strings.TrimSuffix(project, ".git"), 2, 20)
	if err != nil {
		return ""
	}
	root := baseURL + "/" + escaped(p...)
	anchor := ""
	if line > 0 {
		anchor = "#L" + strconv.Itoa(line)
	}
	switch provider {
	case "github", "gitea":
		return root + "/blob/" + commit + "/" + encodedPath + anchor
	case "gitlab":
		return root + "/-/blob/" + commit + "/" + encodedPath + anchor
	case "bitbucket":
		if line > 0 {
			anchor = "#lines-" + strconv.Itoa(line)
		}
		return root + "/src/" + commit + "/" + encodedPath + anchor
	default:
		return ""
	}
}

func (s *Server) findingDetail(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "findings:read") {
		return
	}
	id, branch := r.PathValue("id"), r.URL.Query().Get("branch")
	if branch == "" {
		fail(w, 400, "branch is required")
		return
	}
	var repo, module, ruleID, path, message, provider, project, baseURL string
	var firstSeen, lastSeen time.Time
	err := s.DB.QueryRowContext(r.Context(), `SELECT f.repository_id,f.module,f.rule_id,f.path,f.message,f.first_seen,f.last_seen,r.provider,r.provider_project_id,r.scm_base_url FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE f.id=$1 AND r.archived_at IS NULL`, id).Scan(&repo, &module, &ruleID, &path, &message, &firstSeen, &lastSeen, &provider, &project, &baseURL)
	if err != nil {
		fail(w, 404, "finding not found")
		return
	}
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	var triage string
	_ = s.DB.QueryRowContext(r.Context(), `SELECT status FROM finding_dispositions WHERE finding_id=$1`, id).Scan(&triage)
	if triage == "" {
		triage = "open"
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT s.id,s.commit_sha,s.created_at,o.line,o.raw_severity,o.effective_severity FROM scans s
    LEFT JOIN occurrences o ON o.scan_id=s.id AND o.finding_id=$1
    WHERE s.repository_id=$2 AND s.branch=$3 AND s.status='complete' AND EXISTS (
      SELECT 1 FROM jsonb_array_elements(s.module_status) m WHERE m.value->>'name'=$4 AND m.value->>'status'='complete')
    ORDER BY s.created_at DESC,s.id DESC LIMIT 100`, id, repo, branch, module)
	if err != nil {
		fail(w, 500, "finding history unavailable")
		return
	}
	defer rows.Close()
	history := []map[string]any{}
	status, source := "resolved", ""
	var latestScanID, latestSeverity string
	var latestLine int
	var latestPresent bool
	for rows.Next() {
		var scanID, commit string
		var at time.Time
		var line sql.NullInt64
		var raw, effective sql.NullString
		if err := rows.Scan(&scanID, &commit, &at, &line, &raw, &effective); err != nil {
			fail(w, 500, "finding history unavailable")
			return
		}
		present := raw.Valid
		if len(history) == 0 {
			latestScanID, latestSeverity, latestLine, latestPresent = scanID, effective.String, int(line.Int64), present
			if present {
				status = triage
				source = findingSourceURL(provider, project, baseURL, commit, path, int(line.Int64))
			}
		}
		history = append(history, map[string]any{"scan_id": scanID, "commit_sha": commit, "created_at": at, "detected": present, "line": line.Int64, "raw_severity": raw.String, "effective_severity": effective.String, "source_url": findingSourceURL(provider, project, baseURL, commit, path, int(line.Int64))})
	}
	if err := rows.Err(); err != nil {
		fail(w, 500, "finding history unavailable")
		return
	}
	if len(history) == 0 {
		fail(w, 404, "finding has no complete scan on this branch")
		return
	}
	aiReview, err := s.findingAIReview(r.Context(), latestScanID, id, module, latestSeverity, path, triage, latestLine, latestPresent)
	if err != nil {
		fail(w, 500, "finding AI status unavailable")
		return
	}
	reference, remediation := findingGuidance(module, ruleID)
	jsonOut(w, 200, map[string]any{"id": id, "repository_id": repo, "branch": branch, "module": module, "rule_id": ruleID, "path": path, "message": message, "status": status, "first_seen": firstSeen, "last_seen": lastSeen, "source_url": source, "reference_url": reference, "remediation": remediation, "history": history, "ai_review": aiReview})
}

func (s *Server) scanFindings(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "findings:read") {
		return
	}
	id := r.PathValue("id")
	var repo, commit, provider, project, baseURL string
	err := s.DB.QueryRowContext(r.Context(), `SELECT s.repository_id,s.commit_sha,r.provider,r.provider_project_id,r.scm_base_url FROM scans s JOIN repositories r ON r.id=s.repository_id WHERE s.id=$1 AND r.archived_at IS NULL`, id).Scan(&repo, &commit, &provider, &project, &baseURL)
	if err != nil {
		fail(w, 404, "scan not found")
		return
	}
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT f.id,f.module,f.rule_id,f.path,o.line,f.message,o.raw_severity,o.effective_severity FROM occurrences o JOIN findings f ON f.id=o.finding_id WHERE o.scan_id=$1 ORDER BY o.effective_severity,f.path,o.line LIMIT 1000`, id)
	if err != nil {
		fail(w, 500, "scan findings unavailable")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var fid, module, ruleID, path, message, raw, effective string
		var line int
		if err := rows.Scan(&fid, &module, &ruleID, &path, &line, &message, &raw, &effective); err != nil {
			fail(w, 500, "scan findings unavailable")
			return
		}
		ref, remediation := findingGuidance(module, ruleID)
		out = append(out, map[string]any{"id": fid, "module": module, "rule_id": ruleID, "path": path, "line": line, "message": message, "raw_severity": raw, "effective_severity": effective, "source_url": findingSourceURL(provider, project, baseURL, commit, path, line), "reference_url": ref, "remediation": remediation})
	}
	jsonOut(w, 200, out)
}

func (s *Server) setFindingDisposition(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "findings:recast") {
		return
	}
	id := r.PathValue("id")
	var in struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if (in.Status != "open" && in.Status != "closed" && in.Status != "false_positive" && in.Status != "accepted_risk") || len(in.Reason) < 10 || len(in.Reason) > 500 || containsSecret(in.Reason) {
		fail(w, 400, "status and 10-500 character reason required")
		return
	}
	var repo, previous string
	err := s.DB.QueryRowContext(r.Context(), `SELECT repository_id FROM findings WHERE id=$1`, id).Scan(&repo)
	if err != nil {
		fail(w, 404, "finding not found")
		return
	}
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(r.Context(), `SELECT repository_id FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&repo); err != nil {
		fail(w, 404, "finding not found")
		return
	}
	_ = tx.QueryRowContext(r.Context(), `SELECT status FROM finding_dispositions WHERE finding_id=$1 FOR UPDATE`, id).Scan(&previous)
	if previous == "" {
		previous = "open"
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO finding_dispositions(finding_id,status,reason,actor_id) VALUES($1,$2,$3,$4)
      ON CONFLICT(finding_id) DO UPDATE SET status=$2,reason=$3,actor_id=$4,updated_at=now()`, id, in.Status, in.Reason, who(r).UserID)
	if err != nil {
		fail(w, 500, "disposition save failed")
		return
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO finding_disposition_events(id,finding_id,from_status,to_status,reason,actor_id) VALUES($1,$2,$3,$4,$5,$6)`, core.ID(), id, previous, in.Status, in.Reason, who(r).UserID)
	if err != nil {
		fail(w, 500, "disposition history failed")
		return
	}
	affectedCount, err := recalculateFindingGates(r.Context(), tx, id)
	if err != nil {
		fail(w, 500, "gate recalculation failed")
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, 500, "disposition commit failed")
		return
	}
	s.audit(r.Context(), who(r).UserID, "finding.disposition", id, map[string]any{"from": previous, "to": in.Status, "reason": in.Reason, "affected_scans": affectedCount})
	jsonOut(w, 200, map[string]any{"id": id, "status": in.Status, "affected_scans": affectedCount})
}

func (s *Server) findingDispositionHistory(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "findings:read") {
		return
	}
	id := r.PathValue("id")
	var repo string
	if err := s.DB.QueryRowContext(r.Context(), `SELECT repository_id FROM findings WHERE id=$1`, id).Scan(&repo); err != nil {
		fail(w, 404, "finding not found")
		return
	}
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT from_status,to_status,reason,COALESCE(actor_id,''),created_at FROM finding_disposition_events WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 100`, id)
	if err != nil {
		fail(w, 500, "disposition history unavailable")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var from, to, reason, actor string
		var at time.Time
		if err := rows.Scan(&from, &to, &reason, &actor, &at); err != nil {
			fail(w, 500, "disposition history unavailable")
			return
		}
		out = append(out, map[string]any{"from": from, "to": to, "reason": reason, "actor_id": actor, "created_at": at})
	}
	jsonOut(w, 200, out)
}
