package server

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"panbox/internal/core"
)

type moduleInput struct {
	Name    string `json:"name"`
	Engine  string `json:"engine"`
	Version string `json:"version"`
	Status  string `json:"status"`
}
type findingInput struct {
	Module      string `json:"module"`
	RuleID      string `json:"rule_id"`
	RawSeverity string `json:"raw_severity"`
	Fingerprint string `json:"fingerprint"`
	Location    struct {
		Path string `json:"path"`
		Line int    `json:"line"`
	} `json:"location"`
	Message string `json:"message"`
}
type scanInput struct {
	SchemaVersion string `json:"schema_version"`
	ClientScanID  string `json:"client_scan_id"`
	Scope         string `json:"scope"`
	RepositoryID  string `json:"repository_id"`
	Git           struct {
		Branch    string `json:"branch"`
		CommitSHA string `json:"commit_sha"`
		BaseSHA   string `json:"base_sha"`
	} `json:"git"`
	Modules  []moduleInput  `json:"modules"`
	Findings []findingInput `json:"findings"`
}

func validScan(in scanInput) error {
	if in.SchemaVersion != "1.0" || in.ClientScanID == "" || in.Scope != "repo" || in.RepositoryID == "" || in.Git.Branch == "" || in.Git.CommitSHA == "" {
		return errors.New("invalid scan identity or schema version")
	}
	if len(in.Modules) == 0 || len(in.Modules) > 2 || len(in.Findings) > 10000 {
		return errors.New("invalid module or finding count")
	}
	seen := map[string]bool{}
	completed := map[string]bool{}
	for _, m := range in.Modules {
		if m.Name != "vaccin" && m.Name != "enetron" {
			return errors.New("unsupported phase 1 module")
		}
		if seen[m.Name] {
			return errors.New("duplicate module")
		}
		seen[m.Name] = true
		completed[m.Name] = m.Status == "complete"
		if m.Status != "complete" && m.Status != "error" {
			return errors.New("invalid module status")
		}
	}
	for _, f := range in.Findings {
		if !seen[f.Module] || !completed[f.Module] || !core.ValidSeverity(f.RawSeverity) || f.RuleID == "" || len(f.Message) > 400 || len(f.Location.Path) > 500 || f.Location.Line < 0 {
			return errors.New("invalid finding")
		}
		if containsSecret(f.Message) {
			return errors.New("possible secret in message")
		}
	}
	return nil
}
func statusOf(modules []moduleInput) string {
	complete, errors := 0, 0
	for _, m := range modules {
		if m.Status == "complete" {
			complete++
		} else {
			errors++
		}
	}
	if errors == 0 {
		return "complete"
	}
	if complete == 0 {
		return "error"
	}
	return "partial"
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "scans:write") {
		return
	}
	p := who(r)
	if p.Session || p.Kind != "scan" {
		fail(w, 403, "scan upload requires repository-scoped scan token")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var in scanInput
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		fail(w, 400, "invalid bundle: "+err.Error())
		return
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		fail(w, 400, "unexpected trailing JSON")
		return
	}
	if err := validScan(in); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !s.repoAllowed(r.Context(), p, in.RepositoryID) {
		fail(w, 403, "token is not scoped to repository")
		return
	}
	var existing string
	err := s.DB.QueryRowContext(r.Context(), `SELECT id FROM scans WHERE repository_id=$1 AND client_scan_id=$2`, in.RepositoryID, in.ClientScanID).Scan(&existing)
	if err == nil {
		s.scanByID(w, r, existing)
		return
	}
	if err != sql.ErrNoRows {
		fail(w, 500, "database error")
		return
	}
	status := statusOf(in.Modules)
	modulesJSON, _ := json.Marshal(in.Modules)
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	id := core.ID()
	var passed any = nil
	if status == "complete" {
		passed = true
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO scans(id,client_scan_id,repository_id,branch,commit_sha,base_sha,status,module_status,gate_pass) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, in.ClientScanID, in.RepositoryID, in.Git.Branch, in.Git.CommitSHA, in.Git.BaseSHA, status, string(modulesJSON), passed)
	if err != nil {
		fail(w, 409, "duplicate scan ID or invalid repository")
		return
	}
	baseID := ""
	if in.Git.BaseSHA != "" {
		_ = tx.QueryRowContext(r.Context(), `SELECT id FROM scans WHERE repository_id=$1 AND commit_sha=$2 AND status='complete' ORDER BY created_at DESC LIMIT 1`, in.RepositoryID, in.Git.BaseSHA).Scan(&baseID)
	} else {
		_ = tx.QueryRowContext(r.Context(), `SELECT id FROM scans WHERE repository_id=$1 AND branch=$2 AND status='complete' AND id<>$3 ORDER BY created_at DESC LIMIT 1`, in.RepositoryID, in.Git.Branch, id).Scan(&baseID)
	}
	severities := []string{}
	newCount, unknownCount := 0, 0
	for _, f := range in.Findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = core.Fingerprint(f.Module, f.RuleID, f.Location.Path, f.Message)
		}
		fid := core.ID()
		err = tx.QueryRowContext(r.Context(), `INSERT INTO findings(id,repository_id,module,fingerprint,rule_id,path,message) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(repository_id,module,fingerprint) DO UPDATE SET last_seen=now() RETURNING id`, fid, in.RepositoryID, f.Module, fp, f.RuleID, f.Location.Path, f.Message).Scan(&fid)
		if err != nil {
			fail(w, 500, "finding save failed")
			return
		}
		inBase := false
		if baseID != "" {
			_ = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM occurrences WHERE scan_id=$1 AND finding_id=$2)`, baseID, fid).Scan(&inBase)
		}
		baseline := core.Delta(baseID != "", inBase)
		if baseline == "new" {
			newCount++
		}
		if baseline == "baseline_unknown" {
			unknownCount++
		}
		_, err = tx.ExecContext(r.Context(), `INSERT INTO occurrences(scan_id,finding_id,raw_severity,effective_severity,baseline_status,line) VALUES($1,$2,$3,$3,$4,$5) ON CONFLICT DO NOTHING`, id, fid, f.RawSeverity, baseline, f.Location.Line)
		if err != nil {
			fail(w, 500, "occurrence save failed")
			return
		}
		severities = append(severities, f.RawSeverity)
	}
	gate, gateErr := core.Gate(status, severities)
	var gateValue any = nil
	reasons := []string{}
	if gateErr != nil {
		reasons = append(reasons, "incomplete scan")
	} else {
		gateValue = gate
		if !gate {
			reasons = append(reasons, "high or critical finding")
		}
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE scans SET gate_pass=$2 WHERE id=$1`, id, gateValue); err != nil {
		fail(w, 500, "gate save failed")
		return
	}
	reasonsJSON, _ := json.Marshal(reasons)
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO gate_evaluations(scan_id,revision,policy_version,passed,reasons) VALUES($1,1,1,$2,$3)`, id, gateValue, string(reasonsJSON)); err != nil {
		fail(w, 500, "gate save failed")
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, 500, "scan commit failed")
		return
	}
	s.audit(r.Context(), p.UserID, "scan.ingest", id, map[string]any{"repository_id": in.RepositoryID, "status": status})
	jsonOut(w, 201, map[string]any{"id": id, "status": status, "gate_pass": gateValue, "gate_revision": 1, "new": newCount, "baseline_unknown": unknownCount, "dashboard_url": "/scans/" + id})
}

func (s *Server) scanByID(w http.ResponseWriter, r *http.Request, id string) {
	var repo, branch, commit, base, status, modules string
	var gate sql.NullBool
	var rev int
	var created time.Time
	err := s.DB.QueryRowContext(r.Context(), `SELECT repository_id,branch,commit_sha,base_sha,status,module_status::text,gate_pass,gate_revision,created_at FROM scans WHERE id=$1`, id).Scan(&repo, &branch, &commit, &base, &status, &modules, &gate, &rev, &created)
	if err != nil {
		fail(w, 404, "scan not found")
		return
	}
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	var verdict any = nil
	if gate.Valid {
		verdict = gate.Bool
	}
	var newCount, unknownCount int
	_ = s.DB.QueryRowContext(r.Context(), `SELECT count(*) FILTER(WHERE baseline_status='new'),count(*) FILTER(WHERE baseline_status='baseline_unknown') FROM occurrences WHERE scan_id=$1`, id).Scan(&newCount, &unknownCount)
	jsonOut(w, 200, map[string]any{"id": id, "repository_id": repo, "branch": branch, "commit_sha": commit, "base_sha": base, "status": status, "modules": json.RawMessage(modules), "gate_pass": verdict, "gate_revision": rev, "created_at": created, "new": newCount, "baseline_unknown": unknownCount, "dashboard_url": "/scans/" + id})
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "scans:read") {
		return
	}
	s.scanByID(w, r, r.PathValue("id"))
}
func (s *Server) scans(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "scans:read") {
		return
	}
	repo := r.URL.Query().Get("repository_id")
	if repo != "" && !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT id,repository_id,branch,commit_sha,status,gate_pass,created_at FROM scans WHERE ($1='' OR repository_id=$1) ORDER BY created_at DESC LIMIT 100`, repo)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, rep, branch, commit, status string
		var gate sql.NullBool
		var at time.Time
		_ = rows.Scan(&id, &rep, &branch, &commit, &status, &gate, &at)
		if !s.repoAllowed(r.Context(), who(r), rep) {
			continue
		}
		var verdict any = nil
		if gate.Valid {
			verdict = gate.Bool
		}
		out = append(out, map[string]any{"id": id, "repository_id": rep, "branch": branch, "commit_sha": commit, "status": status, "gate_pass": verdict, "created_at": at})
	}
	jsonOut(w, 200, out)
}

type findingRow struct {
	ID, RepositoryID, Repository, Branch, Module, RuleID, Path, Message, Raw, Effective, Baseline, ScanID string
	Line                                                                                                  int
	At                                                                                                    time.Time
}

func (s *Server) findingRows(r *http.Request) ([]findingRow, error) {
	q := r.URL.Query()
	repo := q.Get("repository_id")
	branch := q.Get("branch")
	module := q.Get("module")
	severity := q.Get("severity")
	if repo != "" && !s.repoAllowed(r.Context(), who(r), repo) {
		return nil, errors.New("repository denied")
	}
	rows, err := s.DB.QueryContext(r.Context(), `WITH latest AS (SELECT DISTINCT ON(repository_id,branch) id FROM scans WHERE status='complete' ORDER BY repository_id,branch,created_at DESC,id DESC) SELECT f.id,f.repository_id,r.name,s.branch,f.module,f.rule_id,f.path,f.message,o.raw_severity,o.effective_severity,o.baseline_status,o.line,s.id,s.created_at FROM latest l JOIN scans s ON s.id=l.id JOIN occurrences o ON o.scan_id=s.id JOIN findings f ON f.id=o.finding_id JOIN repositories r ON r.id=f.repository_id WHERE ($1='' OR f.repository_id=$1) AND ($2='' OR s.branch=$2) AND ($3='' OR f.module=$3) AND ($4='' OR o.effective_severity=$4) ORDER BY s.created_at DESC LIMIT 1000`, repo, branch, module, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []findingRow{}
	for rows.Next() {
		var x findingRow
		err = rows.Scan(&x.ID, &x.RepositoryID, &x.Repository, &x.Branch, &x.Module, &x.RuleID, &x.Path, &x.Message, &x.Raw, &x.Effective, &x.Baseline, &x.Line, &x.ScanID, &x.At)
		if err != nil {
			return nil, err
		}
		if s.repoAllowed(r.Context(), who(r), x.RepositoryID) {
			out = append(out, x)
		}
	}
	return out, rows.Err()
}
func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "findings:read") {
		return
	}
	rows, err := s.findingRows(r)
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	jsonOut(w, 200, rows)
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:read") {
		return
	}
	repoFilter := r.URL.Query().Get("repository_id")
	rows, err := s.DB.QueryContext(r.Context(), `SELECT r.id,r.name,r.default_branch,ls.id,ls.status,ls.created_at,ok.id,ok.created_at FROM repositories r LEFT JOIN LATERAL (SELECT id,status,created_at FROM scans WHERE repository_id=r.id AND branch=r.default_branch ORDER BY created_at DESC LIMIT 1) ls ON true LEFT JOIN LATERAL (SELECT id,created_at FROM scans WHERE repository_id=r.id AND branch=r.default_branch AND status='complete' ORDER BY created_at DESC LIMIT 1) ok ON true ORDER BY r.name`)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	type summary struct {
		ID, Name, Branch, Status          string
		LastScan, LastSuccessful          any
		Critical, High, Medium, Low, Info int
		Gate                              any
		Coverage                          int
	}
	out := []summary{}
	totals := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	covered := 0
	for rows.Next() {
		var id, name, branch string
		var scanID, status, successfulID sql.NullString
		var at, successfulAt sql.NullTime
		_ = rows.Scan(&id, &name, &branch, &scanID, &status, &at, &successfulID, &successfulAt)
		if repoFilter != "" && repoFilter != id {
			continue
		}
		if !s.repoAllowed(r.Context(), who(r), id) {
			continue
		}
		item := summary{ID: id, Name: name, Branch: branch, Status: "never", LastScan: nil}
		if scanID.Valid {
			item.Status = status.String
			item.LastScan = at.Time
			var gate sql.NullBool
			_ = s.DB.QueryRowContext(r.Context(), `SELECT gate_pass FROM scans WHERE id=$1`, scanID.String).Scan(&gate)
			if gate.Valid {
				item.Gate = gate.Bool
			}
			if status.String == "complete" {
				covered++
			}
		}
		if successfulID.Valid {
			item.LastSuccessful = successfulAt.Time
			fr, _ := s.DB.QueryContext(r.Context(), `SELECT effective_severity,count(*) FROM occurrences WHERE scan_id=$1 GROUP BY effective_severity`, successfulID.String)
			if fr != nil {
				for fr.Next() {
					var severity string
					var n int
					_ = fr.Scan(&severity, &n)
					totals[severity] += n
					switch severity {
					case "critical":
						item.Critical = n
					case "high":
						item.High = n
					case "medium":
						item.Medium = n
					case "low":
						item.Low = n
					case "info":
						item.Info = n
					}
				}
				fr.Close()
			}
		}
		out = append(out, item)
	}
	jsonOut(w, 200, map[string]any{"repositories": out, "totals": totals, "enrolled": len(out), "covered": covered, "coverage_percent": percent(covered, len(out)), "ark": totals["critical"] + totals["high"], "generated_at": time.Now().UTC()})
}
func percent(n, d int) int {
	if d == 0 {
		return 0
	}
	return 100 * n / d
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "reports:export") {
		return
	}
	rows, err := s.findingRows(r)
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	format := r.URL.Query().Get("format")
	s.audit(r.Context(), who(r).UserID, "report.export", "technical", map[string]any{"format": format, "count": len(rows)})
	if format == "json" {
		w.Header().Set("Content-Disposition", "attachment; filename=panbox-technical.json")
		jsonOut(w, 200, map[string]any{"report_id": core.ID(), "generated_at": time.Now().UTC(), "template": "technical-v1", "rows": rows})
		return
	}
	if format != "csv" {
		fail(w, 400, "format must be csv or json")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=panbox-technical.csv")
	c := csv.NewWriter(w)
	_ = c.Write([]string{"finding_id", "repository_id", "repository", "branch", "module", "rule_id", "path", "line", "raw_severity", "effective_severity", "baseline_status", "scan_id"})
	for _, x := range rows {
		_ = c.Write([]string{x.ID, x.RepositoryID, x.Repository, x.Branch, x.Module, x.RuleID, x.Path, strconv.Itoa(x.Line), x.Raw, x.Effective, x.Baseline, x.ScanID})
	}
	c.Flush()
}
func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "audit:read") {
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `SELECT id,COALESCE(actor_id,''),action,target,detail::text,created_at FROM audit_events ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, actor, action, target, detail string
		var at time.Time
		_ = rows.Scan(&id, &actor, &action, &target, &detail, &at)
		out = append(out, map[string]any{"id": id, "actor_id": actor, "action": action, "target": target, "detail": json.RawMessage(detail), "created_at": at})
	}
	jsonOut(w, 200, out)
}

var _ = fmt.Sprintf
