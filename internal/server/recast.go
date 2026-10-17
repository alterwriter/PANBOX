package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"panbox/internal/core"
)

// Recast changes effective severity for a stable finding identity. Raw evidence is immutable.
func (s *Server) recastFinding(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "findings:recast") {
		return
	}
	id := r.PathValue("id")
	var in struct {
		Severity string `json:"severity"`
		Reason   string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if (in.Severity != "raw" && !core.ValidSeverity(in.Severity)) || len(in.Reason) < 10 || len(in.Reason) > 500 || containsSecret(in.Reason) {
		fail(w, 400, "valid severity and 10-500 character reason required")
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var repo string
	var previous sql.NullString
	err = tx.QueryRowContext(r.Context(), `SELECT repository_id,recast_severity FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&repo, &previous)
	if err == sql.ErrNoRows {
		fail(w, 404, "finding not found")
		return
	}
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	var newSeverity any = in.Severity
	if in.Severity == "raw" {
		newSeverity = nil
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE findings SET recast_severity=$2 WHERE id=$1`, id, newSeverity); err != nil {
		fail(w, 500, "recast failed")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE occurrences SET effective_severity=COALESCE($2,raw_severity) WHERE finding_id=$1`, id, newSeverity); err != nil {
		fail(w, 500, "recast failed")
		return
	}
	from := "raw"
	if previous.Valid {
		from = previous.String
	}
	recastID := core.ID()
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO finding_recasts(id,finding_id,actor_id,from_severity,to_severity,reason) VALUES($1,$2,$3,$4,$5,$6)`, recastID, id, who(r).UserID, from, in.Severity, in.Reason); err != nil {
		fail(w, 500, "history save failed")
		return
	}
	affected, err := tx.QueryContext(r.Context(), `SELECT DISTINCT s.id,s.status,s.gate_revision,s.gate_severity,s.policy_version FROM scans s JOIN occurrences o ON o.scan_id=s.id WHERE o.finding_id=$1 ORDER BY s.id`, id)
	if err != nil {
		fail(w, 500, "scan lookup failed")
		return
	}
	type affectedScan struct {
		id, status, threshold   string
		revision, policyVersion int
	}
	scans := []affectedScan{}
	for affected.Next() {
		var x affectedScan
		if err = affected.Scan(&x.id, &x.status, &x.revision, &x.threshold, &x.policyVersion); err != nil {
			break
		}
		scans = append(scans, x)
	}
	affected.Close()
	if err != nil {
		fail(w, 500, "scan lookup failed")
		return
	}
	for _, scan := range scans {
		severityRows, qerr := tx.QueryContext(r.Context(), `SELECT effective_severity FROM occurrences WHERE scan_id=$1`, scan.id)
		if qerr != nil {
			fail(w, 500, "gate lookup failed")
			return
		}
		severities := []string{}
		for severityRows.Next() {
			var v string
			if qerr = severityRows.Scan(&v); qerr != nil {
				break
			}
			severities = append(severities, v)
		}
		severityRows.Close()
		if qerr != nil {
			fail(w, 500, "gate lookup failed")
			return
		}
		pass, gateErr := core.GateAt(scan.status, severities, scan.threshold)
		var verdict any
		reasons := []string{}
		if gateErr != nil {
			reasons = append(reasons, "incomplete scan")
		} else {
			verdict = pass
			if !pass {
				reasons = append(reasons, "finding at or above "+scan.threshold)
			}
		}
		revision := scan.revision + 1
		if _, err = tx.ExecContext(r.Context(), `UPDATE scans SET gate_pass=$2,gate_revision=$3 WHERE id=$1`, scan.id, verdict, revision); err != nil {
			fail(w, 500, "gate update failed")
			return
		}
		reasonJSON, _ := json.Marshal(reasons)
		if _, err = tx.ExecContext(r.Context(), `INSERT INTO gate_evaluations(scan_id,revision,policy_version,passed,reasons) VALUES($1,$2,$3,$4,$5)`, scan.id, revision, scan.policyVersion, verdict, string(reasonJSON)); err != nil {
			fail(w, 500, "gate history failed")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		fail(w, 500, "recast commit failed")
		return
	}
	s.audit(r.Context(), who(r).UserID, "finding.recast", id, map[string]any{"from": from, "to": in.Severity, "reason": in.Reason, "affected_scans": len(scans)})
	jsonOut(w, 200, map[string]any{"id": recastID, "finding_id": id, "severity": in.Severity, "affected_scans": len(scans)})
}

func (s *Server) findingRecasts(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.DB.QueryContext(r.Context(), `SELECT id,actor_id,from_severity,to_severity,reason,created_at FROM finding_recasts WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 100`, id)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var eventID, actor, from, to, reason string
		var at any
		if err = rows.Scan(&eventID, &actor, &from, &to, &reason, &at); err != nil {
			fail(w, 500, "database error")
			return
		}
		out = append(out, map[string]any{"id": eventID, "actor_id": actor, "from": from, "to": to, "reason": reason, "created_at": at})
	}
	jsonOut(w, 200, out)
}
