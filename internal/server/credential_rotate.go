package server

import (
	"database/sql"
	"net/http"
	"strconv"

	"panbox/internal/core"
)

// Rotate creates a replacement before revoking the old key in one transaction.
// Only a hash is retained; the new plaintext is returned once.
func (s *Server) rotateCredential(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "tokens:manage") {
		return
	}
	var in struct {
		ExpiresHours int `json:"expires_hours"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.ExpiresHours < 1 || in.ExpiresHours > 8760 {
		fail(w, 400, "expiry 1..8760 hours required")
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var kind, label, scopes, repo, owner string
	err = tx.QueryRowContext(r.Context(), `SELECT kind,label,scopes::text,COALESCE(repository_id,''),owner_id FROM credentials WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`, r.PathValue("id")).Scan(&kind, &label, &scopes, &repo, &owner)
	if err == sql.ErrNoRows {
		fail(w, 404, "active key not found")
		return
	}
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if kind == "scan" {
		fail(w, 409, "legacy scan keys cannot rotate; create an API key with scans:write")
		return
	}
	if owner != who(r).UserID && !who(r).Admin {
		fail(w, 403, "key owner or admin required")
		return
	}
	secret, id := core.Secret("pb_"+kind+"_"), core.ID()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO credentials(id,owner_id,kind,label,secret_hash,scopes,repository_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),now()+($8 || ' hours')::interval)`, id, owner, kind, label, core.Hash(secret), scopes, repo, strconv.Itoa(in.ExpiresHours))
	if err != nil {
		fail(w, 500, "replacement key failed")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE credentials SET revoked_at=now() WHERE id=$1`, r.PathValue("id")); err != nil {
		fail(w, 500, "old key revocation failed")
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, 500, "rotation failed")
		return
	}
	s.audit(r.Context(), who(r).UserID, "credential.rotate", id, map[string]string{"previous_id": r.PathValue("id")})
	jsonOut(w, 201, map[string]string{"id": id, "secret": secret})
}
