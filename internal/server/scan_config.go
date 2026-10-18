package server

import (
	"database/sql"
	"net/http"
	"panbox/internal/core"
)

type scanConfig struct {
	RepositoryID string `json:"repository_id"`
	Enabled      bool   `json:"enabled"`
	Vaccin       bool   `json:"vaccin"`
	Enetron      bool   `json:"enetron"`
	GateSeverity string `json:"gate_severity"`
	Version      int    `json:"version"`
}

func (s *Server) scanConfigFor(repo string) (scanConfig, error) {
	out := scanConfig{RepositoryID: repo, Enabled: true, Vaccin: true, Enetron: true, GateSeverity: "high", Version: 1}
	var exists bool
	if err := s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1 AND archived_at IS NULL)`, repo).Scan(&exists); err != nil {
		return out, err
	}
	if !exists {
		return out, sql.ErrNoRows
	}
	err := s.DB.QueryRow(`SELECT enabled,vaccin,enetron,gate_severity,version FROM repository_scan_configs WHERE repository_id=$1`, repo).Scan(&out.Enabled, &out.Vaccin, &out.Enetron, &out.GateSeverity, &out.Version)
	if err == sql.ErrNoRows {
		return out, nil
	}
	return out, err
}

func (s *Server) getScanConfig(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	if !has(p, "repos:read") && !((p.Kind == "scan" || p.Kind == "api") && has(p, "scans:write")) {
		fail(w, 403, "permission denied")
		return
	}
	repo := r.PathValue("id")
	if !s.repoAllowed(r.Context(), p, repo) {
		fail(w, 403, "repository denied: check PANBOX project ID, API key repository scope, and key owner's repository access")
		return
	}
	cfg, err := s.scanConfigFor(repo)
	if err != nil {
		fail(w, 404, "repository not found")
		return
	}
	jsonOut(w, 200, cfg)
}

func (s *Server) putScanConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:write") {
		return
	}
	repo := r.PathValue("id")
	if !s.repoAllowed(r.Context(), who(r), repo) {
		fail(w, 403, "repository denied")
		return
	}
	var in scanConfig
	if !decode(w, r, &in) {
		return
	}
	if !core.ValidSeverity(in.GateSeverity) || (!in.Vaccin && !in.Enetron) {
		fail(w, 400, "select at least one module and a valid gate severity")
		return
	}
	err := s.DB.QueryRowContext(r.Context(), `INSERT INTO repository_scan_configs(repository_id,enabled,vaccin,enetron,gate_severity) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(repository_id) DO UPDATE SET enabled=$2,vaccin=$3,enetron=$4,gate_severity=$5,version=repository_scan_configs.version+1,updated_at=now()
      RETURNING version`, repo, in.Enabled, in.Vaccin, in.Enetron, in.GateSeverity).Scan(&in.Version)
	if err != nil {
		fail(w, 400, "repository invalid")
		return
	}
	in.RepositoryID = repo
	s.audit(r.Context(), who(r).UserID, "scan_config.update", repo, in)
	jsonOut(w, 200, in)
}
