package server

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

type repoInput struct {
	Name              string `json:"name"`
	Provider          string `json:"provider"`
	ProviderProjectID string `json:"provider_project_id"`
	SCMBaseURL        string `json:"scm_base_url"`
	DefaultBranch     string `json:"default_branch"`
	BranchMode        string `json:"branch_mode"`
	Owner             string `json:"owner"`
}

var branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func validBranch(v string) bool {
	return len(v) <= 240 && branchPattern.MatchString(v) && !strings.Contains(v, "..") && !strings.Contains(v, "//") && !strings.HasSuffix(v, "/") && !strings.HasSuffix(v, ".lock")
}

func normalizeRepoInput(in *repoInput) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	in.ProviderProjectID = strings.TrimSpace(in.ProviderProjectID)
	in.SCMBaseURL = strings.TrimSuffix(strings.TrimSpace(in.SCMBaseURL), "/")
	in.DefaultBranch = strings.TrimSpace(in.DefaultBranch)
	in.BranchMode = strings.TrimSpace(in.BranchMode)
	in.Owner = strings.TrimSpace(in.Owner)
	if in.BranchMode == "" {
		if in.DefaultBranch == "" {
			in.BranchMode = "auto"
		} else {
			in.BranchMode = "manual"
		}
	}
	if in.Name == "" || len(in.Name) > 120 || len(in.Owner) > 120 || len(in.ProviderProjectID) > 240 || (in.BranchMode != "auto" && in.BranchMode != "manual") {
		return errors.New("invalid repository name, path, owner, or branch mode")
	}
	if _, _, err := inspectionURL(in.Provider, in.ProviderProjectID, in.SCMBaseURL); err != nil {
		return err
	}
	if in.BranchMode == "manual" && !validBranch(in.DefaultBranch) {
		return errors.New("enter a valid manual default branch")
	}
	return nil
}

func (s *Server) repoDetail(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:read") {
		return
	}
	id := r.PathValue("id")
	if !s.repoAllowed(r.Context(), who(r), id) {
		fail(w, 403, "repository denied")
		return
	}
	var name, provider, project, baseURL, branch, source, owner, check string
	var archived sql.NullTime
	var scans, findings int
	err := s.DB.QueryRowContext(r.Context(), `SELECT name,provider,provider_project_id,scm_base_url,default_branch,default_branch_source,owner,scm_check_status,archived_at FROM repositories WHERE id=$1`, id).Scan(&name, &provider, &project, &baseURL, &branch, &source, &owner, &check, &archived)
	if err != nil {
		fail(w, 404, "repository not found")
		return
	}
	if archived.Valid && !who(r).Admin {
		fail(w, 404, "repository not found")
		return
	}
	_ = s.DB.QueryRowContext(r.Context(), `SELECT count(*) FROM scans WHERE repository_id=$1`, id).Scan(&scans)
	_ = s.DB.QueryRowContext(r.Context(), `SELECT count(*) FROM findings WHERE repository_id=$1`, id).Scan(&findings)
	jsonOut(w, 200, map[string]any{"id": id, "name": name, "provider": provider, "provider_project_id": project, "scm_base_url": baseURL, "default_branch": branch, "default_branch_source": source, "owner": owner, "scm_check_status": check, "archived": archived.Valid, "scan_count": scans, "finding_count": findings})
}

func (s *Server) updateRepo(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:write") {
		return
	}
	id := r.PathValue("id")
	if !s.repoAllowed(r.Context(), who(r), id) {
		fail(w, 403, "repository denied")
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
	var oldProvider, oldProject, oldBase string
	var scanCount int
	err := s.DB.QueryRowContext(r.Context(), `SELECT provider,provider_project_id,scm_base_url,(SELECT count(*) FROM scans WHERE repository_id=$1) FROM repositories WHERE id=$1 AND archived_at IS NULL`, id).Scan(&oldProvider, &oldProject, &oldBase, &scanCount)
	if err != nil {
		fail(w, 404, "repository not found")
		return
	}
	if scanCount > 0 && (oldProvider != in.Provider || oldProject != in.ProviderProjectID || oldBase != in.SCMBaseURL) {
		fail(w, 409, "SCM identity is locked after the first scan; archive and enroll a new repository")
		return
	}
	check, err := inspectSCM(r.Context(), in.Provider, in.ProviderProjectID, in.SCMBaseURL)
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
	if in.BranchMode != "ci_pending" && !validBranch(in.DefaultBranch) {
		fail(w, 422, "a valid default branch is required")
		return
	}
	_, err = s.DB.ExecContext(r.Context(), `UPDATE repositories SET name=$2,provider=$3,provider_project_id=$4,scm_base_url=$5,default_branch=$6,default_branch_source=$7,owner=$8,scm_check_status=$9,scm_checked_at=now() WHERE id=$1`, id, in.Name, in.Provider, in.ProviderProjectID, in.SCMBaseURL, in.DefaultBranch, in.BranchMode, in.Owner, check.Status)
	if err != nil {
		fail(w, 409, "repository identity already enrolled or invalid")
		return
	}
	s.audit(r.Context(), who(r).UserID, "repo.update", id, map[string]any{"default_branch": in.DefaultBranch, "branch_mode": in.BranchMode, "scm_check_status": check.Status})
	jsonOut(w, 200, map[string]any{"id": id, "default_branch": in.DefaultBranch, "default_branch_source": in.BranchMode, "scm_check_status": check.Status})
}

func (s *Server) deleteRepo(w http.ResponseWriter, r *http.Request) {
	if !who(r).Admin {
		fail(w, 403, "admin required to remove a repository")
		return
	}
	id := r.PathValue("id")
	var name string
	err := s.DB.QueryRowContext(r.Context(), `SELECT name FROM repositories WHERE id=$1 AND archived_at IS NULL`, id).Scan(&name)
	if err != nil {
		fail(w, 404, "repository not found")
		return
	}
	if r.URL.Query().Get("confirm") != name {
		fail(w, 400, "confirm repository name exactly")
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var scans int
	if err = tx.QueryRowContext(r.Context(), `SELECT name FROM repositories WHERE id=$1 AND archived_at IS NULL FOR UPDATE`, id).Scan(&name); err != nil {
		fail(w, 404, "repository not found")
		return
	}
	if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM scans WHERE repository_id=$1`, id).Scan(&scans); err != nil {
		fail(w, 500, "scan lookup failed")
		return
	}
	status := "archived"
	if scans == 0 {
		status = "deleted"
		for _, query := range []string{
			`DELETE FROM credentials WHERE repository_id=$1`,
			`DELETE FROM repository_members WHERE repository_id=$1`,
			`DELETE FROM repository_scan_configs WHERE repository_id=$1`,
			`DELETE FROM findings WHERE repository_id=$1`,
			`DELETE FROM repositories WHERE id=$1`,
		} {
			if _, err = tx.ExecContext(r.Context(), query, id); err != nil {
				fail(w, 500, "repository removal failed")
				return
			}
		}
	} else {
		if _, err = tx.ExecContext(r.Context(), `UPDATE repositories SET archived_at=now() WHERE id=$1`, id); err != nil {
			fail(w, 500, "repository archive failed")
			return
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE credentials SET revoked_at=now() WHERE repository_id=$1 AND revoked_at IS NULL`, id); err != nil {
			fail(w, 500, "scan key revocation failed")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		fail(w, 500, "repository removal failed")
		return
	}
	s.audit(r.Context(), who(r).UserID, "repo."+status, id, map[string]any{"name": name, "scans": scans})
	jsonOut(w, 200, map[string]string{"id": id, "status": status})
}

func (s *Server) restoreRepo(w http.ResponseWriter, r *http.Request) {
	if !who(r).Admin {
		fail(w, 403, "admin required to restore a repository")
		return
	}
	id := r.PathValue("id")
	result, err := s.DB.ExecContext(r.Context(), `UPDATE repositories SET archived_at=NULL WHERE id=$1 AND archived_at IS NOT NULL`, id)
	if err != nil {
		fail(w, 409, "an active repository has the same SCM identity")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		fail(w, 404, "archived repository not found")
		return
	}
	s.audit(r.Context(), who(r).UserID, "repo.restore", id, map[string]any{})
	jsonOut(w, 200, map[string]string{"id": id, "status": "active", "note": "use an API key with scans:write and project access for CI upload"})
}
