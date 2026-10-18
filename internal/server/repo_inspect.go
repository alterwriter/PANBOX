package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// SCM inspection is intentionally metadata-only. The server never clones a repository
// or receives a CI runner's SCM credential. A private project must be checked by its runner.
type scmInspection struct {
	Status        string `json:"status"`
	DefaultBranch string `json:"default_branch,omitempty"`
	Owner         string `json:"owner,omitempty"`
	ConnectionID  string `json:"connection_id,omitempty"`
	Message       string `json:"message"`
}

var scmPathPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]*$`)

func pathParts(raw string, min, max int) ([]string, error) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) < min || len(parts) > max || len(raw) > 240 {
		return nil, errors.New("use the provider repository path shown in the SCM")
	}
	for _, part := range parts {
		if part == "." || part == ".." || strings.TrimSpace(part) != part || !scmPathPart.MatchString(part) {
			return nil, errors.New("invalid SCM repository path")
		}
	}
	return parts, nil
}

func escaped(parts ...string) string {
	out := make([]string, len(parts))
	for i, part := range parts {
		out[i] = url.PathEscape(part)
	}
	return strings.Join(out, "/")
}

func allowedCustomHost(host string) bool {
	for _, entry := range strings.Split(os.Getenv("PANBOX_SCM_ALLOWED_HOSTS"), ",") {
		if strings.EqualFold(strings.TrimSpace(entry), host) && host != "" {
			return true
		}
	}
	return false
}

func customSCMBase(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Hostname() == "" || !allowedCustomHost(u.Host) {
		return "", errors.New("self-hosted SCM requires an HTTPS origin whose exact host is in PANBOX_SCM_ALLOWED_HOSTS")
	}
	return "https://" + u.Host, nil
}

func inspectionURL(provider, project, baseURL string) (string, string, error) {
	if baseURL != "" && provider != "github" && provider != "gitlab" && provider != "gitea" && provider != "generic" {
		return "", "", errors.New("self-hosted URL is supported for GitHub, GitLab, Gitea, or Other Git")
	}
	if baseURL != "" {
		var err error
		baseURL, err = customSCMBase(baseURL)
		if err != nil {
			return "", "", err
		}
	}
	switch provider {
	case "github", "bitbucket":
		parts, err := pathParts(project, 2, 2)
		if err != nil {
			return "", "", err
		}
		if provider == "github" && baseURL != "" {
			return baseURL + "/api/v3/repos/" + escaped(parts...), parts[0], nil
		}
		if provider == "github" {
			return "https://api.github.com/repos/" + escaped(parts...), parts[0], nil
		}
		return "https://api.bitbucket.org/2.0/repositories/" + escaped(parts...), parts[0], nil
	case "gitlab":
		parts, err := pathParts(project, 2, 10)
		if err != nil {
			return "", "", err
		}
		if baseURL == "" {
			baseURL = "https://gitlab.com"
		}
		return baseURL + "/api/v4/projects/" + url.PathEscape(strings.Join(parts, "/")), strings.Join(parts[:len(parts)-1], "/"), nil
	case "azure":
		parts, err := pathParts(project, 3, 3)
		if err != nil {
			return "", "", errors.New("Azure Repos path must be organization/project/repository")
		}
		return "https://dev.azure.com/" + escaped(parts[0], parts[1]) + "/_apis/git/repositories/" + url.PathEscape(parts[2]) + "?api-version=7.1", parts[0], nil
	case "gitea", "generic":
		if baseURL == "" {
			u, err := url.Parse(project)
			if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
				return "", "", errors.New("enter an HTTPS repository URL or choose a self-hosted SCM origin")
			}
			baseURL, err = customSCMBase("https://" + u.Host)
			if err != nil {
				return "", "", err
			}
			project = strings.Trim(u.Path, "/")
		}
		rawPath := strings.Trim(project, "/")
		parts, err := pathParts(strings.TrimSuffix(rawPath, ".git"), 2, 20)
		if err != nil {
			return "", "", err
		}
		if provider == "gitea" {
			if len(parts) != 2 {
				return "", "", errors.New("Gitea URL must end in /owner/repository")
			}
			return baseURL + "/api/v1/repos/" + escaped(parts...), parts[0], nil
		}
		if strings.HasSuffix(rawPath, ".git") {
			parts[len(parts)-1] += ".git"
		}
		return baseURL + "/" + escaped(parts...) + "/info/refs?service=git-upload-pack", "", nil
	default:
		return "", "", errors.New("unsupported SCM provider")
	}
}

func inspectSCM(ctx context.Context, provider, project, baseURL string) (scmInspection, error) {
	client := &http.Client{Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return inspectSCMWithClient(ctx, provider, project, baseURL, client)
}

func inspectSCMWithClient(ctx context.Context, provider, project, baseURL string, client *http.Client) (scmInspection, error) {
	endpoint, owner, err := inspectionURL(provider, project, baseURL)
	if err != nil {
		return scmInspection{Status: "manual_required", Message: err.Error()}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return scmInspection{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PANBOX-SCM-check/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return scmInspection{Status: "manual_required", Message: "SCM metadata could not be reached from the PANBOX server; validate from the CI runner"}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return scmInspection{Status: "manual_required", Message: fmt.Sprintf("SCM returned HTTP %d; private repositories need a runner-side check", resp.StatusCode)}, nil
	}
	if provider == "generic" {
		if !strings.Contains(resp.Header.Get("Content-Type"), "git-upload-pack-advertisement") {
			return scmInspection{Status: "manual_required", Message: "SCM responded, but its Git smart-HTTP endpoint was not confirmed"}, nil
		}
		return scmInspection{Status: "reachable_no_branch", Message: "Git endpoint is reachable; CI can report its default branch on the first upload"}, nil
	}
	var meta struct {
		DefaultBranch string `json:"default_branch"`
		AzureBranch   string `json:"defaultBranch"`
		MainBranch    struct {
			Name string `json:"name"`
		} `json:"mainbranch"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&meta); err != nil {
		return scmInspection{Status: "manual_required", Message: "SCM metadata response was invalid"}, nil
	}
	branch := meta.DefaultBranch
	if provider == "bitbucket" {
		branch = meta.MainBranch.Name
	}
	if provider == "azure" {
		branch = strings.TrimPrefix(meta.AzureBranch, "refs/heads/")
	}
	if !validBranch(branch) {
		return scmInspection{Status: "manual_required", Message: "SCM did not return a usable default branch"}, nil
	}
	if meta.Owner.Login != "" {
		owner = meta.Owner.Login
	}
	return scmInspection{Status: "verified", DefaultBranch: branch, Owner: owner, Message: "Repository metadata is reachable from PANBOX; CI runner connectivity must still be checked"}, nil
}

func (s *Server) inspectRepo(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:write") {
		return
	}
	var in struct {
		Provider          string `json:"provider"`
		ProviderProjectID string `json:"provider_project_id"`
		SCMBaseURL        string `json:"scm_base_url"`
		SCMConnectionID   string `json:"scm_connection_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	result, err := s.inspectConnectedSCM(r.Context(), strings.ToLower(strings.TrimSpace(in.Provider)), strings.TrimSpace(in.ProviderProjectID), strings.TrimSpace(in.SCMBaseURL), strings.TrimSpace(in.SCMConnectionID))
	if err != nil {
		fail(w, 500, "SCM inspection failed")
		return
	}
	jsonOut(w, 200, result)
}

func (s *Server) recheckRepoSCM(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, "repos:write") {
		return
	}
	id := r.PathValue("id")
	if !s.repoAllowed(r.Context(), who(r), id) {
		fail(w, 403, "repository denied")
		return
	}
	var provider, project, baseURL, connectionID string
	if err := s.DB.QueryRowContext(r.Context(), `SELECT provider,provider_project_id,scm_base_url,COALESCE(scm_connection_id,'') FROM repositories WHERE id=$1 AND archived_at IS NULL`, id).Scan(&provider, &project, &baseURL, &connectionID); err != nil {
		fail(w, 404, "repository not found")
		return
	}
	result, err := s.inspectConnectedSCM(r.Context(), provider, project, baseURL, connectionID)
	if err != nil {
		fail(w, 500, "SCM inspection failed")
		return
	}
	if result.Status == "verified" {
		_, err = s.DB.ExecContext(r.Context(), `UPDATE repositories SET default_branch=CASE WHEN default_branch_source<>'manual' THEN $2 ELSE default_branch END,default_branch_source=CASE WHEN default_branch_source<>'manual' THEN 'auto' ELSE 'manual' END,owner=CASE WHEN owner='' THEN $3 ELSE owner END,scm_check_status=$4,scm_checked_at=now(),scm_connection_id=COALESCE(NULLIF($5,''),scm_connection_id) WHERE id=$1`, id, result.DefaultBranch, result.Owner, result.Status, result.ConnectionID)
	} else {
		_, err = s.DB.ExecContext(r.Context(), `UPDATE repositories SET scm_check_status=$2,scm_checked_at=now() WHERE id=$1`, id, result.Status)
	}
	if err != nil {
		fail(w, 500, "repository update failed")
		return
	}
	s.audit(r.Context(), who(r).UserID, "repo.scm_recheck", id, map[string]any{"status": result.Status})
	jsonOut(w, 200, result)
}
