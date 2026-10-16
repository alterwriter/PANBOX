package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type gitlabJob struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	Ref           string `json:"ref"`
	ArtifactsFile struct {
		Filename string `json:"filename"`
	} `json:"artifacts_file"`
}

func relayPull(args []string) int {
	f := flag.NewFlagSet("relay-pull", flag.ContinueOnError)
	project := f.String("project-id", "", "GitLab numeric project ID")
	repo := f.String("repo", os.Getenv("PANBOX_REPOSITORY_ID"), "enrolled PANBOX repository ID")
	gitlab := f.String("gitlab-url", "https://gitlab.com", "GitLab base URL")
	server := f.String("server", os.Getenv("PANBOX_SERVER"), "PANBOX URL")
	statePath := f.String("state", "panbox-relay-state.json", "processed job state file")
	refs := f.String("refs", "main", "comma-separated exact allowed GitLab refs")
	if f.Parse(args) != nil {
		return 2
	}
	if _, err := strconv.ParseInt(*project, 10, 64); err != nil || *repo == "" {
		fmt.Fprintln(os.Stderr, "numeric project ID and repository ID required")
		return 2
	}
	base, err := baseServer(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !strings.HasPrefix(*gitlab, "https://") {
		fmt.Fprintln(os.Stderr, "GitLab URL must use HTTPS")
		return 2
	}
	panboxToken := os.Getenv("PANBOX_TOKEN")
	if panboxToken == "" {
		fmt.Fprintln(os.Stderr, "PANBOX_TOKEN required")
		return 3
	}
	processed := map[int64]bool{}
	if raw, err := os.ReadFile(*statePath); err == nil {
		var ids []int64
		if json.Unmarshal(raw, &ids) == nil {
			for _, id := range ids {
				processed[id] = true
			}
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := strings.TrimRight(*gitlab, "/") + "/api/v4/projects/" + *project
	jobsRaw, err := gitlabGet(client, endpoint+"/jobs?scope%5B%5D=success&per_page=100")
	if err != nil {
		fmt.Fprintln(os.Stderr, "GitLab jobs: "+err.Error())
		return 2
	}
	var jobs []gitlabJob
	if json.Unmarshal(jobsRaw, &jobs) != nil {
		fmt.Fprintln(os.Stderr, "invalid GitLab response")
		return 2
	}
	allowed := map[string]bool{}
	for _, ref := range strings.Split(*refs, ",") {
		allowed[strings.TrimSpace(ref)] = true
	}
	newJobs := []gitlabJob{}
	for _, job := range jobs {
		if job.Name == "panbox_bundle" && job.Status == "success" && allowed[job.Ref] && job.ArtifactsFile.Filename != "" && !processed[job.ID] {
			newJobs = append(newJobs, job)
		}
	}
	for i, j := 0, len(newJobs)-1; i < j; i, j = i+1, j-1 {
		newJobs[i], newJobs[j] = newJobs[j], newJobs[i]
	}
	for _, job := range newJobs {
		artifact, err := gitlabGet(client, endpoint+"/jobs/"+strconv.FormatInt(job.ID, 10)+"/artifacts/panbox-results.json")
		if err != nil {
			fmt.Fprintln(os.Stderr, "artifact download failed: "+err.Error())
			return 2
		}
		var b bundle
		if json.Unmarshal(artifact, &b) != nil || b.RepositoryID != *repo {
			fmt.Fprintln(os.Stderr, "artifact repo mismatch or invalid bundle")
			return 3
		}
		req, _ := http.NewRequest("POST", base+"/v1/scans", bytes.NewReader(artifact))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+panboxToken)
		res, err := client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "PANBOX upload failed: "+err.Error())
			return 2
		}
		payload, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		if res.StatusCode != 200 && res.StatusCode != 201 {
			fmt.Fprintf(os.Stderr, "PANBOX upload rejected (%d): %s\n", res.StatusCode, payload)
			if res.StatusCode == 401 || res.StatusCode == 403 {
				return 3
			}
			return 2
		}
		processed[job.ID] = true
		fmt.Printf("Imported GitLab job %d into PANBOX\n", job.ID)
	}
	ids := []int64{}
	for id := range processed {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	if len(ids) > 1000 {
		ids = ids[:1000]
	}
	raw, _ := json.Marshal(ids)
	if err := os.MkdirAll(filepath.Dir(*statePath), 0700); err != nil {
		return 2
	}
	tmp := *statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return 2
	}
	if err := os.Rename(tmp, *statePath); err != nil {
		return 2
	}
	return 0
}
func gitlabGet(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if token := os.Getenv("GITLAB_READ_TOKEN"); token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("HTTP " + res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, 9<<20))
}
