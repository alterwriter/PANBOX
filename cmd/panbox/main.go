package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"panbox/internal/core"
	"panbox/internal/scanner"
)

type module struct {
	Name    string `json:"name"`
	Engine  string `json:"engine"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}
type finding struct {
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
type bundle struct {
	SchemaVersion string `json:"schema_version"`
	ClientScanID  string `json:"client_scan_id"`
	Scope         string `json:"scope"`
	RepositoryID  string `json:"repository_id"`
	Git           struct {
		Branch        string `json:"branch"`
		DefaultBranch string `json:"default_branch"`
		CommitSHA     string `json:"commit_sha"`
		BaseSHA       string `json:"base_sha"`
	} `json:"git"`
	Modules  []module  `json:"modules"`
	Findings []finding `json:"findings"`
}

type scanConfig struct {
	Enabled      bool   `json:"enabled"`
	Vaccin       bool   `json:"vaccin"`
	Enetron      bool   `json:"enetron"`
	GateSeverity string `json:"gate_severity"`
	Version      int    `json:"version"`
}

func fetchScanConfig(base, repo, token string) (scanConfig, error) {
	var cfg scanConfig
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/repos/"+url.PathEscape(repo)+"/scan-config", nil)
	if err != nil {
		return cfg, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return cfg, fmt.Errorf("scan config HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "ready":
		return ready(args[1:])
	case "go":
		return goScan(args[1:])
	case "relay-pull":
		return relayPull(args[1:])
	case "shutdown":
		return shutdown()
	case "mcp":
		return runMCP(args[1:])
	default:
		usage()
		return 2
	}
}
func usage() { fmt.Fprintln(os.Stderr, "panbox ready|go|relay-pull|mcp|shutdown  (see README.md)") }
func git(path string, args ...string) string {
	c := exec.Command("git", append([]string{"-C", path}, args...)...)
	b, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func ciAPIKey() string {
	if key := os.Getenv("PANBOX_API_KEY"); key != "" {
		return key
	}
	return os.Getenv("PANBOX_TOKEN") // Existing alpha jobs remain usable while migrating.
}
func ciDefaultBranch(path string) string {
	for _, key := range []string{"PANBOX_DEFAULT_BRANCH", "CI_DEFAULT_BRANCH", "GITHUB_DEFAULT_BRANCH"} {
		if branch := os.Getenv(key); branch != "" {
			return branch
		}
	}
	return strings.TrimPrefix(git(path, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"), "origin/")
}
func baseServer(v string) (string, error) {
	u, err := url.Parse(v)
	if err != nil {
		return "", err
	}
	if u.Scheme == "https" {
		return strings.TrimRight(v, "/"), nil
	}
	if u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1") {
		return strings.TrimRight(v, "/"), nil
	}
	return "", errors.New("server requires HTTPS; HTTP is allowed only on loopback")
}
func ready(args []string) int {
	f := flag.NewFlagSet("ready", flag.ContinueOnError)
	server := f.String("server", os.Getenv("PANBOX_SERVER"), "PANBOX URL")
	mods := f.String("modules", "vaccin,enetron", "modules")
	if f.Parse(args) != nil {
		return 2
	}
	base, err := baseServer(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	for _, m := range strings.Split(*mods, ",") {
		if m != "vaccin" && m != "enetron" {
			fmt.Fprintln(os.Stderr, m+": unsupported module")
			return 2
		}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", base+"/readyz", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server: "+err.Error())
		return 2
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 2
	}
	fmt.Println("PANBOX ready: server and native scanner available")
	return 0
}
func shutdown() int {
	cache := filepath.Join(os.TempDir(), "panbox-cli-cache")
	if err := os.RemoveAll(cache); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Println("PANBOX temporary cache cleared")
	return 0
}

func goScan(args []string) int {
	f := flag.NewFlagSet("go", flag.ContinueOnError)
	server := f.String("server", os.Getenv("PANBOX_SERVER"), "PANBOX URL")
	repo := f.String("repo", os.Getenv("PANBOX_REPOSITORY_ID"), "enrolled repository ID")
	path := f.String("path", ".", "scan path")
	mods := f.String("modules", "vaccin,enetron", "modules")
	branch := f.String("branch", "", "Git branch")
	defaultBranch := f.String("default-branch", "", "SCM default branch (auto from CI when available)")
	commit := f.String("commit", "", "Git commit SHA")
	baseSHA := f.String("base-sha", "", "base SHA")
	advisoryURL := f.String("advisory-url", os.Getenv("PANBOX_ADVISORY_URL"), "OSV-compatible advisory API URL")
	offline := f.Bool("offline", false, "save bundle without upload")
	output := f.String("output", "panbox-results.json", "offline output path")
	format := f.String("format", "text", "text|json|sarif")
	_ = f.Bool("no-color", false, "disable ANSI color (default output has no ANSI)")
	fixture := f.String("bundle", "", "upload existing normalized bundle for integration test")
	if f.Parse(args) != nil {
		return 2
	}
	if *format != "text" && *format != "json" && *format != "sarif" {
		fmt.Fprintln(os.Stderr, "format must be text, json or sarif")
		return 2
	}
	if !*offline && *fixture == "" {
		base, err := baseServer(*server)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		token := ciAPIKey()
		if token == "" {
			fmt.Fprintln(os.Stderr, "PANBOX_API_KEY required (PANBOX_TOKEN is accepted for existing jobs)")
			return 3
		}
		if *repo == "" {
			fmt.Fprintln(os.Stderr, "PANBOX_REPOSITORY_ID required")
			return 2
		}
		cfg, err := fetchScanConfig(base, *repo, token)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot load repository scan configuration: "+err.Error())
			return 2
		}
		if !cfg.Enabled {
			fmt.Fprintln(os.Stderr, "scanning disabled for this repository")
			return 2
		}
		selected := []string{}
		requested := map[string]bool{}
		f.Visit(func(x *flag.Flag) {
			if x.Name == "modules" {
				for _, m := range strings.Split(*mods, ",") {
					requested[strings.TrimSpace(m)] = true
				}
			}
		})
		for _, m := range []string{"vaccin", "enetron"} {
			enabled := (m == "vaccin" && cfg.Vaccin) || (m == "enetron" && cfg.Enetron)
			if enabled && (len(requested) == 0 || requested[m]) {
				selected = append(selected, m)
			}
			if requested[m] && !enabled {
				fmt.Fprintln(os.Stderr, m+" disabled by repository configuration")
				return 2
			}
		}
		if len(selected) == 0 {
			fmt.Fprintln(os.Stderr, "no enabled modules selected")
			return 2
		}
		*mods = strings.Join(selected, ",")
	}
	var b bundle
	if *fixture != "" {
		raw, err := os.ReadFile(*fixture)
		if err != nil || json.Unmarshal(raw, &b) != nil {
			fmt.Fprintln(os.Stderr, "invalid bundle file")
			return 2
		}
	} else {
		if *repo == "" {
			fmt.Fprintln(os.Stderr, "PANBOX_REPOSITORY_ID required")
			return 2
		}
		b.SchemaVersion = "1.0"
		b.ClientScanID = core.ID()
		b.Scope = "repo"
		b.RepositoryID = *repo
		b.Git.DefaultBranch = *defaultBranch
		if b.Git.DefaultBranch == "" {
			b.Git.DefaultBranch = ciDefaultBranch(*path)
		}
		b.Git.Branch = *branch
		if b.Git.Branch == "" {
			for _, key := range []string{"CI_COMMIT_REF_NAME", "GITHUB_HEAD_REF", "GITHUB_REF_NAME", "BITBUCKET_BRANCH", "BUILD_SOURCEBRANCHNAME"} {
				if b.Git.Branch == "" {
					b.Git.Branch = os.Getenv(key)
				}
			}
		}
		if b.Git.Branch == "" {
			b.Git.Branch = git(*path, "branch", "--show-current")
		}
		b.Git.CommitSHA = *commit
		if b.Git.CommitSHA == "" {
			b.Git.CommitSHA = git(*path, "rev-parse", "HEAD")
		}
		b.Git.BaseSHA = *baseSHA
		if b.Git.Branch == "" || b.Git.CommitSHA == "" {
			fmt.Fprintln(os.Stderr, "branch and commit required; use flags for non-Git paths")
			return 2
		}
		failed := false
		for _, m := range strings.Split(*mods, ",") {
			m = strings.TrimSpace(m)
			var native []scanner.Finding
			var err error
			switch m {
			case "vaccin":
				native, err = scanner.Vaccin(*path)
			case "enetron":
				native, err = scanner.Enetron(context.Background(), *path, *advisoryURL)
			default:
				err = errors.New("unsupported module")
			}
			status := "complete"
			moduleMessage := ""
			if errors.Is(err, scanner.ErrNoDependencyManifest) {
				fmt.Fprintln(os.Stderr, "enetron: skipped (no supported dependency manifest; source scan can still complete)")
				status = "skipped"
				moduleMessage = "No supported dependency manifest found; ENETRON did not apply to this repository."
				err = nil
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, m+": "+err.Error())
				status = "error"
				failed = true
			} else {
				for _, n := range native {
					f := finding{Module: n.Module, RuleID: n.RuleID, RawSeverity: n.Severity, Fingerprint: core.Hash(n.Identity), Message: n.Message}
					f.Location.Path, f.Location.Line = n.Path, n.Line
					b.Findings = append(b.Findings, f)
				}
			}
			b.Modules = append(b.Modules, module{Name: m, Engine: "panbox-native", Version: scanner.Version, Status: status, Message: moduleMessage})
		}
		if failed && len(b.Modules) == 0 {
			return 2
		}
	}
	if *offline {
		var raw []byte
		if *format == "sarif" {
			raw, _ = json.MarshalIndent(toSARIF(b, "unverified"), "", "  ")
		} else {
			raw, _ = json.MarshalIndent(b, "", "  ")
		}
		if err := os.WriteFile(*output, raw, 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf("Offline bundle: %s (gate unverified)\n", *output)
		return 2
	}
	base, err := baseServer(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	token := ciAPIKey()
	if token == "" {
		fmt.Fprintln(os.Stderr, "PANBOX_API_KEY required (PANBOX_TOKEN is accepted for existing jobs)")
		return 3
	}
	raw, _ := json.Marshal(b)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/scans", bytes.NewReader(raw))
	if err != nil {
		return 2
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upload failed: "+err.Error())
		return 2
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		fmt.Fprintln(os.Stderr, "server rejected token or repository permission")
		return 3
	}
	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "server rejected scan (%d): %s\n", resp.StatusCode, payload)
		return 2
	}
	var result struct {
		ID, Status      string
		GatePass        *bool  `json:"gate_pass"`
		New             int    `json:"new"`
		BaselineUnknown int    `json:"baseline_unknown"`
		DashboardURL    string `json:"dashboard_url"`
	}
	if json.Unmarshal(payload, &result) != nil {
		return 2
	}
	if *format == "json" {
		fmt.Println(string(payload))
	} else if *format == "sarif" {
		gate := "incomplete"
		if result.GatePass != nil {
			if *result.GatePass {
				gate = "pass"
			} else {
				gate = "fail"
			}
		}
		output, _ := json.Marshal(toSARIF(b, gate))
		fmt.Println(string(output))
	} else {
		fmt.Printf("PANBOX scan %s · %s · %d findings · %d new · %d baseline unknown\n", result.ID, result.Status, len(b.Findings), result.New, result.BaselineUnknown)
		for i, f := range b.Findings {
			if i >= 3 {
				break
			}
			fmt.Printf("  %s %s %s:%d\n", strings.ToUpper(f.RawSeverity), f.RuleID, f.Location.Path, f.Location.Line)
		}
		fmt.Printf("Dashboard: %s%s\n", base, result.DashboardURL)
	}
	if result.Status != "complete" || result.GatePass == nil {
		return 2
	}
	if !*result.GatePass {
		return 1
	}
	return 0
}
