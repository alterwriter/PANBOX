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
	"sort"
	"strings"
	"time"

	"panbox/internal/core"
	"panbox/internal/scanner"
)

// Set by the release workflow. Development builds remain identifiable.
var releaseVersion = "dev"

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

type uploadResult struct {
	ID, Status      string
	GatePass        *bool  `json:"gate_pass"`
	New             int    `json:"new"`
	BaselineUnknown int    `json:"baseline_unknown"`
	DashboardURL    string `json:"dashboard_url"`
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

func safeLog(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 500 {
		return string(runes[:500]) + "…"
	}
	return value
}

func ciSourceURL(b bundle, f finding) string {
	path, commit := f.Location.Path, b.Git.CommitSHA
	if path == "" || strings.Contains(path, "\\") || strings.HasPrefix(path, "/") || len(commit) < 7 || len(commit) > 64 {
		return ""
	}
	for _, c := range commit {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return ""
		}
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ""
		}
		parts[i] = url.PathEscape(part)
	}
	base := strings.TrimSuffix(os.Getenv("CI_PROJECT_URL"), "/")
	if base == "" && os.Getenv("GITHUB_REPOSITORY") != "" {
		base = strings.TrimSuffix(os.Getenv("GITHUB_SERVER_URL"), "/") + "/" + os.Getenv("GITHUB_REPOSITORY")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	marker := "/blob/"
	if os.Getenv("GITLAB_CI") == "true" {
		marker = "/-/blob/"
	}
	link := base + marker + commit + "/" + strings.Join(parts, "/")
	if f.Location.Line > 0 {
		link += fmt.Sprintf("#L%d", f.Location.Line)
	}
	return link
}

func printScanSummary(w io.Writer, b bundle, result uploadResult, base string) {
	gate := "UNVERIFIED"
	if result.GatePass != nil {
		if *result.GatePass {
			gate = "PASS"
		} else {
			gate = "FAIL"
		}
	}
	fmt.Fprintf(w, "PANBOX %s | %s | %s\n", safeLog(releaseVersion), safeLog(b.Git.Branch), safeLog(b.Git.CommitSHA))
	fmt.Fprintf(w, "Gate: %s | Scan: %s | Findings: %d | New: %d | Baseline unknown: %d\n", gate, safeLog(result.Status), len(b.Findings), result.New, result.BaselineUnknown)
	for _, m := range b.Modules {
		fmt.Fprintf(w, "Module %-7s %s (%s)\n", safeLog(strings.ToUpper(m.Name)), safeLog(m.Status), safeLog(m.Version))
	}
	counts := map[string]int{}
	for _, f := range b.Findings {
		counts[strings.ToLower(f.RawSeverity)]++
	}
	fmt.Fprintf(w, "Severity: critical %d | high %d | medium %d | low %d | info %d\n", counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])
	if len(b.Findings) > 0 {
		if os.Getenv("GITLAB_CI") == "true" {
			fmt.Fprintf(w, "section_start:%d:panbox_findings[collapsed=true]\r\033[0KFinding locations (top 10)\n", time.Now().Unix())
		}
		items := append([]finding(nil), b.Findings...)
		severityRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
		sort.SliceStable(items, func(i, j int) bool { return severityRank[items[i].RawSeverity] < severityRank[items[j].RawSeverity] })
		for i, f := range items {
			if i == 10 {
				fmt.Fprintf(w, "  … %d more findings in dashboard\n", len(items)-10)
				break
			}
			fmt.Fprintf(w, "  %-8s %-42s %s:%d\n", safeLog(strings.ToUpper(f.RawSeverity)), safeLog(f.RuleID), safeLog(f.Location.Path), f.Location.Line)
			if link := ciSourceURL(b, f); link != "" {
				fmt.Fprintf(w, "    Source: %s\n", safeLog(link))
			}
		}
		if os.Getenv("GITLAB_CI") == "true" {
			fmt.Fprintf(w, "section_end:%d:panbox_findings\r\033[0K\n", time.Now().Unix())
		}
	}
	fmt.Fprintf(w, "Dashboard: %s\n", safeLog(base+result.DashboardURL))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Printf("PANBOX agent %s (VACCIN/ENETRON engine %s)\n", releaseVersion, scanner.Version)
		return 0
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
func usage() {
	fmt.Fprintln(os.Stderr, "panbox version|ready|go|relay-pull|mcp|shutdown  (see README.md)")
}
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
	var result uploadResult
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
		printScanSummary(os.Stdout, b, result, base)
	}
	if result.Status != "complete" || result.GatePass == nil {
		return 2
	}
	if !*result.GatePass {
		return 1
	}
	return 0
}
