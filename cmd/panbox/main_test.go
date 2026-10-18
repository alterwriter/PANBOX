package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCISummaryShowsGateLocationAndSourceLink(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_URL", "https://gitlab.example.com/group/project")
	b := bundle{}
	b.Git.Branch, b.Git.CommitSHA = "feature/demo", "deadbeef"
	b.Modules = []module{{Name: "vaccin", Version: "0.1.5", Status: "complete"}}
	f := finding{Module: "vaccin", RuleID: "panbox.python.sql-fstring", RawSeverity: "high"}
	f.Location.Path, f.Location.Line = "src/app.py", 42
	b.Findings = []finding{f}
	pass := false
	var out bytes.Buffer
	printScanSummary(&out, b, uploadResult{ID: "scan-1", Status: "complete", GatePass: &pass, DashboardURL: "/scans/scan-1"}, "https://panbox.example.com")
	for _, want := range []string{"Gate: FAIL", "src/app.py:42", "https://gitlab.example.com/group/project/-/blob/deadbeef/src/app.py#L42", "https://panbox.example.com/scans/scan-1", "section_start:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in CI summary: %s", want, out.String())
		}
	}
}

func TestGateExitCodes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(file, []byte(`{"schema_version":"1.0","client_scan_id":"test","scope":"repo","repository_id":"repo","git":{"branch":"main","commit_sha":"a"},"modules":[{"name":"vaccin","status":"complete"}],"findings":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANBOX_TOKEN", "test-token")
	for _, tc := range []struct {
		name, body   string
		status, want int
	}{
		{"pass", `{"id":"1","status":"complete","gate_pass":true}`, 201, 0},
		{"fail", `{"id":"1","status":"complete","gate_pass":false}`, 201, 1},
		{"partial", `{"id":"1","status":"partial","gate_pass":null}`, 201, 2},
		{"denied", `{"error":"denied"}`, 403, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			got := goScan([]string{"--server", srv.URL, "--bundle", file})
			if got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestGoScanSkipsEnetronWhenNoManifestExists(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(t.TempDir(), "bundle.json")
	code := goScan([]string{
		"--offline",
		"--repo", "repo-123",
		"--path", root,
		"--branch", "feature/demo",
		"--default-branch", "main",
		"--commit", "deadbeef",
		"--modules", "vaccin,enetron",
		"--output", output,
	})
	if code != 2 { // Offline scans are intentionally unverified until uploaded.
		t.Fatalf("got exit %d; offline scan must remain unverified", code)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result bundle
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Modules) != 2 {
		t.Fatalf("got %d modules, want vaccin and enetron: %+v", len(result.Modules), result.Modules)
	}
	if result.Modules[0].Name != "vaccin" || result.Modules[0].Status != "complete" {
		t.Fatalf("VACCIN result = %+v, want complete", result.Modules[0])
	}
	if result.Modules[1].Name != "enetron" || result.Modules[1].Status != "skipped" || result.Modules[1].Message == "" {
		t.Fatalf("ENETRON result = %+v, want skipped with explanation", result.Modules[1])
	}
}

func TestCIIdentityFromEnvironment(t *testing.T) {
	t.Setenv("PANBOX_API_KEY", "api-key")
	t.Setenv("PANBOX_TOKEN", "old-key")
	t.Setenv("CI_DEFAULT_BRANCH", "release")
	if got := ciAPIKey(); got != "api-key" {
		t.Fatalf("API key precedence: %q", got)
	}
	if got := ciDefaultBranch(t.TempDir()); got != "release" {
		t.Fatalf("CI default branch: %q", got)
	}
}
