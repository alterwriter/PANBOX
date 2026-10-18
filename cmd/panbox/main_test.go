package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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
