package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVaccinNativeRules(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("# app.run(debug=True)\napp.run(debug=True)\nsubprocess.run(command, shell=True)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("// eval(untrusted)\neval(untrusted)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Vaccin(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("wanted three native findings, got %+v", got)
	}
	for _, f := range got {
		if f.Module != "vaccin" || f.RuleID == "" || f.Path == "" || f.Line == 0 {
			t.Fatalf("bad finding %+v", f)
		}
	}
}

func TestEnetronQueriesPinnedDependencies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("demo-pkg==1.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"OSV-TEST-1"}]}]}`))
		case "/v1/vulns/OSV-TEST-1":
			_, _ = w.Write([]byte(`{"database_specific":{"severity":"HIGH"}}`))
		default:
			t.Errorf("path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	got, err := Enetron(context.Background(), root, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RuleID != "OSV-TEST-1" || got[0].Severity != "high" {
		t.Fatalf("bad advisory result %+v", got)
	}
}

func TestEnetronNoManifestIsUnverified(t *testing.T) {
	_, err := Enetron(context.Background(), t.TempDir(), "")
	if err == nil {
		t.Fatal("missing manifest must not silently pass")
	}
}
