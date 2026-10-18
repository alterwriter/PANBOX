package scanner

import (
	"context"
	"encoding/json"
	"errors"
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

func TestVaccinExpandedLanguageFamilies(t *testing.T) {
	root := t.TempDir()
	sources := map[string]string{
		"app.py":   "breakpoint()\n",
		"app.ts":   "element.innerHTML = input\n",
		"app.go":   "unsafe.Pointer(value)\n",
		"App.java": "new ProcessBuilder(\"sh\")\n",
		"app.php":  "eval($input);\n",
	}
	for name, source := range sources {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Vaccin(root)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"panbox.python.debugger":           true,
		"panbox.javascript.html-injection": true,
		"panbox.go.unsafe-pointer":         true,
		"panbox.java.process-builder":      true,
		"panbox.php.dynamic-eval":          true,
	}
	for _, finding := range got {
		delete(wanted, finding.RuleID)
	}
	if len(wanted) != 0 {
		t.Fatalf("missing native rules: %v; got %+v", wanted, got)
	}
}

func TestVaccinRepositoryCustomRules(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".panbox"), 0700); err != nil {
		t.Fatal(err)
	}
	config := `{"rules":[{"id":"custom.team.unsafe-call","severity":"medium","message":"Unsafe call needs review","pattern":"unsafeCall\\(","extensions":[".js"]}]}`
	if err := os.WriteFile(filepath.Join(root, ".panbox", "rules.json"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("// unsafeCall(x)\nunsafeCall(input)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Vaccin(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RuleID != "custom.team.unsafe-call" || got[0].Line != 2 {
		t.Fatalf("custom rules mismatch: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(root, ".panbox", "rules.json"), []byte(`{"rules":[{"id":"custom.bad","severity":"high","message":"bad","pattern":"(","extensions":[".js"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Vaccin(root); err == nil {
		t.Fatal("invalid rule must fail scan rather than silently pass")
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

func TestEnetronFollowsPerQueryOSVPagination(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("demo-a==1.0.0\ndemo-b==2.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/querybatch":
			var body struct {
				Queries []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
					PageToken string `json:"page_token"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			page++
			if page == 1 {
				if len(body.Queries) != 2 {
					t.Errorf("first page should query both packages: %+v", body.Queries)
				}
				_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"OSV-A-1"}],"next_page_token":"next-a"},{"vulns":[]}]}`))
				return
			}
			if len(body.Queries) != 1 || body.Queries[0].Package.Name != "demo-a" || body.Queries[0].PageToken != "next-a" {
				t.Errorf("next page must contain only the pending query and its token: %+v", body.Queries)
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"OSV-A-2"}]}]}`))
		case "/v1/vulns/OSV-A-1", "/v1/vulns/OSV-A-2":
			_, _ = w.Write([]byte(`{"database_specific":{"severity":"HIGH"}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	got, err := Enetron(context.Background(), root, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if page != 2 || len(got) != 2 {
		t.Fatalf("wanted two paginated findings after two requests, got pages=%d findings=%+v", page, got)
	}
}

func TestEnetronNoManifestIsUnverified(t *testing.T) {
	_, err := Enetron(context.Background(), t.TempDir(), "")
	if !errors.Is(err, ErrNoDependencyManifest) {
		t.Fatalf("missing manifest should be reported as not applicable, got %v", err)
	}
}

func TestEnetronExpandedManifestFormats(t *testing.T) {
	root := t.TempDir()
	manifests := map[string]string{
		"package-lock.json":    `{"lockfileVersion":3,"packages":{"":{"name":"fixture"},"node_modules/left-pad":{"version":"1.3.0"}}}`,
		"pnpm-lock.yaml":       "lockfileVersion: '9.0'\npackages:\n  foo@1.2.3:\n    resolution: {integrity: fixture}\n",
		"yarn.lock":            "foo@^1.0.0:\n  version \"1.2.3\"\n",
		"bun.lock":             `{"lockfileVersion":1,"packages":{"foo":["foo@1.2.3"]}}`,
		"requirements-dev.txt": "demo-py==1.0.0\n",
		"poetry.lock":          "[[package]]\nname = \"demo-poetry\"\nversion = \"2.0.0\"\n",
		"go.sum":               "example.com/demo v1.2.3 h1:fixture\n",
		"pom.xml":              `<project><dependencies><dependency><groupId>org.demo</groupId><artifactId>sample</artifactId><version>1.2.3</version></dependency></dependencies></project>`,
		"gradle.lockfile":      "org.demo:locked:1.2.3=runtimeClasspath\n",
		"composer.lock":        `{"packages":[{"name":"demo/package","version":"1.2.3"}]}`,
	}
	for name, content := range manifests {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := dependencies(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(manifests) {
		t.Fatalf("wanted one pinned dependency per fixture manifest, got %d: %+v", len(got), got)
	}
}
