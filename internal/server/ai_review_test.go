package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type aiRoundTrip func(*http.Request) (*http.Response, error)

func (f aiRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAISourceFetchAtExactCommit(t *testing.T) {
	old := scmTransport
	defer func() { scmTransport = old }()
	commit := strings.Repeat("a", 40)
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			scmTransport = aiRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("ref") != commit {
					t.Errorf("wrong ref: %s", r.URL.String())
				}
				if provider == "gitlab" && !strings.Contains(r.URL.EscapedPath(), "owner%2Fproject") {
					t.Errorf("project path was not encoded: %s", r.URL.EscapedPath())
				}
				if provider == "gitlab" && r.Header.Get("PRIVATE-TOKEN") != "example" {
					t.Error("missing GitLab auth")
				}
				if provider == "github" && r.Header.Get("Authorization") != "Bearer example" {
					t.Error("missing GitHub auth")
				}
				if !strings.Contains(r.URL.EscapedPath(), "foo") {
					t.Error("missing file path")
				}
				body := "line one\nunsafe call\nline three"
				if provider == "github" {
					body = fmt.Sprintf(`{"type":"file","encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString([]byte(body)))
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})
			content, err := fetchAISource(context.Background(), scmConnection{Provider: provider}, "example", "owner/project", commit, "src/foo.py", 2)
			if err != nil || !strings.Contains(content, "2: unsafe call") {
				t.Fatalf("content=%q err=%v", content, err)
			}
		})
	}
}

func TestAIRejectsUnsafePath(t *testing.T) {
	for _, path := range []string{"../secret", "/etc/passwd", "a\\b", "src//x", "a?b", "a\nb"} {
		if validAIPath(path) {
			t.Errorf("accepted %q", path)
		}
	}
}

func TestAISourceRedactsLikelyCredential(t *testing.T) {
	got := redactAISource("2: token=glpat-abcdefghijklmnop")
	if strings.Contains(got, "glpat-") {
		t.Fatalf("credential leaked: %s", got)
	}
}

func TestAIProviderTextExtraction(t *testing.T) {
	openai := []byte(`{"output":[{"content":[{"type":"output_text","text":"{\"verdict\":\"needs_review\"}"}]}]}`)
	claude := []byte(`{"content":[{"type":"text","text":"{\"verdict\":\"needs_review\"}"}]}`)
	for provider, raw := range map[string][]byte{"openai": openai, "anthropic": claude} {
		text, err := extractAIText(provider, raw)
		if err != nil || !strings.Contains(text, "needs_review") {
			t.Fatalf("%s: %q %v", provider, text, err)
		}
	}
}

func TestAIProviderRequestsAreStructuredAndRedacted(t *testing.T) {
	old := aiProviderTransport
	defer func() { aiProviderTransport = old }()
	t.Setenv("PANBOX_OPENAI_API_KEY", "test-openai")
	t.Setenv("PANBOX_ANTHROPIC_API_KEY", "test-anthropic")
	for _, provider := range []string{"openai", "anthropic"} {
		t.Run(provider, func(t *testing.T) {
			aiProviderTransport = aiRoundTrip(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "glpat-abcdefghijklmnop") {
					t.Error("secret sent to provider")
				}
				if !strings.Contains(string(body), "json_schema") {
					t.Error("missing structured-output schema")
				}
				if provider == "openai" && !strings.Contains(string(body), `"store":false`) {
					t.Error("OpenAI request persisted by default")
				}
				if r.URL.Scheme != "https" {
					t.Error("provider request is not HTTPS")
				}
				payload := `{"output":[{"content":[{"type":"output_text","text":"{\"verdict\":\"needs_review\",\"confidence\":\"low\",\"explanation\":\"check source\",\"remediation\":\"replace unsafe call\",\"evidence\":\"line 2\"}"}]}]}`
				if provider == "anthropic" {
					payload = `{"content":[{"type":"text","text":"{\"verdict\":\"needs_review\",\"confidence\":\"low\",\"explanation\":\"check source\",\"remediation\":\"replace unsafe call\",\"evidence\":\"line 2\"}"}]}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
			})
			a, err := callAIProvider(context.Background(), provider, "example-model", aiCandidate{RuleID: "r", Message: "m", Path: "a.py", Line: 2}, "token=glpat-abcdefghijklmnop")
			if err != nil || a.Verdict != "needs_review" {
				t.Fatalf("assessment=%+v error=%v", a, err)
			}
		})
	}
}
