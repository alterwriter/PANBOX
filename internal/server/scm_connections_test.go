package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSCMSecretEncryptedAndRequiresSameKey(t *testing.T) {
	t.Setenv("PANBOX_SCM_ENCRYPTION_KEY", strings.Repeat("a", 64))
	sealed, err := sealSCM(scmSecret{Token: "secret-private-token"})
	if err != nil || strings.Contains(string(sealed), "secret-private-token") {
		t.Fatalf("SCM secret not sealed: %v", err)
	}
	opened, err := openSCM(sealed)
	if err != nil || opened.Token != "secret-private-token" {
		t.Fatalf("SCM secret not recovered: %v", err)
	}
	t.Setenv("PANBOX_SCM_ENCRYPTION_KEY", strings.Repeat("b", 64))
	if _, err := openSCM(sealed); err == nil {
		t.Fatal("wrong encryption key accepted")
	}
}

func TestGitHubAppJWTAndPrivateRepositoryDiscovery(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secret := scmSecret{AppID: 42, InstallationID: 7, PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))}
	jwt, err := githubAppJWT(secret)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT segments")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("invalid app JWT signature: %v", err)
	}
	var payload map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(raw, &payload); err != nil || payload["iss"] != "42" {
		t.Fatalf("invalid app JWT payload: %v", err)
	}
	prior := scmTransport
	scmTransport = scmRoundTrip(func(r *http.Request) (*http.Response, error) {
		var status int
		var body string
		switch r.URL.String() {
		case "https://api.github.com/app/installations/7/access_tokens":
			if r.Method != "POST" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer eyJ") {
				t.Fatal("missing GitHub App JWT")
			}
			status = 201
			body = `{"token":"installation-secret"}`
		case "https://api.github.com/installation/repositories?per_page=100&page=1":
			if r.Header.Get("Authorization") != "Bearer installation-secret" {
				t.Fatal("missing installation token")
			}
			status = 200
			body = `{"repositories":[{"full_name":"org/private","name":"private","default_branch":"develop","owner":{"login":"org"}}]}`
		default:
			t.Fatalf("unexpected GitHub request %s", r.URL.String())
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	t.Cleanup(func() { scmTransport = prior })
	repos, truncated, err := listSCMRepositories(context.Background(), scmConnection{Provider: "github"}, secret)
	if err != nil || truncated || len(repos) != 1 || repos[0].Path != "org/private" || repos[0].DefaultBranch != "develop" {
		t.Fatalf("GitHub discovery: %+v, %v", repos, err)
	}
}

func TestGitLabServiceAccountDiscoversPrivateRepository(t *testing.T) {
	prior := scmTransport
	scmTransport = scmRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://gitlab.com/api/v4/projects?membership=true&per_page=100&page=1" || r.Header.Get("PRIVATE-TOKEN") != "service-secret" {
			t.Fatalf("unexpected GitLab request: %s", r.URL.String())
		}
		body := `[{"path_with_namespace":"group/private","name":"private","default_branch":"stable","namespace":{"full_path":"group"}}]`
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	t.Cleanup(func() { scmTransport = prior })
	repos, truncated, err := listSCMRepositories(context.Background(), scmConnection{Provider: "gitlab"}, scmSecret{Token: "service-secret"})
	if err != nil || truncated || len(repos) != 1 || repos[0].Owner != "group" || repos[0].DefaultBranch != "stable" {
		t.Fatalf("GitLab discovery: %+v, %v", repos, err)
	}
}

func TestPrivateGitLabMetadataUsesServiceAccount(t *testing.T) {
	client := &http.Client{Transport: scmAuthTransport{provider: "gitlab", token: "service-secret", base: scmRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://gitlab.com/api/v4/projects/group%2Fprivate" || r.Header.Get("PRIVATE-TOKEN") != "service-secret" {
			t.Fatalf("private metadata request not authenticated: %s", r.URL.String())
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"default_branch":"stable"}`))}, nil
	})}}
	result, err := inspectSCMWithClient(context.Background(), "gitlab", "group/private", "", client)
	if err != nil || result.Status != "verified" || result.DefaultBranch != "stable" {
		t.Fatalf("private metadata: %+v, %v", result, err)
	}
}
