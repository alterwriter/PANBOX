package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type scmRoundTrip func(*http.Request) (*http.Response, error)

func (f scmRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSCMInspectionDetectsDefaultBranch(t *testing.T) {
	tests := []struct {
		provider, project, expectedURL, body, branch, owner string
	}{
		{"github", "alterwriter/PANBOX", "https://api.github.com/repos/alterwriter/PANBOX", `{"default_branch":"main","owner":{"login":"alterwriter"}}`, "main", "alterwriter"},
		{"gitlab", "boxsploit-labs/subgroup/site", "https://gitlab.com/api/v4/projects/boxsploit-labs%2Fsubgroup%2Fsite", `{"default_branch":"develop"}`, "develop", "boxsploit-labs/subgroup"},
		{"bitbucket", "team/site", "https://api.bitbucket.org/2.0/repositories/team/site", `{"mainbranch":{"name":"trunk"}}`, "trunk", "team"},
		{"azure", "org/project/site", "https://dev.azure.com/org/project/_apis/git/repositories/site?api-version=7.1", `{"defaultBranch":"refs/heads/release/main"}`, "release/main", "org"},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			client := &http.Client{Transport: scmRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != tt.expectedURL {
					t.Errorf("URL = %q", r.URL.String())
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			})}
			got, err := inspectSCMWithClient(context.Background(), tt.provider, tt.project, "", client)
			if err != nil || got.Status != "verified" || got.DefaultBranch != tt.branch || got.Owner != tt.owner {
				t.Fatalf("inspection = %+v, %v", got, err)
			}
		})
	}
}

func TestSCMInspectionRejectsUnapprovedTargets(t *testing.T) {
	for _, tt := range []struct{ provider, project string }{
		{"github", "owner/repo/extra"},
		{"github", "owner/../repo"},
		{"generic", "http://127.0.0.1/repo.git"},
		{"gitea", "https://private.example/owner/repo"},
	} {
		got, err := inspectSCM(context.Background(), tt.provider, tt.project, "")
		if err != nil || got.Status != "manual_required" {
			t.Fatalf("%s %s: %+v, %v", tt.provider, tt.project, got, err)
		}
	}
}

func TestSCMInspectionSelfManagedHost(t *testing.T) {
	t.Setenv("PANBOX_SCM_ALLOWED_HOSTS", "git.example.test")
	tests := []struct {
		provider, project, endpoint, body, contentType, status, branch string
	}{
		{"gitea", "https://git.example.test/team/service", "https://git.example.test/api/v1/repos/team/service", `{"default_branch":"stable"}`, "application/json", "verified", "stable"},
		{"generic", "https://git.example.test/team/service.git", "https://git.example.test/team/service.git/info/refs?service=git-upload-pack", "", "application/x-git-upload-pack-advertisement", "reachable_no_branch", ""},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			client := &http.Client{Transport: scmRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != tt.endpoint {
					t.Errorf("URL = %q", r.URL.String())
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{tt.contentType}}, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			})}
			got, err := inspectSCMWithClient(context.Background(), tt.provider, tt.project, "", client)
			if err != nil || got.Status != tt.status || got.DefaultBranch != tt.branch {
				t.Fatalf("inspection = %+v, %v", got, err)
			}
		})
	}
}

func TestSelfHostedProviderMetadataURL(t *testing.T) {
	t.Setenv("PANBOX_SCM_ALLOWED_HOSTS", "git.example.test,github.example.test")
	for _, tt := range []struct{ provider, base, project, want string }{
		{"github", "https://github.example.test", "team/app", "https://github.example.test/api/v3/repos/team/app"},
		{"gitlab", "https://git.example.test", "team/sub/app", "https://git.example.test/api/v4/projects/team%2Fsub%2Fapp"},
	} {
		got, _, err := inspectionURL(tt.provider, tt.project, tt.base)
		if err != nil || got != tt.want {
			t.Fatalf("%s URL = %q, %v", tt.provider, got, err)
		}
	}
	if _, _, err := inspectionURL("github", "team/app", "https://unapproved.example.test"); err == nil {
		t.Fatal("unapproved host accepted")
	}
	if _, _, err := inspectionURL("github", "team/app", "https://github.example.test@127.0.0.1"); err == nil {
		t.Fatal("userinfo host accepted")
	}
}
