package server

import (
	"strings"
	"testing"
)

func TestFindingGuidanceUsesPublicRuleRelevantReferences(t *testing.T) {
	for _, tc := range []struct{ rule, path string }{
		{"panbox.python.django-csrf-disabled", "Cross-Site_Request_Forgery_Prevention"},
		{"panbox.python.sql-fstring", "SQL_Injection_Prevention"},
		{"panbox.javascript.axios-request-url", "Server_Side_Request_Forgery_Prevention"},
		{"panbox.javascript.jwt-none-algorithm", "JSON_Web_Token_Cheat_Sheet"},
		{"panbox.django.template-safe", "Cross_Site_Scripting_Prevention"},
	} {
		ref, advice := findingGuidance("vaccin", tc.rule)
		if !strings.HasPrefix(ref, "https://") || !strings.Contains(ref, tc.path) || advice == "" {
			t.Errorf("rule %s: ref=%q advice=%q", tc.rule, ref, advice)
		}
	}
	ref, _ := findingGuidance("enetron", "GHSA-1234-5678-90ab")
	if !strings.Contains(ref, "osv.dev/vulnerability/") {
		t.Fatalf("ENETRON advisory reference changed: %q", ref)
	}
}
