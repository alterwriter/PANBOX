package scanner

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// These checks operate on comment-stripped text. They are deliberately scoped
// to Django settings, Python call sites, or Django templates; they do not prove
// exploitability or follow values between functions.
var djangoPythonRules = []rule{
	{"panbox.python.django-sql-interpolation", "high", "SQL passed to execute uses string interpolation; bind parameters instead", regexp.MustCompile(`(?s)\b(?:execute|executemany)\s*\(\s*["'].{0,800}?["']\s*%\s*\(`)},
	{"panbox.python.django-open-redirect", "medium", "Redirect destination comes from request input; validate a local or allowlisted target", regexp.MustCompile(`\bredirect\s*\(\s*request\.(?:GET|POST)\.get\s*\(`)},
}

var djangoSettingsRules = []rule{
	{"panbox.python.django-debug", "high", "Django DEBUG is enabled in settings", regexp.MustCompile(`(?m)^[ \t]*(?:DEBUG|TEMPLATE_DEBUG)[ \t]*=[ \t]*True\b`)},
	{"panbox.python.django-hardcoded-secret", "high", "Django SECRET_KEY is hard-coded; load it from a protected runtime secret", regexp.MustCompile(`(?m)^[ \t]*SECRET_KEY[ \t]*=[ \t]*["'][^"'\r\n]{8,}["']`)},
	{"panbox.python.django-hardcoded-credential", "high", "A provider credential is hard-coded in Django settings; rotate it and load from a protected runtime secret", regexp.MustCompile(`(?m)^[ \t]*(?:AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)|SLACK_API_TOKEN)[ \t]*=[ \t]*["'][^"'\r\n]{8,}["']`)},
	{"panbox.python.django-weak-password-hasher", "high", "Django password hashers include MD5; use a supported adaptive hasher", regexp.MustCompile(`(?s)\bPASSWORD_HASHERS\s*=\s*[\[(].{0,800}?MD5PasswordHasher`)},
	{"panbox.python.django-pickle-session", "high", "Pickle session serializer can deserialize unsafe data; use the JSON serializer", regexp.MustCompile(`(?m)^[ \t]*SESSION_SERIALIZER[ \t]*=[ \t]*["'][^"'\r\n]*PickleSerializer`)},
	{"panbox.python.django-frame-protection", "medium", "Django frame protection is disabled with ALLOWALL", regexp.MustCompile(`(?m)^[ \t]*X_FRAME_OPTIONS[ \t]*=[ \t]*["']ALLOWALL["']`)},
	{"panbox.python.django-insecure-session-cookie", "medium", "Django session cookie is allowed over HTTP", regexp.MustCompile(`(?m)^[ \t]*SESSION_COOKIE_SECURE[ \t]*=[ \t]*False\b`)},
	{"panbox.python.django-insecure-csrf-cookie", "medium", "Django CSRF cookie is allowed over HTTP", regexp.MustCompile(`(?m)^[ \t]*CSRF_COOKIE_SECURE[ \t]*=[ \t]*False\b`)},
}

var djangoTemplateRules = []rule{
	{"panbox.django.template-safe", "high", "The safe filter bypasses Django HTML escaping; remove it or sanitize trusted markup", regexp.MustCompile(`\{\{[^}\n]{1,300}\|\s*safe\b`)},
	{"panbox.django.autoescape-off", "high", "Django template autoescaping is disabled; keep it enabled for untrusted values", regexp.MustCompile(`\{%\s*autoescape\s+off\s*%\}`)},
}

func isDjangoTemplate(p string) bool {
	return strings.Contains("/"+strings.ToLower(p), "/templates/")
}

// Known distributable assets should not dominate application findings.
// Keep this narrow: application-owned JS in static/ is still scanned.
func isBundledJavaScript(p string) bool {
	lower := strings.ToLower(p)
	if !strings.Contains("/"+lower, "/static/") && !strings.Contains("/"+lower, "/assets/") {
		return false
	}
	if !strings.HasSuffix(lower, ".js") && !strings.HasSuffix(lower, ".mjs") && !strings.HasSuffix(lower, ".cjs") {
		return false
	}
	base := path.Base(lower)
	if strings.Contains(base, ".min.") {
		return true
	}
	for _, prefix := range []string{"jquery", "bootstrap", "highlight", "html5shiv", "respond", "xregexp", "superfish"} {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

func addRuleMatches(out []Finding, p, source string, starts []int, rules []rule) []Finding {
	for _, r := range rules {
		seen := map[int]bool{}
		for _, match := range r.re.FindAllStringIndex(source, -1) {
			line := sort.Search(len(starts), func(i int) bool { return starts[i] > match[0] })
			if line < 1 {
				line = 1
			}
			if !seen[line] {
				out = append(out, Finding{Module: "vaccin", RuleID: r.id, Severity: r.severity, Path: p, Line: line, Message: r.message, Identity: fmt.Sprintf("%s:%s:%d", r.id, p, line)})
				seen[line] = true
			}
		}
	}
	return out
}

func scanDjangoPython(p, source string, starts []int) []Finding {
	out := addRuleMatches(nil, p, source, starts, djangoPythonRules)
	if path.Base(strings.ToLower(p)) != "settings.py" {
		return out
	}
	out = addRuleMatches(out, p, source, starts, djangoSettingsRules)
	middleware := regexp.MustCompile(`(?s)\bMIDDLEWARE(?:_CLASSES)?\s*=\s*[\[(].{0,1000}?[\])]`).FindStringIndex(source)
	if middleware != nil && !strings.Contains(source[middleware[0]:middleware[1]], "django.middleware.csrf.CsrfViewMiddleware") {
		line := sort.Search(len(starts), func(i int) bool { return starts[i] > middleware[0] })
		if line < 1 {
			line = 1
		}
		out = append(out, Finding{Module: "vaccin", RuleID: "panbox.python.django-csrf-middleware-missing", Severity: "high", Path: p, Line: line, Message: "Django CSRF middleware is absent from the active middleware list", Identity: fmt.Sprintf("%s:%s:%d", "panbox.python.django-csrf-middleware-missing", p, line)})
	}
	return out
}

func scanDjangoTemplate(p string, raw []byte) []Finding {
	source := string(raw)
	starts := []int{0}
	for i, c := range raw {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return addRuleMatches(nil, p, source, starts, djangoTemplateRules)
}
