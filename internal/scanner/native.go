package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Version identifies the built-in detection rules and lockfile parser.
const Version = "0.1.2"

type Finding struct {
	Module, RuleID, Severity, Path, Message, Identity string
	Line                                              int
}

var excluded = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "dist": true, "build": true}

func files(root string, accept func(string) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && excluded[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && accept(d.Name()) {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func relative(root, path string) string {
	p, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(filepath.Base(path))
	}
	return filepath.ToSlash(p)
}

type rule struct {
	id, severity, message string
	re                    *regexp.Regexp
}

// Custom VACCIN rules are versioned with the repository and run on the CI checkout.
type customRule struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	Message    string   `json:"message"`
	Pattern    string   `json:"pattern"`
	Extensions []string `json:"extensions"`
}

func loadCustomRules(root string) (map[string][]rule, error) {
	path := filepath.Join(root, ".panbox", "rules.json")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]rule{}, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() > 64<<10 {
		return nil, errors.New("custom rule file exceeds 64 KiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config struct {
		Rules []customRule `json:"rules"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid custom rules: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, errors.New("unexpected content after custom rules")
	}
	if len(config.Rules) > 64 {
		return nil, errors.New("maximum 64 custom rules")
	}
	allowed := map[string]bool{".py": true, ".pyw": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true, ".go": true, ".java": true, ".jsp": true, ".php": true, ".phtml": true}
	out := map[string][]rule{}
	seen := map[string]bool{}
	for _, spec := range config.Rules {
		if !regexp.MustCompile(`^custom\.[a-z0-9][a-z0-9._-]{0,63}$`).MatchString(spec.ID) || seen[spec.ID] || !validSeverity(spec.Severity) || len(spec.Message) == 0 || len(spec.Message) > 200 || len(spec.Pattern) == 0 || len(spec.Pattern) > 256 || len(spec.Extensions) == 0 || len(spec.Extensions) > 16 {
			return nil, fmt.Errorf("invalid custom rule: %s", spec.ID)
		}
		seen[spec.ID] = true
		compiled, err := regexp.Compile(spec.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", spec.ID, err)
		}
		for _, ext := range spec.Extensions {
			if !allowed[ext] {
				return nil, fmt.Errorf("rule %s: unsupported extension %s", spec.ID, ext)
			}
			out[ext] = append(out[ext], rule{spec.ID, spec.Severity, spec.Message, compiled})
		}
	}
	return out, nil
}

func validSeverity(v string) bool {
	return v == "critical" || v == "high" || v == "medium" || v == "low" || v == "info"
}

var codeRules = map[string][]rule{
	".py": {
		{"panbox.python.flask-debug", "high", "Flask debug mode is enabled", regexp.MustCompile(`\b(?:app|application)\.run\s*\([^\n]*\bdebug\s*=\s*True\b`)},
		{"panbox.python.shell-true", "high", "Subprocess shell execution needs input review", regexp.MustCompile(`\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^\n]*\bshell\s*=\s*True\b`)},
		{"panbox.python.os-system", "high", "os.system executes a shell command", regexp.MustCompile(`\bos\.(?:system|popen)\s*\(`)},
		{"panbox.python.dynamic-eval", "high", "eval or exec evaluates runtime-supplied code", regexp.MustCompile(`\b(?:eval|exec)\s*\(`)},
		{"panbox.python.pickle", "high", "Pickle loading can execute code from untrusted input", regexp.MustCompile(`\bpickle\.(?:load|loads)\s*\(`)},
		{"panbox.python.yaml-unsafe-load", "high", "yaml.load can construct unsafe objects without a safe loader", regexp.MustCompile(`\byaml\.load\s*\(`)},
		{"panbox.python.sql-fstring", "high", "Formatted SQL passed to execute may be injectable", regexp.MustCompile(`\b(?:execute|executemany)\s*\(\s*f[\"']`)},
		{"panbox.python.sql-format", "high", "Formatted SQL passed to execute may be injectable", regexp.MustCompile(`\b(?:execute|executemany)\s*\(\s*[\"'][^\"']*(?:%s|\{)[^\"']*[\"']\s*%`)},
		{"panbox.python.template-string", "high", "Dynamic template rendering can enable server-side template injection", regexp.MustCompile(`\brender_template_string\s*\(`)},
		{"panbox.python.mark-safe", "medium", "mark_safe bypasses template output escaping", regexp.MustCompile(`\bmark_safe\s*\(`)},
		{"panbox.python.tls-verify-disabled", "high", "TLS certificate verification is disabled", regexp.MustCompile(`\bverify\s*=\s*False\b`)},
		{"panbox.python.tempfile-mktemp", "medium", "tempfile.mktemp has a race condition; use a secure temporary file API", regexp.MustCompile(`\btempfile\.mktemp\s*\(`)},
		{"panbox.python.weak-hash", "low", "MD5 or SHA-1 is unsuitable for security-sensitive hashing", regexp.MustCompile(`\bhashlib\.(?:md5|sha1)\s*\(`)},
		{"panbox.python.insecure-random", "low", "The random module is not cryptographically secure", regexp.MustCompile(`\brandom\.(?:random|randint|choice|randrange)\s*\(`)},
	},
	".pyw": {},
	".js":  javascriptRules(), ".jsx": javascriptRules(), ".ts": javascriptRules(), ".tsx": javascriptRules(),
	".mjs": javascriptRules(), ".cjs": javascriptRules(), ".mts": javascriptRules(), ".cts": javascriptRules(),
	".go": {
		{"panbox.go.shell-command", "high", "Shell command execution needs input review", regexp.MustCompile(`\bexec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"\s*,`)},
		{"panbox.go.sql-concatenation", "high", "SQL assembled with concatenation may be injectable", regexp.MustCompile(`\b(?:Query|QueryRow|Exec|Prepare)\s*\([^\n]*\+`)},
		{"panbox.go.ssrf-request-input", "high", "HTTP request uses a request-controlled URL", regexp.MustCompile(`\bhttp\.(?:Get|Post|NewRequest)\s*\([^\n]*(?:r\.URL|r\.Form|r\.PostForm)`)},
		{"panbox.go.tls-verify-disabled", "high", "TLS certificate verification is disabled", regexp.MustCompile(`\bInsecureSkipVerify\s*:\s*true\b`)},
		{"panbox.go.html-trust", "high", "template.HTML bypasses HTML contextual escaping", regexp.MustCompile(`\btemplate\.HTML\s*\(`)},
		{"panbox.go.gob-untrusted", "medium", "Gob decoding requires strict validation when input is untrusted", regexp.MustCompile(`\bgob\.NewDecoder\s*\(`)},
		{"panbox.go.path-join-input", "medium", "Path joins using request input need traversal validation", regexp.MustCompile(`\bfilepath\.Join\s*\([^\n]*(?:r\.URL|r\.Form|r\.PostForm)`)},
		{"panbox.go.weak-hash", "low", "MD5 or SHA-1 is unsuitable for security-sensitive hashing", regexp.MustCompile(`\b(?:md5|sha1)\.New\s*\(`)},
		{"panbox.go.insecure-random", "low", "math/rand is not cryptographically secure", regexp.MustCompile(`\brand\.(?:Int|Intn|Int63|Read|Float64)\s*\(`)},
		{"panbox.go.debug-pprof", "medium", "Exposing pprof handlers can disclose runtime details; restrict access", regexp.MustCompile(`\b(?:http\.Handle|HandleFunc)\s*\([^\n]*\bpprof\.`)},
	},
	".java": javaRules(), ".jsp": javaRules(),
	".php": phpRules(), ".phtml": phpRules(),
}

func javascriptRules() []rule {
	return []rule{
		{"panbox.javascript.eval", "high", "Dynamic eval executes a string", regexp.MustCompile(`\beval\s*\(`)},
		{"panbox.javascript.function-constructor", "high", "Function constructor evaluates runtime-supplied code", regexp.MustCompile(`\bnew\s+Function\s*\(`)},
		{"panbox.javascript.child-process-exec", "high", "Shell command execution needs input review", regexp.MustCompile(`\b(?:child_process\.)?(?:exec|execSync)\s*\(`)},
		{"panbox.javascript.html-injection", "high", "Direct HTML insertion bypasses normal output encoding", regexp.MustCompile(`\.(?:innerHTML|outerHTML)\s*=`)},
		{"panbox.javascript.insert-adjacent-html", "high", "insertAdjacentHTML inserts untrusted markup without encoding", regexp.MustCompile(`\.insertAdjacentHTML\s*\(`)},
		{"panbox.javascript.react-raw-html", "high", "dangerouslySetInnerHTML bypasses React output escaping", regexp.MustCompile(`dangerouslySetInnerHTML\s*=`)},
		{"panbox.javascript.document-write", "high", "document.write inserts markup directly into the page", regexp.MustCompile(`\bdocument\.write(?:ln)?\s*\(`)},
		{"panbox.javascript.ssrf-request-input", "high", "Fetch URL is built directly from request input; validate destination", regexp.MustCompile(`\bfetch\s*\(\s*(?:req|request)\.(?:query|params|body)`)},
		{"panbox.javascript.open-redirect", "medium", "Redirect destination comes directly from request input", regexp.MustCompile(`\b(?:res|response)\.redirect\s*\(\s*(?:req|request)\.(?:query|params|body)`)},
		{"panbox.javascript.jwt-decode", "high", "jwt.decode does not verify a token signature", regexp.MustCompile(`\bjwt\.decode\s*\(`)},
		{"panbox.javascript.tls-verify-disabled", "high", "TLS certificate verification is disabled", regexp.MustCompile(`\brejectUnauthorized\s*:\s*false\b`)},
		{"panbox.javascript.insecure-random", "low", "Math.random is not cryptographically secure", regexp.MustCompile(`\bMath\.random\s*\(`)},
		{"panbox.javascript.dynamic-timeout", "medium", "String arguments to timers are evaluated as code", regexp.MustCompile(`\b(?:setTimeout|setInterval)\s*\(\s*[\"']`)},
		{"panbox.javascript.wildcard-cors", "medium", "Wildcard CORS origin needs review for credentialed routes", regexp.MustCompile(`\borigin\s*:\s*[\"']\*[\"']`)},
	}
}

// Additions are first-party PANBOX checks grouped by language. They deliberately
// report risky constructs for review; the source scanner is lexical and does
// not claim interprocedural or taint-flow proof.
func init() {
	additional := map[string][]rule{
		".py": {
			{"panbox.python.django-csrf-disabled", "high", "CSRF protection is disabled or exempted", regexp.MustCompile(`\b(?:csrf_exempt|CsrfViewMiddleware)\b|\bCSRF_COOKIE_HTTPONLY\s*=\s*False\b`)},
			{"panbox.python.django-host-wildcard", "high", "Wildcard ALLOWED_HOSTS permits untrusted Host headers", regexp.MustCompile(`\bALLOWED_HOSTS\s*=\s*\[[^\]]*["']\*["']`)},
			{"panbox.python.path-traversal", "high", "File path uses request data; constrain the resolved path", regexp.MustCompile(`\b(?:open|Path)\s*\([^\n]*(?:request\.(?:args|form|json|GET|POST))`)},
			{"panbox.python.archive-slip", "high", "Archive extraction should validate member paths before writing", regexp.MustCompile(`\b(?:ZipFile|TarFile)\s*\([^\n]*\)\.(?:extractall|extract)\s*\(`)},
			{"panbox.python.subprocess-user-input", "high", "Subprocess arguments include request input; validate arguments", regexp.MustCompile(`\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^\n]*(?:request\.(?:args|form|json)|sys\.argv)`)},
			{"panbox.python.ssl-unverified-context", "high", "Unverified TLS context accepts invalid certificates", regexp.MustCompile(`\b(?:_create_unverified_context|CERT_NONE)\b`)},
			{"panbox.python.temp-permissions", "medium", "Temporary file APIs with predictable names or broad permissions need review", regexp.MustCompile(`\b(?:tempfile\.mktemp|os\.tmpnam)\s*\(`)},
			{"panbox.python.weak-password-hash", "high", "Fast general-purpose hashing is unsuitable for password storage", regexp.MustCompile(`\bhashlib\.(?:md5|sha1|sha256)\s*\([^\n]*(?:password|passwd|secret)`)},
			{"panbox.python.dev-server-exposed", "medium", "Development server binds to all network interfaces", regexp.MustCompile(`\b(?:app|application)\.run\s*\([^\n]*\bhost\s*=\s*["']0\.0\.0\.0["']`)},
			{"panbox.python.debugger", "medium", "Interactive debugger should not be shipped in application code", regexp.MustCompile(`\b(?:pdb\.set_trace|breakpoint)\s*\(`)},
			{"panbox.python.xml-parser", "high", "XML parsing requires explicit external entity protections", regexp.MustCompile(`\b(?:etree\.parse|XMLParser|xml\.sax\.parse|parseString)\s*\(`)},
			{"panbox.python.insecure-cookie", "medium", "Session cookie security flags are disabled", regexp.MustCompile(`\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False\b`)},
		},
		".go": {
			{"panbox.go.path-traversal", "high", "Filesystem operation uses request data; constrain the resolved path", regexp.MustCompile(`\b(?:os\.(?:Open|ReadFile|WriteFile)|http\.ServeFile)\s*\([^\n]*(?:r\.URL|r\.Form|r\.PostForm)`)},
			{"panbox.go.sql-format", "high", "SQL uses formatted input; use parameter placeholders", regexp.MustCompile(`\b(?:Query|QueryRow|Exec|Prepare)\s*\(\s*fmt\.Sprintf\s*\(`)},
			{"panbox.go.tls-legacy-version", "medium", "TLS minimum version is obsolete", regexp.MustCompile(`\bMinVersion\s*:\s*tls\.VersionTLS(?:10|11)\b`)},
			{"panbox.go.jwt-unverified", "high", "JWT parsing skips signature verification", regexp.MustCompile(`\bParseUnverified\s*\(`)},
			{"panbox.go.cookie-insecure", "medium", "Cookie disables Secure or HttpOnly protection", regexp.MustCompile(`http\.Cookie\s*\{[^}]*\b(?:Secure|HttpOnly)\s*:\s*false`)},
			{"panbox.go.insecure-http-server", "high", "Default HTTP server has no explicit timeout configuration", regexp.MustCompile(`\bhttp\.ListenAndServe\s*\([^\n]*\)`)},
			{"panbox.go.unsafe-pointer", "medium", "unsafe.Pointer bypasses memory and type safety", regexp.MustCompile(`\bunsafe\.Pointer\s*\(`)},
			{"panbox.go.weak-key-size", "medium", "RSA keys below 2048 bits are weak", regexp.MustCompile(`\bGenerateKey\s*\([^,]+,\s*(?:512|1024)\s*\)`)},
			{"panbox.go.http-redirect-input", "medium", "Redirect target derived from request data needs validation", regexp.MustCompile(`\bhttp\.Redirect\s*\([^\n]*(?:r\.URL|r\.Form|r\.PostForm)`)},
			{"panbox.go.file-permissions", "medium", "World-readable or writable file permissions need review", regexp.MustCompile(`\b(?:os\.OpenFile|os\.WriteFile)\s*\([^\n]*0?666`)},
			{"panbox.go.hardcoded-secret", "high", "Hard-coded credential-like assignment detected", regexp.MustCompile(`(?i)\b(?:password|secret|api[_-]?key|access[_-]?token)\s*:?=\s*["'][^"']{8,}["']`)},
			{"panbox.go.weak-crypto-curve", "medium", "Legacy elliptic curve is configured", regexp.MustCompile(`\belliptic\.(?:P224|P192)\s*\(`)},
		},
		".js": {
			{"panbox.javascript.sql-interpolation", "high", "SQL query uses string interpolation or concatenation", regexp.MustCompile(`\b(?:query|execute|raw)\s*\(\s*(?:["'][^"']*["']\s*\+|\x60[^\x60]*\$\{)`)},
			{"panbox.javascript.path-traversal", "high", "Filesystem path uses request input; constrain the resolved path", regexp.MustCompile(`\b(?:readFile|writeFile|createReadStream|sendFile)\s*\([^\n]*(?:req|request)\.(?:query|params|body)`)},
			{"panbox.javascript.express-trust-proxy", "medium", "Unrestricted proxy trust can enable spoofed client metadata", regexp.MustCompile(`\bapp\.set\s*\(\s*["']trust proxy["']\s*,\s*true`)},
			{"panbox.javascript.cookie-insecure", "medium", "Cookie security flag is explicitly disabled", regexp.MustCompile(`\b(?:secure|httpOnly|sameSite)\s*:\s*false`)},
			{"panbox.javascript.prototype-pollution", "high", "Prototype mutation or dynamic key assignment needs validation", regexp.MustCompile(`\b__proto__\b|\bconstructor\s*\[\s*["']prototype["']`)},
			{"panbox.javascript.postmessage-wildcard", "high", "postMessage wildcard target origin exposes data to every origin", regexp.MustCompile(`\bpostMessage\s*\([^\n]*,[^\n]*["']\*["']`)},
			{"panbox.javascript.weak-password-hash", "high", "Fast general-purpose hashing is unsuitable for password storage", regexp.MustCompile(`\b(?:md5|sha1|sha256)\s*\([^\n]*(?:password|passwd|secret)`)},
			{"panbox.javascript.node-shell-option", "high", "Child process shell option enables shell interpretation", regexp.MustCompile(`\b(?:execFile|spawn|spawnSync)\s*\([^\n]*\bshell\s*:\s*true`)},
			{"panbox.javascript.weak-tls-protocol", "high", "Legacy SSL/TLS protocol is configured", regexp.MustCompile(`\b(?:SSLv3|TLSv1(?:\.0)?)\b`)},
			{"panbox.javascript.webview-file-access", "high", "WebView file access should be disabled for untrusted content", regexp.MustCompile(`\bsetAllowFileAccess\s*\(\s*true\s*\)`)},
			{"panbox.javascript.document-domain", "medium", "document.domain relaxation weakens same-origin isolation", regexp.MustCompile(`\bdocument\.domain\s*=`)},
			{"panbox.javascript.disable-csp", "medium", "Disabling Content Security Policy removes a browser defense", regexp.MustCompile(`\b(?:contentSecurityPolicy|content-security-policy)\s*:\s*false`)},
		},
		".java": {
			{"panbox.java.path-traversal", "high", "File path uses request-controlled data; normalize and constrain it", regexp.MustCompile(`\bnew\s+File\s*\([^\n]*(?:getParameter|getQueryString|getHeader)\s*\(`)},
			{"panbox.java.redirect-input", "medium", "Redirect destination comes from request input", regexp.MustCompile(`\b(?:sendRedirect|setHeader)\s*\([^\n]*(?:getParameter|getQueryString)\s*\(`)},
			{"panbox.java.ldap-injection", "high", "LDAP filter assembled with concatenation may be injectable", regexp.MustCompile(`\b(?:search|searchForObject)\s*\([^\n]*["'][^"']*["']\s*\+`)},
			{"panbox.java.xpath-injection", "high", "XPath expression assembled with concatenation may be injectable", regexp.MustCompile(`\b(?:compile|evaluate)\s*\(\s*["'][^"']*["']\s*\+`)},
			{"panbox.java.weak-tls-protocol", "high", "Legacy SSL/TLS protocol is configured", regexp.MustCompile(`["'](?:SSL|SSLv3|TLSv1|TLSv1\.1)["']`)},
			{"panbox.java.cookie-flags-disabled", "medium", "Cookie Secure or HttpOnly flag is disabled", regexp.MustCompile(`\bset(?:Secure|HttpOnly)\s*\(\s*false\s*\)`)},
			{"panbox.java.expression-engine", "high", "Dynamic expression engine can execute attacker-controlled expressions", regexp.MustCompile(`\b(?:ScriptEngineManager|SpelExpressionParser|ExpressionParser)\b`)},
			{"panbox.java.weak-key-size", "medium", "RSA keys below 2048 bits are weak", regexp.MustCompile(`\b(?:initialize|genKeyPair)\s*\(\s*(?:512|1024)\s*\)`)},
			{"panbox.java.hardcoded-secret", "high", "Hard-coded credential-like assignment detected", regexp.MustCompile(`(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*=\s*["'][^"']{8,}["']`)},
			{"panbox.java.directory-listing", "medium", "Directory listing is enabled", regexp.MustCompile(`\bsetListings\s*\(\s*true\s*\)`)},
			{"panbox.java.insecure-random-seed", "medium", "Random generator seeded with a constant is predictable", regexp.MustCompile(`\bnew\s+Random\s*\(\s*\d+\s*\)`)},
			{"panbox.java.weak-password-digest", "high", "Fast general-purpose digest is unsuitable for password storage", regexp.MustCompile(`\bMessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1|SHA-256)["']`)},
		},
		".php": {
			{"panbox.php.path-traversal", "high", "File path uses request data; constrain the resolved path", regexp.MustCompile(`\b(?:fopen|file_get_contents|readfile|unlink|include|require)\s*\([^\n]*\$_(?:GET|POST|REQUEST)`)},
			{"panbox.php.weak-tls", "high", "TLS peer verification is disabled", regexp.MustCompile(`\b(?:CURLOPT_SSL_VERIFYPEER|verify_peer)\s*[,=>: ]+\s*(?:false|0)\b`)},
			{"panbox.php.upload-validation", "high", "Uploaded file must be validated before moving into a served path", regexp.MustCompile(`\bmove_uploaded_file\s*\(`)},
			{"panbox.php.insecure-cookie", "medium", "Cookie should set Secure, HttpOnly, and SameSite attributes", regexp.MustCompile(`\bsetcookie\s*\([^\n]*(?:secure\s*=>\s*false|httponly\s*=>\s*false)`)},
			{"panbox.php.open-redirect", "medium", "Redirect destination comes from request input", regexp.MustCompile(`\bheader\s*\(\s*["']Location:["']\s*\.\s*\$_(?:GET|POST|REQUEST)`)},
			{"panbox.php.weak-password-hash", "high", "Fast general-purpose digest is unsuitable for password storage", regexp.MustCompile(`\b(?:md5|sha1|sha256)\s*\([^\n]*(?:password|passwd|secret|\$_POST)`)},
			{"panbox.php.dynamic-function", "high", "Dynamic function invocation uses request-controlled input", regexp.MustCompile(`\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST)`)},
			{"panbox.php.xml-parser", "high", "XML parsing requires explicit external entity protections", regexp.MustCompile(`\b(?:simplexml_load_string|DOMDocument|xml_parse)\s*\(`)},
			{"panbox.php.runtime-error-display", "medium", "Runtime error display may disclose sensitive details", regexp.MustCompile(`\bini_set\s*\(\s*["']display_errors["']\s*,\s*["'](?:1|on|true)["']`)},
			{"panbox.php.session-cookie-insecure", "medium", "Session cookie security flag is disabled", regexp.MustCompile(`\bsession_set_cookie_params\s*\([^\n]*(?:secure\s*=>\s*false|httponly\s*=>\s*false)`)},
		},
	}
	for ext, rules := range additional {
		codeRules[ext] = append(codeRules[ext], rules...)
	}
	codeRules[".pyw"] = append(codeRules[".pyw"], additional[".py"]...)
	for _, ext := range []string{".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"} {
		codeRules[ext] = append(codeRules[ext], additional[".js"]...)
	}
	for _, ext := range []string{".jsp"} {
		codeRules[ext] = append(codeRules[ext], additional[".java"]...)
	}
	for _, ext := range []string{".phtml"} {
		codeRules[ext] = append(codeRules[ext], additional[".php"]...)
	}
}

func javaRules() []rule {
	return []rule{
		{"panbox.java.runtime-exec", "high", "Runtime command execution needs input review", regexp.MustCompile(`\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`)},
		{"panbox.java.process-builder", "high", "ProcessBuilder launches an operating-system process", regexp.MustCompile(`\bnew\s+ProcessBuilder\s*\(`)},
		{"panbox.java.unsafe-deserialization", "high", "ObjectInputStream can deserialize untrusted objects", regexp.MustCompile(`\bnew\s+ObjectInputStream\s*\(`)},
		{"panbox.java.yaml-load", "high", "SnakeYAML load may construct unsafe objects; use SafeConstructor", regexp.MustCompile(`\bnew\s+Yaml\s*\(\s*\)\s*\.\s*load\s*\(`)},
		{"panbox.java.sql-statement", "high", "Statement SQL assembled with concatenation may be injectable", regexp.MustCompile(`\b(?:executeQuery|executeUpdate|execute)\s*\(\s*[\"'][^\"']*[\"']\s*\+`)},
		{"panbox.java.xxe-document-builder", "high", "XML parser creation needs external entity protections", regexp.MustCompile(`\bDocumentBuilderFactory\.newInstance\s*\(`)},
		{"panbox.java.xxe-sax", "high", "SAX parser creation needs external entity protections", regexp.MustCompile(`\bSAXParserFactory\.newInstance\s*\(`)},
		{"panbox.java.weak-cipher", "high", "ECB mode does not provide semantic security", regexp.MustCompile(`Cipher\.getInstance\s*\(\s*[\"'][^\"']*ECB`)},
		{"panbox.java.weak-hash", "low", "MD5 or SHA-1 is unsuitable for security-sensitive hashing", regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']`)},
		{"panbox.java.insecure-random", "low", "java.util.Random is not cryptographically secure", regexp.MustCompile(`\bnew\s+Random\s*\(`)},
		{"panbox.java.hostname-verifier", "high", "Hostname verification is bypassed", regexp.MustCompile(`\b(?:NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER)\b`)},
		{"panbox.java.sql-raw", "high", "Raw SQL API needs parameterization review", regexp.MustCompile(`\b(?:createNativeQuery|createSQLQuery)\s*\(`)},
	}
}

func phpRules() []rule {
	return []rule{
		{"panbox.php.dynamic-eval", "high", "Dynamic evaluation can execute attacker-controlled PHP", regexp.MustCompile(`\beval\s*\(`)},
		{"panbox.php.command-execution", "high", "Shell command execution needs input review", regexp.MustCompile(`\b(?:shell_exec|passthru|system|exec|proc_open|popen)\s*\(`)},
		{"panbox.php.unsafe-unserialize", "high", "Unserialize can instantiate unsafe objects from untrusted data", regexp.MustCompile(`\bunserialize\s*\(`)},
		{"panbox.php.assert-input", "high", "assert on dynamic input can execute code on older PHP versions", regexp.MustCompile(`\bassert\s*\(\s*\$_(?:GET|POST|REQUEST)`)},
		{"panbox.php.dynamic-include", "high", "Include path comes directly from request input", regexp.MustCompile(`\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)`)},
		{"panbox.php.sql-input", "high", "SQL execution references request input; use bound parameters", regexp.MustCompile(`\b(?:query|exec|mysqli_query)\s*\([^\n]*\$_(?:GET|POST|REQUEST)`)},
		{"panbox.php.xss-output", "high", "Request input is emitted without visible HTML encoding", regexp.MustCompile(`\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST)`)},
		{"panbox.php.ssrf-input", "high", "Outbound URL is built from request input; validate destination", regexp.MustCompile(`\b(?:file_get_contents|curl_init)\s*\(\s*\$_(?:GET|POST|REQUEST)`)},
		{"panbox.php.weak-hash", "low", "MD5 or SHA-1 is unsuitable for password hashing", regexp.MustCompile(`\b(?:md5|sha1)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|\$password)`)},
		{"panbox.php.insecure-random", "low", "rand/mt_rand is not cryptographically secure", regexp.MustCompile(`\b(?:rand|mt_rand)\s*\(`)},
		{"panbox.php.extract-request", "medium", "extract on request data can overwrite variables and bypass validation", regexp.MustCompile(`\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)`)},
		{"panbox.php.preg-replace-eval", "high", "The deprecated e modifier evaluates replacement as PHP code", regexp.MustCompile(`\bpreg_replace\s*\(\s*[\"'][^\"']*e[\"']`)},
	}
}

// These signatures depend on literal values such as cipher names, so match a
// comment-stripped view that retains string contents. Custom rules always use
// the safer string-stripped view.
var literalRuleIDs = map[string]bool{
	"panbox.java.weak-cipher":                true,
	"panbox.java.weak-hash":                  true,
	"panbox.java.sql-statement":              true,
	"panbox.java.weak-tls-protocol":          true,
	"panbox.java.hardcoded-secret":           true,
	"panbox.javascript.wildcard-cors":        true,
	"panbox.javascript.postmessage-wildcard": true,
	"panbox.javascript.sql-interpolation":    true,
	"panbox.javascript.weak-tls-protocol":    true,
	"panbox.php.preg-replace-eval":           true,
	"panbox.php.open-redirect":               true,
	"panbox.go.insecure-http-server":         true,
	"panbox.go.hardcoded-secret":             true,
	"panbox.python.sql-fstring":              true,
	"panbox.python.sql-format":               true,
	"panbox.python.django-host-wildcard":     true,
	"panbox.python.dev-server-exposed":       true,
}

func Vaccin(root string) ([]Finding, error) {
	custom, err := loadCustomRules(root)
	if err != nil {
		return nil, err
	}
	paths, err := files(root, func(name string) bool { _, ok := codeRules[filepath.Ext(name)]; return ok })
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Size() > 2<<20 {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p := relative(root, path)
		ext := filepath.Ext(path)
		code := stripSource(raw, ext, false)
		literals := stripSource(raw, ext, true)
		lineStarts := []int{0}
		for i, c := range code {
			if c == '\n' {
				lineStarts = append(lineStarts, i+1)
			}
		}
		rules := make([]rule, 0, len(codeRules[ext])+len(custom[ext]))
		rules = append(rules, codeRules[ext]...)
		rules = append(rules, custom[ext]...)
		for _, r := range rules {
			candidate := code
			if literalRuleIDs[r.id] {
				candidate = literals
			}
			seenLines := map[int]bool{}
			for _, location := range r.re.FindAllStringIndex(candidate, -1) {
				line := sort.Search(len(lineStarts), func(i int) bool { return lineStarts[i] > location[0] })
				if line == 0 {
					line = 1
				}
				if !seenLines[line] {
					out = append(out, Finding{Module: "vaccin", RuleID: r.id, Severity: r.severity, Path: p, Line: line, Message: r.message, Identity: fmt.Sprintf("%s:%s:%d", r.id, p, line)})
					seenLines[line] = true
				}
			}
		}
	}
	return out, nil
}

// stripSource preserves line and byte offsets while removing comments. It can
// either blank or preserve string literals. This lexer is intentionally small;
// it is not a language parser or taint analysis.
func stripSource(source []byte, ext string, keepStrings bool) string {
	var b strings.Builder
	b.Grow(len(source))
	quote, escaped, blockComment := byte(0), false, false
	for i := 0; i < len(source); i++ {
		c := source[i]
		if blockComment {
			if c == '*' && i+1 < len(source) && source[i+1] == '/' {
				b.WriteString("  ")
				i++
				blockComment = false
			} else if c == '\n' || c == '\r' {
				b.WriteByte(c)
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if quote != 0 {
			if keepStrings {
				b.WriteByte(c)
			} else if c == '\n' || c == '\r' {
				b.WriteByte(c)
			} else {
				b.WriteByte(' ')
			}
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '*' && ext != ".py" && ext != ".pyw" {
			b.WriteString("  ")
			i++
			blockComment = true
			continue
		}
		if (c == '#' && (ext == ".py" || ext == ".pyw" || ext == ".php" || ext == ".phtml")) || (c == '/' && i+1 < len(source) && source[i+1] == '/' && ext != ".py" && ext != ".pyw") {
			for i < len(source) && source[i] != '\n' && source[i] != '\r' {
				b.WriteByte(' ')
				i++
			}
			if i < len(source) {
				b.WriteByte(source[i])
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
		}
		b.WriteByte(c)
	}
	return b.String()
}

type dependency struct{ ecosystem, name, version, path string }

func dependencies(root string) ([]dependency, error) {
	paths, err := files(root, func(name string) bool {
		switch name {
		case "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "go.mod", "go.sum", "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock", "pom.xml", "gradle.lockfile", "composer.lock":
			return true
		default:
			base := filepath.Base(name)
			return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
		}
	})
	if err != nil {
		return nil, err
	}
	var out []dependency
	seen := map[string]bool{}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Size() > 8<<20 {
			return nil, fmt.Errorf("manifest too large: %s", path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p := relative(root, path)
		base := filepath.Base(path)
		if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
			parsed, err := parseRequirements(raw, p)
			if err != nil {
				return nil, err
			}
			out = append(out, parsed...)
			continue
		}
		switch filepath.Base(path) {
		case "package-lock.json":
			type npmDependency struct {
				Version      string                   `json:"version"`
				Dependencies map[string]npmDependency `json:"dependencies"`
			}
			var lock struct {
				LockfileVersion int `json:"lockfileVersion"`
				Packages        map[string]struct {
					Version string `json:"version"`
				} `json:"packages"`
				Dependencies map[string]npmDependency `json:"dependencies"`
			}
			if err := json.Unmarshal(raw, &lock); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			if lock.LockfileVersion == 1 {
				var collect func(map[string]npmDependency)
				collect = func(items map[string]npmDependency) {
					for name, dep := range items {
						if pinnedVersion(dep.Version) {
							out = append(out, dependency{"npm", name, dep.Version, p})
						}
						collect(dep.Dependencies)
					}
				}
				collect(lock.Dependencies)
			} else if lock.LockfileVersion >= 2 {
				for key, v := range lock.Packages {
					if !strings.HasPrefix(key, "node_modules/") || !pinnedVersion(v.Version) {
						continue
					}
					name := key[strings.LastIndex(key, "node_modules/")+len("node_modules/"):]
					if name != "" {
						out = append(out, dependency{"npm", name, v.Version, p})
					}
				}
			} else {
				return nil, fmt.Errorf("%s: unsupported npm lockfile version %d", p, lock.LockfileVersion)
			}
		case "pnpm-lock.yaml":
			parsed, err := parsePnpmLock(raw, p)
			if err != nil {
				return nil, err
			}
			out = append(out, parsed...)
		case "yarn.lock":
			parsed, err := parseYarnLock(raw, p)
			if err != nil {
				return nil, err
			}
			out = append(out, parsed...)
		case "bun.lock":
			var lock struct {
				Packages map[string][]json.RawMessage `json:"packages"`
			}
			if err := json.Unmarshal(raw, &lock); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			for _, entry := range lock.Packages {
				if len(entry) == 0 {
					continue
				}
				var coordinate string
				if json.Unmarshal(entry[0], &coordinate) == nil {
					name, version := splitPackageCoordinate(coordinate)
					if name != "" && pinnedVersion(version) {
						out = append(out, dependency{"npm", name, version, p})
					}
				}
			}
		case "Pipfile.lock":
			var lock struct {
				Default map[string]struct {
					Version string `json:"version"`
				} `json:"default"`
				Develop map[string]struct {
					Version string `json:"version"`
				} `json:"develop"`
			}
			if err := json.Unmarshal(raw, &lock); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			for _, packages := range []map[string]struct {
				Version string `json:"version"`
			}{lock.Default, lock.Develop} {
				for name, dep := range packages {
					version := strings.TrimPrefix(dep.Version, "==")
					if pinnedVersion(version) {
						out = append(out, dependency{"PyPI", normalizePyPI(name), version, p})
					}
				}
			}
		case "poetry.lock", "uv.lock", "pdm.lock":
			parsed, err := parsePythonLock(raw, p)
			if err != nil {
				return nil, err
			}
			out = append(out, parsed...)
		case "go.mod":
			inRequire := false
			s := bufio.NewScanner(bytes.NewReader(raw))
			for s.Scan() {
				line := strings.TrimSpace(strings.SplitN(s.Text(), "//", 2)[0])
				if line == "require (" {
					inRequire = true
					continue
				}
				if line == ")" {
					inRequire = false
					continue
				}
				if strings.HasPrefix(line, "require ") {
					line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
				} else if !inRequire {
					continue
				}
				f := strings.Fields(line)
				if len(f) >= 2 && strings.HasPrefix(f[1], "v") {
					out = append(out, dependency{"Go", f[0], f[1], p})
				}
			}
			if err := s.Err(); err != nil {
				return nil, err
			}
		case "go.sum":
			s := bufio.NewScanner(bytes.NewReader(raw))
			for s.Scan() {
				f := strings.Fields(s.Text())
				if len(f) < 2 {
					continue
				}
				version := strings.TrimSuffix(f[1], "/go.mod")
				if strings.HasPrefix(version, "v") && pinnedVersion(version) {
					out = append(out, dependency{"Go", f[0], version, p})
				}
			}
			if err := s.Err(); err != nil {
				return nil, err
			}
		case "pom.xml":
			var pom struct {
				Dependencies []struct {
					GroupID    string `xml:"groupId"`
					ArtifactID string `xml:"artifactId"`
					Version    string `xml:"version"`
				} `xml:"dependencies>dependency"`
				Managed []struct {
					GroupID    string `xml:"groupId"`
					ArtifactID string `xml:"artifactId"`
					Version    string `xml:"version"`
				} `xml:"dependencyManagement>dependencies>dependency"`
			}
			if err := xml.Unmarshal(raw, &pom); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			managed := map[string]string{}
			for _, dep := range pom.Managed {
				if dep.GroupID != "" && dep.ArtifactID != "" && pinnedVersion(dep.Version) {
					managed[dep.GroupID+":"+dep.ArtifactID] = dep.Version
				}
			}
			for _, dep := range pom.Dependencies {
				name := dep.GroupID + ":" + dep.ArtifactID
				version := dep.Version
				if version == "" {
					version = managed[name]
				}
				if dep.GroupID != "" && dep.ArtifactID != "" && pinnedVersion(version) {
					out = append(out, dependency{"Maven", name, version, p})
				}
			}
		case "gradle.lockfile":
			s := bufio.NewScanner(bytes.NewReader(raw))
			for s.Scan() {
				line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
				if line == "" || !strings.Contains(line, "=") {
					continue
				}
				coordinate := strings.SplitN(line, "=", 2)[0]
				parts := strings.Split(coordinate, ":")
				if len(parts) == 3 && parts[0] != "" && parts[1] != "" && pinnedVersion(parts[2]) {
					out = append(out, dependency{"Maven", parts[0] + ":" + parts[1], parts[2], p})
				}
			}
			if err := s.Err(); err != nil {
				return nil, err
			}
		case "composer.lock":
			var lock struct {
				Packages []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"packages"`
			}
			if err := json.Unmarshal(raw, &lock); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			for _, dep := range lock.Packages {
				if strings.Contains(dep.Name, "/") && pinnedVersion(dep.Version) {
					out = append(out, dependency{"Packagist", dep.Name, strings.TrimPrefix(dep.Version, "v"), p})
				}
			}
		}
	}
	unique := out[:0]
	for _, d := range out {
		k := d.ecosystem + "\x00" + d.name + "\x00" + d.version + "\x00" + d.path
		if d.ecosystem == "Go" {
			k = d.ecosystem + "\x00" + d.name + "\x00" + d.version
		}
		if !seen[k] {
			seen[k] = true
			unique = append(unique, d)
		}
	}
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].ecosystem+unique[i].name+unique[i].path < unique[j].ecosystem+unique[j].name+unique[j].path
	})
	return unique, nil
}

func parseRequirements(raw []byte, path string) ([]dependency, error) {
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 2<<20)
	var out []dependency
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		part := strings.SplitN(line, "==", 2)
		if len(part) != 2 {
			continue
		}
		name := normalizePyPI(strings.TrimSpace(part[0]))
		version := strings.TrimSpace(strings.SplitN(strings.SplitN(part[1], ";", 2)[0], "#", 2)[0])
		if name != "" && pinnedVersion(version) {
			out = append(out, dependency{"PyPI", name, version, path})
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func pinnedVersion(version string) bool {
	return version != "" && !strings.ContainsAny(version, "$*<>, ")
}

func normalizePyPI(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	return regexp.MustCompile(`-+`).ReplaceAllString(name, "-")
}

func splitPackageCoordinate(raw string) (string, string) {
	key := strings.Trim(strings.TrimSpace(raw), `"'`)
	key = strings.TrimPrefix(key, "/")
	if strings.HasPrefix(key, "@") {
		if slash := strings.IndexByte(key, '/'); slash >= 0 {
			if at := strings.LastIndex(key, "@"); at > slash {
				name := key[:at]
				version := strings.TrimPrefix(key[at+1:], "npm:")
				version = strings.SplitN(version, "(", 2)[0]
				return name, strings.TrimSpace(version)
			}
			if slash := strings.LastIndex(key, "/"); slash > 0 {
				return key[:slash], strings.TrimSpace(strings.SplitN(key[slash+1:], "(", 2)[0])
			}
		}
	}
	if at := strings.LastIndex(key, "@"); at > 0 {
		version := strings.TrimPrefix(key[at+1:], "npm:")
		version = strings.SplitN(version, "(", 2)[0]
		return key[:at], strings.TrimSpace(version)
	}
	if slash := strings.LastIndex(key, "/"); slash > 0 {
		return key[:slash], strings.TrimSpace(strings.SplitN(key[slash+1:], "(", 2)[0])
	}
	return "", ""
}

func parseYarnLock(raw []byte, path string) ([]dependency, error) {
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 2<<20)
	current := []string{}
	version := ""
	var out []dependency
	flush := func() {
		if !pinnedVersion(version) {
			return
		}
		for _, selector := range current {
			name, _ := splitPackageCoordinate(selector)
			if name != "" {
				out = append(out, dependency{"npm", name, version, path})
			}
		}
	}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || line == "__metadata:" {
			continue
		}
		if !strings.HasPrefix(s.Text(), " ") && strings.HasSuffix(line, ":") {
			flush()
			current = nil
			version = ""
			selectors := strings.TrimSuffix(line, ":")
			selectors = strings.Trim(selectors, `"'`)
			for _, selector := range strings.Split(selectors, ",") {
				selector = strings.Trim(strings.TrimSpace(selector), `"'`)
				if selector != "" {
					current = append(current, selector)
				}
			}
			continue
		}
		if strings.HasPrefix(line, "version ") || strings.HasPrefix(line, "version:") {
			version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "version "), "version:")), `"'`)
		}
	}
	flush()
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func parsePnpmLock(raw []byte, path string) ([]dependency, error) {
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 2<<20)
	inPackages := false
	var out []dependency
	for s.Scan() {
		line := s.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "packages:" {
			inPackages = true
			continue
		}
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inPackages = false
		}
		if !inPackages || len(line) < 3 || line[0] != ' ' || line[1] != ' ' || line[2] == ' ' || !strings.HasSuffix(trimmed, ":") {
			continue
		}
		key := strings.TrimSuffix(trimmed, ":")
		name, version := splitPackageCoordinate(key)
		if name != "" && pinnedVersion(version) {
			out = append(out, dependency{"npm", name, version, path})
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func parsePythonLock(raw []byte, path string) ([]dependency, error) {
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 2<<20)
	inPackage := false
	name, version := "", ""
	var out []dependency
	flush := func() {
		if name != "" && pinnedVersion(version) {
			out = append(out, dependency{"PyPI", normalizePyPI(name), version, path})
		}
	}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[[package]]") || strings.HasPrefix(line, "[[packages]]") {
			flush()
			name, version, inPackage = "", "", true
			continue
		}
		if !inPackage {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "name":
			name = value
		case "version":
			version = value
		}
	}
	flush()
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

type advisory struct {
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		EcosystemSpecific struct {
			Severity string `json:"severity"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

type osvBatchResult struct {
	Results []osvBatchEntry `json:"results"`
}

type osvBatchEntry struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// queryOSVBatch keeps each response aligned with its input query and follows
// per-query pagination tokens. Batches stay small enough for public OSV limits.
func queryOSVBatch(ctx context.Context, client *http.Client, endpoint string, deps []dependency) ([][]string, error) {
	const batchSize = 100
	all := make([][]string, len(deps))
	for offset := 0; offset < len(deps); offset += batchSize {
		end := offset + batchSize
		if end > len(deps) {
			end = len(deps)
		}
		chunk := deps[offset:end]
		pending := make([]int, len(chunk))
		for i := range pending {
			pending[i] = i
		}
		tokens := map[int]string{}
		seen := make([]map[string]bool, len(chunk))
		for page := 0; len(pending) > 0; page++ {
			if page >= 100 {
				return nil, errors.New("advisory response exceeded 100 pages for a batch")
			}
			queries := make([]map[string]any, 0, len(pending))
			for _, index := range pending {
				d := chunk[index]
				q := map[string]any{"package": map[string]string{"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
				if token := tokens[index]; token != "" {
					q["page_token"] = token
				}
				queries = append(queries, q)
			}
			body, err := json.Marshal(map[string]any{"queries": queries})
			if err != nil {
				return nil, err
			}
			req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(endpoint, "/")+"/v1/querybatch", bytes.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return nil, fmt.Errorf("advisory query returned HTTP %d", resp.StatusCode)
			}
			raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			var result osvBatchResult
			if err := json.Unmarshal(raw, &result); err != nil {
				return nil, err
			}
			if len(result.Results) != len(pending) {
				return nil, errors.New("advisory response count mismatch")
			}
			next := make([]int, 0, len(pending))
			for i, group := range result.Results {
				index := pending[i]
				if seen[index] == nil {
					seen[index] = map[string]bool{}
				}
				for _, vuln := range group.Vulns {
					if vuln.ID != "" && !seen[index][vuln.ID] {
						seen[index][vuln.ID] = true
						all[offset+index] = append(all[offset+index], vuln.ID)
					}
				}
				if group.NextPageToken != "" {
					tokens[index] = group.NextPageToken
					next = append(next, index)
				}
			}
			pending = next
		}
	}
	return all, nil
}

func advisorySeverity(a advisory) string {
	for _, s := range append([]string{a.DatabaseSpecific.Severity}, func() []string {
		var v []string
		for _, x := range a.Affected {
			v = append(v, x.EcosystemSpecific.Severity)
		}
		return v
	}()...) {
		switch strings.ToLower(s) {
		case "critical", "high", "medium", "low":
			return strings.ToLower(s)
		}
	}
	return "info"
}

func Enetron(ctx context.Context, root, endpoint string) ([]Finding, error) {
	deps, err := dependencies(root)
	if err != nil {
		return nil, err
	}
	if len(deps) == 0 {
		return nil, errors.New("no supported pinned dependency manifest found; use an npm/pnpm/Yarn/Bun lockfile, pinned Python requirements or Pipfile/Poetry/uv/PDM lock, go.mod/go.sum, Maven pom.xml, gradle.lockfile, or composer.lock")
	}
	if len(deps) > 20000 {
		return nil, errors.New("more than 20,000 pinned dependencies; narrow the scan path or split the repository")
	}
	if endpoint == "" {
		endpoint = "https://api.osv.dev"
	}
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		return nil, errors.New("advisory endpoint must use HTTPS or loopback HTTP")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	matches, err := queryOSVBatch(ctx, client, endpoint, deps)
	if err != nil {
		return nil, err
	}
	var out []Finding
	severities := map[string]string{}
	for i, vulnerabilityIDs := range matches {
		d := deps[i]
		for _, vulnID := range vulnerabilityIDs {
			severity, ok := severities[vulnID]
			if !ok {
				u := strings.TrimRight(endpoint, "/") + "/v1/vulns/" + url.PathEscape(vulnID)
				req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
				if err != nil {
					return nil, err
				}
				resp, err := client.Do(req)
				if err != nil {
					return nil, err
				}
				if resp.StatusCode != 200 {
					resp.Body.Close()
					return nil, fmt.Errorf("advisory %s returned HTTP %d", vulnID, resp.StatusCode)
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
				resp.Body.Close()
				if err != nil {
					return nil, err
				}
				var detail advisory
				if err := json.Unmarshal(body, &detail); err != nil {
					return nil, err
				}
				severity = advisorySeverity(detail)
				severities[vulnID] = severity
			}
			message := fmt.Sprintf("%s %s %s: advisory %s", d.ecosystem, d.name, d.version, vulnID)
			if severity == "info" {
				message += " (severity unavailable)"
			}
			out = append(out, Finding{Module: "enetron", RuleID: vulnID, Severity: severity, Path: d.path, Message: message, Identity: d.ecosystem + ":" + d.name + ":" + d.version + ":" + vulnID + ":" + d.path})
		}
	}
	return out, nil
}
