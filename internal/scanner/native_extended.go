package scanner

import "regexp"

// These bounded signatures cover direct dangerous calls and configuration.
// They intentionally avoid claims about interprocedural data flow.
var extendedPythonRules = []rule{
	{"panbox.python.requests-request-url", "high", "Outbound request URL comes directly from HTTP input; constrain destinations", regexp.MustCompile(`\brequests\.(?:get|post|put|delete|request)\s*\(\s*request\.(?:GET|POST|args|form)\b`)},
	{"panbox.python.urllib-request-url", "high", "urllib URL comes directly from HTTP input; constrain destinations", regexp.MustCompile(`\b(?:urllib\.request\.)?urlopen\s*\(\s*request\.(?:GET|POST|args|form)\b`)},
	{"panbox.python.file-response-request", "high", "File response path comes directly from HTTP input; constrain it to an allowed directory", regexp.MustCompile(`\b(?:FileResponse|send_file)\s*\(\s*(?:open\s*\(\s*)?request\.(?:GET|POST|args|form)\b`)},
	{"panbox.python.django-httpresponse-request", "high", "Django HttpResponse returns request input without visible HTML encoding", regexp.MustCompile(`\bHttpResponse\s*\(\s*request\.(?:GET|POST)\.get\s*\(`)},
	{"panbox.python.jwt-signature-disabled", "high", "JWT decode explicitly disables signature verification", regexp.MustCompile(`\bjwt\.decode\s*\([^\n]{0,300}["']verify_signature["']\s*:\s*False\b`)},
	{"panbox.python.jwt-none-algorithm", "high", "JWT uses the none algorithm; require an approved signed algorithm", regexp.MustCompile(`\bjwt\.(?:encode|decode)\s*\([^\n]{0,300}\balgorithms?\s*=\s*["']none["']`)},
	{"panbox.python.yaml-unsafe-load", "high", "yaml.unsafe_load can instantiate arbitrary objects", regexp.MustCompile(`\byaml\.unsafe_load\s*\(`)},
	{"panbox.python.jsonpickle-decode", "high", "jsonpickle.decode may instantiate arbitrary objects from untrusted data", regexp.MustCompile(`\bjsonpickle\.decode\s*\(`)},
	{"panbox.python.dill-loads", "high", "dill.loads can execute code during deserialization", regexp.MustCompile(`\bdill\.loads\s*\(`)},
	{"panbox.python.lxml-entities", "high", "XML parser enables entity resolution; disable external entities", regexp.MustCompile(`\b(?:etree\.)?XMLParser\s*\([^\n]{0,250}\bresolve_entities\s*=\s*True\b`)},
	{"panbox.python.paramiko-autoaddpolicy", "high", "SSH host keys are accepted automatically; verify pinned host keys", regexp.MustCompile(`\b(?:paramiko\.)?AutoAddPolicy\s*\(`)},
	{"panbox.python.django-rawsql-fstring", "high", "Django raw SQL uses an f-string; use bound parameters", regexp.MustCompile(`\b(?:RawSQL|raw)\s*\(\s*f["']`)},
	{"panbox.python.django-rawsql-percent", "high", "Django raw SQL uses percent formatting; use bound parameters", regexp.MustCompile(`\b(?:RawSQL|raw)\s*\(\s*["'][^\n]{0,250}["']\s*%\s*\(`)},
	{"panbox.python.django-httpredirect-request", "medium", "Django redirect target comes directly from request input", regexp.MustCompile(`\bHttpResponseRedirect\s*\(\s*request\.(?:GET|POST)\.get\s*\(`)},
	{"panbox.python.flask-template-request", "high", "Flask template source comes directly from request input", regexp.MustCompile(`\brender_template_string\s*\(\s*request\.(?:args|form)\.get\s*\(`)},
	{"panbox.python.flask-redirect-request", "medium", "Flask redirect target comes directly from request input", regexp.MustCompile(`\bredirect\s*\(\s*request\.(?:args|form)\.get\s*\(`)},
	{"panbox.python.world-writable-chmod", "medium", "File permissions allow broad write access; use a restricted mode", regexp.MustCompile(`\bos\.chmod\s*\([^\n]{0,200},\s*0o(?:777|666)\s*\)`)},
	{"panbox.python.flask-hardcoded-secret", "high", "Flask secret key is a source literal; load it from a protected runtime secret", regexp.MustCompile(`(?m)^[ \t]*(?:app|application)\.secret_key[ \t]*=[ \t]*["'][^"'\r\n]{8,}["']`)},
}

var extendedJavaScriptRules = []rule{
	{"panbox.javascript.node-tls-disabled", "high", "Node TLS verification is disabled globally", regexp.MustCompile(`\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?\b`)},
	{"panbox.javascript.jwt-ignore-expiration", "high", "JWT verification ignores token expiration", regexp.MustCompile(`\bjwt\.verify\s*\([^\n]{0,300}\bignoreExpiration\s*:\s*true\b`)},
	{"panbox.javascript.jwt-none-algorithm", "high", "JWT signing selects the none algorithm", regexp.MustCompile(`\bjwt\.sign\s*\([^\n]{0,300}\balgorithm\s*:\s*["']none["']`)},
	{"panbox.javascript.vm-request-code", "high", "Node VM executes request-controlled code", regexp.MustCompile(`\bvm\.runIn(?:New|This)Context\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.require-request", "high", "Module path comes directly from request input", regexp.MustCompile(`\brequire\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.import-request", "high", "Dynamic import path comes directly from request input", regexp.MustCompile(`\bimport\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.axios-request-url", "high", "Axios destination comes directly from request input", regexp.MustCompile(`\baxios\.(?:get|post|put|delete|request)\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.http-request-url", "high", "Node HTTP destination comes directly from request input", regexp.MustCompile(`\bhttps?\.(?:get|request)\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.fs-read-request", "high", "Filesystem read path comes directly from request input", regexp.MustCompile(`\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.fs-write-request", "high", "Filesystem write path comes directly from request input", regexp.MustCompile(`\bfs\.(?:writeFile|writeFileSync|createWriteStream)\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.sendfile-request", "high", "sendFile path comes directly from request input", regexp.MustCompile(`\b(?:res|response)\.sendFile\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.express-raw-response", "high", "Express response emits request input without visible output encoding", regexp.MustCompile(`\b(?:res|response)\.send\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.regex-request", "medium", "Regular expression is built directly from request input; bound pattern complexity", regexp.MustCompile(`\bnew\s+RegExp\s*\(\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.mongo-where-request", "high", "MongoDB $where receives request input; use structured query operators", regexp.MustCompile(`\$where\s*:\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.buffer-alloc-unsafe", "medium", "Buffer.allocUnsafe can expose uninitialized memory; initialize before use", regexp.MustCompile(`\bBuffer\.allocUnsafe(?:Slow)?\s*\(`)},
	{"panbox.javascript.node-weak-hash", "medium", "MD5 or SHA-1 is unsuitable for security-sensitive hashing", regexp.MustCompile(`\bcrypto\.createHash\s*\(\s*["'](?:md5|sha1)["']`)},
	{"panbox.javascript.node-ecb-cipher", "high", "ECB cipher mode does not hide repeated plaintext patterns", regexp.MustCompile(`\bcrypto\.createCipheriv\s*\(\s*["'][^"'\n]*-ecb["']`)},
	{"panbox.javascript.location-header-request", "medium", "Location header comes directly from request input", regexp.MustCompile(`\b(?:res|response)\.setHeader\s*\(\s*["']Location["']\s*,\s*(?:req|request)\.(?:body|query|params)\b`)},
	{"panbox.javascript.wildcard-cors-header", "medium", "Wildcard CORS response header needs review for credentialed routes", regexp.MustCompile(`\b(?:res|response)\.setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']`)},
	{"panbox.javascript.express-dotfiles-allow", "medium", "Static server exposes dotfiles; restrict sensitive filenames", regexp.MustCompile(`\bexpress\.static\s*\([^\n]{0,250}\bdotfiles\s*:\s*["']allow["']`)},
}

var extendedLiteralRuleIDs = map[string]bool{
	"panbox.python.jwt-signature-disabled":      true,
	"panbox.python.jwt-none-algorithm":          true,
	"panbox.python.django-rawsql-fstring":       true,
	"panbox.python.django-rawsql-percent":       true,
	"panbox.python.flask-hardcoded-secret":      true,
	"panbox.javascript.node-tls-disabled":       true,
	"panbox.javascript.jwt-ignore-expiration":   true,
	"panbox.javascript.jwt-none-algorithm":      true,
	"panbox.javascript.node-weak-hash":          true,
	"panbox.javascript.node-ecb-cipher":         true,
	"panbox.javascript.location-header-request": true,
	"panbox.javascript.wildcard-cors-header":    true,
	"panbox.javascript.express-dotfiles-allow":  true,
}

func extendedRules(ext string) []rule {
	switch ext {
	case ".py", ".pyw":
		return extendedPythonRules
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts":
		return extendedJavaScriptRules
	default:
		return nil
	}
}
