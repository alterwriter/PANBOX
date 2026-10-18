package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
const Version = "0.1.0"

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
	allowed := map[string]bool{".py": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".go": true}
	out := map[string][]rule{}
	seen := map[string]bool{}
	for _, spec := range config.Rules {
		if !regexp.MustCompile(`^custom\.[a-z0-9][a-z0-9._-]{0,63}$`).MatchString(spec.ID) || seen[spec.ID] || !validSeverity(spec.Severity) || len(spec.Message) == 0 || len(spec.Message) > 200 || len(spec.Pattern) == 0 || len(spec.Pattern) > 256 || len(spec.Extensions) == 0 || len(spec.Extensions) > 6 {
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
	},
	".js":  {{"panbox.javascript.eval", "high", "Dynamic eval executes a string", regexp.MustCompile(`\beval\s*\(`)}},
	".ts":  {{"panbox.typescript.eval", "high", "Dynamic eval executes a string", regexp.MustCompile(`\beval\s*\(`)}},
	".jsx": {{"panbox.javascript.eval", "high", "Dynamic eval executes a string", regexp.MustCompile(`\beval\s*\(`)}},
	".tsx": {{"panbox.typescript.eval", "high", "Dynamic eval executes a string", regexp.MustCompile(`\beval\s*\(`)}},
	".go":  {{"panbox.go.shell-command", "medium", "Shell command execution needs input review", regexp.MustCompile(`\bexec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"\s*,`)}},
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
		s := bufio.NewScanner(bytes.NewReader(raw))
		s.Buffer(make([]byte, 4096), 2<<20)
		for line := 1; s.Scan(); line++ {
			code := stripLine(s.Text(), filepath.Ext(path))
			if filepath.Ext(path) == ".go" && !strings.HasPrefix(strings.TrimSpace(s.Text()), "//") {
				code = strings.SplitN(s.Text(), "//", 2)[0]
			}
			for _, r := range append(codeRules[filepath.Ext(path)], custom[filepath.Ext(path)]...) {
				if r.re.MatchString(code) {
					out = append(out, Finding{Module: "vaccin", RuleID: r.id, Severity: r.severity, Path: p, Line: line, Message: r.message, Identity: fmt.Sprintf("%s:%s:%d", r.id, p, line)})
				}
			}
		}
		if err := s.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// stripLine removes line comments and quoted values while preserving string
// delimiters for the small set of shell-command rules. This is a bounded
// heuristic, not a full language parser or taint analysis.
func stripLine(s, ext string) string {
	var b strings.Builder
	quote, escaped := byte(0), false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
				b.WriteByte(' ')
				continue
			}
			if c == '\\' {
				escaped = true
				b.WriteByte(' ')
				continue
			}
			if c == quote {
				b.WriteByte(c)
				quote = 0
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if (c == '#' && ext == ".py") || (c == '/' && i+1 < len(s) && s[i+1] == '/' && ext != ".py") {
			break
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
		return name == "package-lock.json" || name == "go.mod" || name == "requirements.txt"
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
		switch filepath.Base(path) {
		case "package-lock.json":
			var lock struct {
				LockfileVersion int `json:"lockfileVersion"`
				Packages        map[string]struct {
					Version string `json:"version"`
				} `json:"packages"`
			}
			if err := json.Unmarshal(raw, &lock); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			if lock.LockfileVersion < 2 {
				return nil, fmt.Errorf("%s: npm lockfile v2 or v3 required", p)
			}
			for key, v := range lock.Packages {
				if !strings.HasPrefix(key, "node_modules/") || v.Version == "" {
					continue
				}
				name := key[strings.LastIndex(key, "node_modules/")+len("node_modules/"):]
				if name == "" {
					continue
				}
				out = append(out, dependency{"npm", name, v.Version, p})
			}
		case "requirements.txt":
			s := bufio.NewScanner(bytes.NewReader(raw))
			for s.Scan() {
				line := strings.TrimSpace(s.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				part := strings.SplitN(line, "==", 2)
				if len(part) != 2 {
					continue
				}
				name := strings.ToLower(strings.TrimSpace(part[0]))
				version := strings.TrimSpace(strings.SplitN(strings.SplitN(part[1], ";", 2)[0], "#", 2)[0])
				if name != "" && version != "" {
					out = append(out, dependency{"PyPI", name, version, p})
				}
			}
			if err := s.Err(); err != nil {
				return nil, err
			}
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
		}
	}
	unique := out[:0]
	for _, d := range out {
		k := d.ecosystem + "\x00" + d.name + "\x00" + d.version + "\x00" + d.path
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
		return nil, errors.New("no supported pinned dependency manifest found (npm lockfile v2/v3, go.mod, requirements.txt)")
	}
	if len(deps) > 500 {
		return nil, errors.New("more than 500 dependencies; split the scan or narrow the path")
	}
	if endpoint == "" {
		endpoint = "https://api.osv.dev"
	}
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		return nil, errors.New("advisory endpoint must use HTTPS or loopback HTTP")
	}
	queries := make([]any, 0, len(deps))
	for _, d := range deps {
		queries = append(queries, map[string]any{"package": map[string]string{"name": d.name, "ecosystem": d.ecosystem}, "version": d.version})
	}
	body, _ := json.Marshal(map[string]any{"queries": queries})
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(endpoint, "/")+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("advisory query returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var result struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if len(result.Results) != len(deps) {
		return nil, errors.New("advisory response count mismatch")
	}
	for _, group := range result.Results {
		if group.NextPageToken != "" {
			return nil, errors.New("advisory response was paginated; scan cannot claim complete coverage")
		}
	}
	var out []Finding
	severities := map[string]string{}
	for i, matches := range result.Results {
		d := deps[i]
		for _, v := range matches.Vulns {
			if v.ID == "" {
				continue
			}
			severity, ok := severities[v.ID]
			if !ok {
				u := strings.TrimRight(endpoint, "/") + "/v1/vulns/" + url.PathEscape(v.ID)
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
					return nil, fmt.Errorf("advisory %s returned HTTP %d", v.ID, resp.StatusCode)
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
				severities[v.ID] = severity
			}
			message := fmt.Sprintf("%s %s %s: advisory %s", d.ecosystem, d.name, d.version, v.ID)
			if severity == "info" {
				message += " (severity unavailable)"
			}
			out = append(out, Finding{Module: "enetron", RuleID: v.ID, Severity: severity, Path: d.path, Message: message, Identity: d.ecosystem + ":" + d.name + ":" + d.version + ":" + v.ID + ":" + d.path})
		}
	}
	return out, nil
}
