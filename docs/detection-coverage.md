# PANBOX Detection Coverage (Alpha)

PANBOX ships two first-party modules: **VACCIN** for source-code checks and **ENETRON** for dependency advisory matching. This page describes the built-in alpha coverage so operators can decide what to enable and where another scanner is still needed.

## VACCIN: source checks

VACCIN currently has **120 built-in rule signatures**: 26 Python, 26 JavaScript/TypeScript, 22 Go, 24 Java, and 22 PHP. It scans Python (`.py`, `.pyw`), JavaScript and TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`), Go (`.go`), Java/JSP (`.java`, `.jsp`), and PHP (`.php`, `.phtml`). It skips individual source files larger than 2 MiB.

The built-in checks are native PANBOX signatures. They flag risky constructs for review; they do not prove exploitability or trace data from source to sink across functions. Comment and literal handling is lexical. Some findings therefore need human triage, and PANBOX has not published an independently measured precision/recall or false-positive percentage.

| Language | Built-in check families |
|---|---|
| Python | Flask debug and all-interface development server; shell/process execution and request-derived process arguments; dynamic `eval`/`exec`; unsafe pickle/YAML/XML parsing; SQL formatting; template-string rendering and `mark_safe`; request-derived filesystem paths and archive extraction; disabled TLS verification; weak hashes/password hashing and non-cryptographic random; temporary-name hazards; Django CSRF/host and session-cookie controls; interactive debugger. |
| JavaScript / TypeScript | `eval` and `Function`; child-process execution and shell mode; HTML/DOM/React raw output; `document.write`; request-derived fetch/redirect/filesystem paths; JWT decode; disabled TLS verification and legacy TLS; wildcard CORS and `postMessage`; SQL interpolation; prototype mutation; insecure cookies and proxy trust; weak password hashes/random; string-based timers; WebView file access; relaxed `document.domain` and disabled CSP. |
| Go | Shell execution; SQL concatenation/formatting; request-derived HTTP destinations, redirects, and filesystem paths; disabled/legacy TLS; raw HTML/template output; Gob decoding; JWT unverified parsing; weak hashes/random/key sizes/curves; cookies; HTTP server exposure/timeouts; pprof; `unsafe.Pointer`; permissive file modes; hard-coded credential-like assignments. |
| Java | Runtime/process execution; Java object deserialization; unsafe SnakeYAML loading; SQL concatenation/raw APIs; XML parser/XXE setup; LDAP and XPath concatenation; ECB and weak digest/random/key sizes; disabled hostname/certificate verification and legacy TLS; request-derived file paths and redirects; insecure cookie flags; dynamic expression engines; directory listing; credential-like assignments. |
| PHP | `eval`, shell functions, dynamic calls, and request-derived `assert`; unsafe `unserialize`; dynamic file includes and request-derived file paths; SQL and raw HTML output from request data; SSRF-shaped URL sources and open redirects; upload movement needing validation; XML parser setup; disabled TLS verification; weak hashes/random; insecure cookies/session settings; `extract` on request data; deprecated `preg_replace` evaluation; runtime error display. |

The rules are deliberately review-oriented. For example, use of an XML parser is flagged because safe parser configuration must be checked; a lexical rule cannot determine whether the required protections are set elsewhere. Results include rule ID, severity, file, line, and a remediation-oriented message. Findings can be triaged/recast in the dashboard with an audited reason.

### Custom VACCIN rules

Commit `.panbox/rules.json` in the repository. Custom regex signatures run alongside built-ins on supported extensions, with comment/string stripping and file/size limits. The rule file accepts up to 64 rules, 256 characters per pattern, and 64 KiB total. Supported extension values are `.py`, `.pyw`, `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`, `.go`, `.java`, `.jsp`, `.php`, and `.phtml`. Regex patterns can span lines; this remains lexical matching, not AST or taint analysis. Review rule changes as code and validate them on representative repositories.

## ENETRON: dependency advisories

ENETRON extracts pinned/resolved package coordinates from these repository files:

| Ecosystem | Inputs currently read | Coverage notes |
|---|---|---|
| npm | `package-lock.json` v1/v2/v3 | Includes nested/installed package entries. |
| pnpm | `pnpm-lock.yaml` | Reads package entries from common lockfile layouts. |
| Yarn | `yarn.lock` | Reads versioned selectors from Yarn lock entries. |
| Bun | JSON `bun.lock` | Reads package coordinates from JSON lockfile entries. |
| Python / PyPI | `requirements*.txt` with `==` pins, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock` | Requirements ranges and editable/VCS references without a resolved version are not queried. |
| Go | `go.mod`, `go.sum` | Uses declared module versions and checksums; duplicate module/version entries are collapsed. |
| Maven | `pom.xml` | Reads explicit versions and locally declared `dependencyManagement` versions. Maven properties, imported BOMs, inherited parent versions, and a full transitive resolution are not computed. |
| Gradle | `gradle.lockfile` | Reads locked `group:artifact:version` entries. |
| Composer / Packagist | `composer.lock` | Reads resolved packages. |

Coordinates and versions are sent over HTTPS to OSV-compatible advisory API data (`POST /v1/querybatch`); PANBOX performs package parsing, querying, normalization, and dashboard workflows itself. OSV is the advisory-data source, not a scanner executable. The default endpoint is `https://api.osv.dev`; `PANBOX_ADVISORY_URL` or `--advisory-url` can select an approved compatible mirror. Queries are batched and paginated. A scan is marked incomplete if a supported manifest is absent, malformed, dependency volume exceeds 20,000, or the advisory service cannot provide a complete response. An advisory whose severity is unavailable is shown as `info` rather than silently dropped.

## Scope and roadmap

VACCIN is not yet a compiler-backed AST/dataflow engine, a full CWE implementation, or a replacement claim for mature SAST platforms. ENETRON coverage depends on supported lockfile formats and advisory data availability. RIDER secret scanning and TESLA IaC scanning are not active in this alpha. Review current coverage before relying on a PANBOX gate as the only security control.

For operator setup and CI wiring, see the [English guide](product-guide-en.md) or [Indonesian guide](product-guide-id.md).
