## v0.1.0-alpha.8

- CI text output now prints gate status, module results, severity counts, ten prioritized finding locations, and commit-pinned source links when CI metadata is available. GitLab folds the finding list; JSON and SARIF remain machine-readable.
- The dashboard pages repository, finding, scan, and Overview rows ten at a time and shows the latest scan timestamp per repository across branches.
- VACCIN finding detail keeps path and line prominent and links to curated OWASP or Django remediation guidance. ENETRON keeps its OSV advisory link. The advice is not an AI fix or exploitability verdict.
- GitHub and GitLab SCM connection controls are explained in a dedicated English/Indonesian guide chapter, including the new-connection button and each lifecycle action.
- The scanner rule engine remains `0.1.5`; this release changes agent presentation and dashboard/API behavior, not the detection signature set.

## v0.1.0-alpha.7

- The agent-only release includes VACCIN engine `0.1.5` and 38 new Python/JavaScript/TypeScript lexical signatures with positive and negative fixtures. See [release notes](releases/v0.1.0-alpha.7.md).
- `panbox version` prints both the release tag and engine version so CI can verify the downloaded binary.
- VACCIN adds scoped Django settings, SQL, CSRF, redirect, and template checks; known bundled JavaScript is excluded to reduce noise. A local `django.nv` regression scan produced 25 Python/template findings before the additional signatures in this release.
- Finding detail now groups location, scan history, suggested remediation, and audited triage in a responsive panel. Common rule families receive more specific fix guidance.
- VACCIN expands first-party native rule families across Java/JSP, JavaScript/TypeScript, Python, PHP, and Go; custom rules accept all scanned extensions and regexes can span lines.
- ENETRON adds pnpm, Yarn, Bun JSON, Pipfile, Poetry, uv, PDM, requirements variants, and Go `go.sum` inputs alongside npm, Maven, Gradle, and Composer.
- ENETRON batches up to 20,000 pinned dependencies and follows OSV per-query pagination tokens instead of failing on paginated advisory responses.
- ENETRON is explicitly marked `skipped` when a repository has no supported dependency manifest; completed source scans can still pass, while malformed/unpinned manifests remain unverified.
- Adds a detailed detection coverage matrix describing rule families, supported manifests, and alpha limitations.
- Hosted CI examples use Alpine with curl installed for GitLab and `ubuntu-latest` for GitHub Actions. Private SCM stays private because checkout remains in the provider's runner.
- Operator and CI setup guides add server upgrade instructions, configuration-variable tables, and the ENETRON no-manifest diagnosis.
- Agent-only release assets are built from the `v0.1.0-alpha.7` tag by GitHub Actions.

## v0.1.0-alpha.6

PANBOX v0.1.0-alpha.6 native agent preview for Linux, macOS, and Windows on amd64 and arm64.

This release adds a simpler CI credential path: one PANBOX API key with `scans:write` plus the enrolled PANBOX project ID. Private SCM remains private; the CI runner uses its own checkout credentials. GitLab `CI_DEFAULT_BRANCH` and `PANBOX_DEFAULT_BRANCH` can establish the default even when the first job scans a feature branch. The dashboard adds project edit/archive/restore, key rotation, finding triage/history, and detailed views. Native VACCIN supports reviewed custom rules. Existing alpha scan keys remain accepted for migration.

- Each platform now has a direct `panbox-agent_<os>_<arch>` binary asset (with `.exe` on Windows). These assets contain only the agent, not the dashboard or PostgreSQL.
- `install-agent.sh` and `install-agent.ps1` download the platform binary and verify it against `SHA256SUMS` inside a CI workspace. Pin this release tag in your pipeline; see the copy-ready examples in `deploy/`.
- The older archive format is retained for manual users.

- VACCIN uses built-in source rules for selected Python, JavaScript/TypeScript, and Go patterns.
- ENETRON parses pinned npm, PyPI, and Go dependencies and queries an OSV-compatible advisory API. Advisory data is fetched from OSV by default; this is not an offline SCA database.
- The agent can run in a local or self-hosted CI runner for any Git repository. GitHub and GitLab examples are in `deploy/`.
- The dashboard is distributed separately with Docker Compose and PostgreSQL. These assets are CLI/agent binaries only.
- Before each online scan, the agent fetches enabled modules and the gate threshold from the PANBOX API using `PANBOX_API_KEY`. Dashboard operators can pause future scans or change module selection.
- `panbox mcp` exposes read-only repository, finding, and scan tools to a local MCP host using a scoped access key.
- The server/dashboard also adds reasoned severity recasts with gate revisions and filtered PDF exports. The server still comes from the repository Docker build, not these agent assets.

This is a narrow preview, not broad SAST/SCA coverage. See the README for supported patterns and manifest formats.
## v0.1.0-alpha.9

- Optional AI review runs on the PANBOX server after the CI gate returns. The worker reads bounded source windows from connected GitHub/GitLab at the scan commit and asks a configured OpenAI or Anthropic model to assess existing VACCIN findings.
- Admin can enable it, choose provider/model and a 1–10 finding cap, queue an older scan, and inspect sanitized stage logs plus advisory assessments. Provider secrets stay on the server. AI output never changes raw findings, dispositions, severity, or gates.
- Agent-only release assets remain available; VACCIN/ENETRON detection rules are unchanged from alpha.8. Upgrade the dashboard server from this tag separately to use AI review.
