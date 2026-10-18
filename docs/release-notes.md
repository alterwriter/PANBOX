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
