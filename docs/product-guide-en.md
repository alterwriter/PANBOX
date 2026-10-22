# PANBOX - Product and Operator Guide

Start with the path that matches your job: **server operator** installs the private dashboard once; **DevOps** adds an agent-only step to each CI job. The agent is one Go binary. The runner does not need Node, Python, Semgrep, Grype, or a PANBOX server installation.

## 1. What runs where

```text
Git host/CI -> protected runner -> PANBOX agent -> private PANBOX API -> PostgreSQL
                                  | VACCIN: source rules            |
                                  | ENETRON: packages -> OSV        +-> React UI
```

**Result:** CI receives pass, gate failure, incomplete, or authorization failure; operators see repository and branch snapshots. The CI bundle contains no raw source; optional server-side AI review separately fetches bounded snippets through a connected SCM account. ENETRON sends package names and versions to an OSV-compatible advisory API. The agent uploads normalized findings with a PANBOX API key, without raw source snippets. See the [architecture and network diagram](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/docs/architecture.md).

### Why teams may choose PANBOX

PANBOX's practical distinction is the **combination** of these controls in one self-hosted pilot, not a claim that no other vendor has any one feature:

| Capability | Implemented PANBOX behavior |
|---|---|
| Private delivery | A protected local runner, SSH relay, or later artifact import can reach a private dashboard without a public PANBOX IP. Only the first two can enforce a synchronous CI gate. |
| Source stays on runner | Native VACCIN examines the checkout in CI; the API receives normalized findings, paths, and lines, not raw source snippets. ENETRON sends package coordinates to OSV-compatible advisory data. |
| Review and policy | Per-repository modules/gate, RBAC, scoped keys, audited severity recasts and dispositions, branch history, and filtered exports sit beside the findings. |
| Actionable context | A finding carries file/line, a scanned-commit source link when available, a suggested fix, and a curated public remediation reference. The text is guidance; it does not prove exploitability or automatically modify code. |

Other SAST/SCA platforms may offer overlapping features. PANBOX's alpha scanner is lexical, lacks cross-function taint analysis, and has no measured false-positive rate or production-scale benchmark. Evaluate detection quality on your own representative repositories before replacing an existing control.

## 2. Choose your setup path

- **Server operator, once:** Docker Engine/Desktop with Linux containers and Compose v2. Start with section 3 on Debian/Linux/macOS or section 4 on Windows. Debian is the initial production target.
- **DevOps, per repository:** enroll a repository, create one API key with `scans:write`, set CI secrets, and run section 6. The runner needs outbound HTTPS to GitHub Releases and the advisory API, plus a route to the private PANBOX API.
- **No public IP/domain:** choose a route in section 7 before writing the CI job.

PANBOX binds HTTP `8080` and PostgreSQL `5434` to host loopback by default. Change `PANBOX_HOST_PORT` or `PANBOX_DB_HOST_PORT` in `.env` if needed. Keep PostgreSQL private.

## 3. Start the dashboard on Debian/Linux/macOS

**Goal:** bring up the private API and UI once. Run on the server host:

```bash
git clone https://github.com/alterwriter/PANBOX.git
cd PANBOX
sh scripts/init-local.sh
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
curl -fsS http://127.0.0.1:8080/readyz
```

**Expected:** `/readyz` succeeds. Open `http://127.0.0.1:8080` on the server and sign in with `PANBOX_BOOTSTRAP_EMAIL` and `PANBOX_BOOTSTRAP_PASSWORD` from the ignored `.env`. The initializer creates secrets with restricted permissions and refuses to overwrite an existing `.env`. Bootstrap credentials apply only when the database is first initialized; retain its volume on routine restarts.

**Optional demo:** `PANBOX_SERVER=http://127.0.0.1:8080 bash scripts/seed-demo.sh` needs `curl` and `jq`, then prompts for the admin password. Demo findings are synthetic.

## 4. Start the dashboard on Windows

**Goal:** run the same Linux containers through Docker Desktop. In PowerShell:

```powershell
git clone https://github.com/alterwriter/PANBOX.git
cd PANBOX
./scripts/init-local.ps1
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
Invoke-RestMethod http://127.0.0.1:8080/readyz
```

**Expected:** the same dashboard and API as section 3. Use `./scripts/seed-demo.ps1` only for optional demo data. Run one initializer for a new `.env`, not both.

### Server variables and dashboard upgrades

| Server `.env` variable | Required | Purpose |
|---|---:|---|
| `PANBOX_DB_PASSWORD` | Yes | Strong random PostgreSQL password. |
| `PANBOX_BOOTSTRAP_EMAIL` / `PANBOX_BOOTSTRAP_PASSWORD` | Yes | Initial admin; password is used only when the database is first created. |
| `PANBOX_SECURE_COOKIE` | Production | Set `true` when the dashboard uses HTTPS. |
| `PANBOX_HOST_PORT` / `PANBOX_DB_HOST_PORT` | No | Host ports; defaults `8080` / `5434`, bound to loopback. |
| `PANBOX_SCM_ALLOWED_HOSTS` | Optional | Comma-separated HTTPS origins allowed for self-hosted SCM metadata checks. |
| `PANBOX_SCM_ENCRYPTION_KEY` | Private SCM integration | 64 random hex characters; encrypts GitLab/GitHub credentials in PostgreSQL. Generated by new local initializers. Back it up with the database. |

**Upgrade on Debian/Linux:** back up the database and record the current commit, then rebuild from `main`. Run in the PANBOX clone:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml exec -T db pg_dump -U panbox panbox > "panbox-db-$(date -u +%Y%m%dT%H%M%SZ).sql"
git rev-parse HEAD > .panbox-previous-version
git pull --ff-only origin main
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
curl -fsS http://127.0.0.1:8080/readyz
```

Database migrations run when the new server starts. Keep the backup before upgrading; for a schema-changing rollback, restore the database backup together with the previous code version. Never run `docker compose down -v` during an upgrade.

## 5. Manage GitHub and GitLab SCM connections

**Purpose:** an SCM connection lets the PANBOX server read permitted repository metadata, including private repositories and default branches. The dashboard does not clone source, trigger a pipeline, or use this credential to upload scans. The CI runner performs checkout and scanning, then uploads with its own `PANBOX_API_KEY` and `PANBOX_REPOSITORY_ID`.

**Before connecting:** keep `PANBOX_SCM_ENCRYPTION_KEY` stable in the server `.env` (new installs create one; existing installs can generate `openssl rand -hex 32`). Back it up with PostgreSQL. The PANBOX host needs outbound HTTPS to the SCM. For GitLab self-managed or GitHub Enterprise, allowlist the exact host in `PANBOX_SCM_ALLOWED_HOSTS` and enter its HTTPS origin; leave origin blank for public GitHub/GitLab cloud. No PANBOX public IP or webhook is required.

| Provider | Prepare in the SCM | Enter in PANBOX |
|---|---|---|
| GitLab | Create a [service account](https://docs.gitlab.com/user/profile/service_accounts/) with access to the target group/projects and a token with [`read_api`](https://docs.gitlab.com/security/tokens/access_token_scopes/). | Select **GitLab service account**, enter a label and token, and choose cloud or the allowed self-managed HTTPS origin. |
| GitHub | Create a [GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation), grant repository **Metadata: read**, install it only on the intended repositories, and download its private key. | Select **GitHub App**, enter the App ID, installation ID, PEM private key, label, and optional allowed Enterprise origin. |

1. Sign in as Admin and open **Settings & Audit → GitHub & GitLab connections → Manage SCM connections**. Click **Connect GitHub or GitLab**. This button **opens the new-connection form**; it does not connect or import anything until you submit it.
2. Set **Connection enabled** to allow reads. Set **Automatically enroll** only if all repositories visible to this credential should become PANBOX projects. Click **Connect, test and discover**. PANBOX tests the credential, saves it encrypted, reads up to 500 permitted repository entries, and imports them only when auto-enroll is on.
3. In **Repositories**, copy each imported PANBOX project ID to CI variable `PANBOX_REPOSITORY_ID`. Create a separate PANBOX API key with `scans:write` as `PANBOX_API_KEY`. Check runner-to-PANBOX connectivity before the first scan; the SCM test checks the **server-to-SCM** route only.

| Button | What it does |
|---|---|
| **Edit** | Opens the selected connection form; change its label, status, auto-enroll, or replace credentials. Save tests access again. |
| **Discover** | Reads currently visible repositories and shows enrolled, ready, or excluded state. It does not import when auto-enroll is off. |
| **Sync** | Refreshes metadata and imports newly visible repositories when auto-enroll is enabled. It does not start a CI scan. |
| **Disable / Enable** | Stops or resumes metadata access and future sync for that connection; existing PANBOX projects and scan history remain. |
| **Delete** | Removes the stored SCM connection; enrolled projects and scan history remain. |
| **Allow reimport** | Clears an imported repository's exclusion after deliberate removal; use **Sync** to import it again. |

Keep the SCM credential limited to the repositories you intend to discover. If access testing fails, check token/App permissions, installation scope, outbound HTTPS, and the exact allowed self-hosted hostname. The connection screen reports these failures before saving.

## 6. Add only the agent to CI

| CI variable | Store as | Purpose |
|---|---|---|
| `PANBOX_SERVER` | Variable | Dashboard URL reachable by the runner, preferably HTTPS. |
| `PANBOX_REPOSITORY_ID` | Variable | Internal PANBOX project ID from the repository page; not the SCM project ID. |
| `PANBOX_API_KEY` | Masked/protected secret | PANBOX API key scoped to `scans:write`; no repository token is needed. |
| `PANBOX_VERSION` | Variable | Pinned agent release tag, for example `v0.1.0-alpha.12`. |
| `PANBOX_MODULES` | Optional variable | Modules passed to the agent; defaults to `vaccin,enetron` in the GitLab example. Use `vaccin` when you intentionally want SAST only. |
| `PANBOX_DEFAULT_BRANCH` | Optional | Set when the CI provider does not supply default-branch metadata. |

**Onboarding model:** A connected GitLab service account or GitHub App can enroll permitted private repositories automatically; manual enrollment remains available. Each PANBOX project ID routes uploads but is not a secret. One API key with `scans:write` authenticates policy fetch and upload. CI's checkout credentials fetch source, while PANBOX receives only normalized results.

**Once per repository, before changing the pipeline:**

1. Sign in as an admin or a user with `repos:write`, then open **Repositories -> Enroll repository**. Select GitHub, GitLab, Bitbucket, Azure Repos, Gitea, or Other Git.
2. Enter **name** (display label, for example `PANBOX`) and **SCM repository ID or path** (for example `alterwriter/PANBOX`; GitLab may use `group/subgroup/project`). Select **Test SCM connectivity and detect branch**. Public metadata from GitHub, GitLab, Bitbucket, Azure Repos, or an operator-allowed Gitea host fills **default branch** automatically. **Owner** may be blank; it is display metadata, not RBAC or scan authorization. Display name, SCM path, and internal PANBOX ID are three different values.
3. Read the result before selecting **Enroll repository**. **Verified metadata** means the PANBOX host read the default branch, including a private GitLab/GitHub repository when an SCM connection has access. **Waiting for CI** means no usable connection or unreachable metadata; keep **Auto-detect** selected. The first authenticated CI upload can supply the true default branch, even when it scans a feature branch. PANBOX never guesses the first scanned branch is default. For self-hosted Git, add the exact HTTPS host to `PANBOX_SCM_ALLOWED_HOSTS`. Copy **PANBOX ID for CI** to `PANBOX_REPOSITORY_ID`; this internal ID differs from the SCM path or GitLab project ID.
4. Select **Create CI API key**. The admin/key manager needs `tokens:manage`, `scans:write`, and project access. Keep `scans:write`, optionally scope the key to this PANBOX project, and save the one-time secret as protected CI secret `PANBOX_API_KEY`. No separate repository token is needed. The key owner still needs project membership unless admin.
5. Open the row's **Scan policy**: enable scans, select VACCIN/ENETRON, and set the gate threshold. Set `PANBOX_SERVER` in CI to the API URL reachable from the runner, such as PANBOX's LAN address. `127.0.0.1` works only when runner and server share a host. Never put an API key in repository files or untrusted pull request jobs.
6. From the runner using its CI checkout credentials, verify checkout succeeded (`git rev-parse --is-inside-work-tree`), then check dashboard reachability, key, and ID with the commands below. The dashboard metadata check in step 2 does not prove either runner path. Once both succeed, run the agent job below. The first complete scan appears in **Scans**, with its findings in **Findings**.

```bash
curl -fsS "$PANBOX_SERVER/readyz"
curl -fsS -H "Authorization: Bearer $PANBOX_API_KEY" \
  "$PANBOX_SERVER/v1/repos/$PANBOX_REPOSITORY_ID/scan-config"
```

**Branches after enrollment:** every job reports its checkout branch, so a feature branch appears separately once CI runs PANBOX there. GitLab `CI_DEFAULT_BRANCH` and the GitHub template's `PANBOX_DEFAULT_BRANCH` report the actual default even from a feature branch. Other CI systems can set `PANBOX_DEFAULT_BRANCH` or use `--default-branch`. Without this metadata, default stays pending. The supplied GitLab job runs on protected branches; extend CI rules for others. Overview uses the default branch baseline. **Recheck SCM** refreshes auto-detected metadata.

**Fix a wrong enrollment:** click a repository row to open details. **Edit** changes display name, owner, and default branch; select **Manual override** when needed. Choose **Self-hosted / enterprise** and enter an HTTPS origin for GitHub Enterprise or GitLab self-managed; allowlist its exact host in `PANBOX_SCM_ALLOWED_HOSTS`. SCM identity can be edited until the first scan, then it is locked to preserve finding history. Admin **Pause/Resume** toggles new scans. Admin **Remove** deletes an unscanned repository or archives a scanned one and revokes project-bound keys. Imported repositories stay excluded from later sync; **Allow reimport** reverses that choice. Admin can **Restore** and use an API key with project access. A missing owner is safe: it never grants permission.

**Custom native VACCIN rule:** commit `.panbox/rules.json` to the scanned repository. PANBOX reads it on the runner before scanning, alongside built-in rules; an invalid file fails the VACCIN module rather than silently passing. Example:

```json
{"rules":[{"id":"custom.team.unsafe-call","severity":"medium","message":"Unsafe call needs review","pattern":"unsafeCall\\(","extensions":[".js"]}]}
```

The JSON pattern above represents regex `unsafeCall\(`. IDs start with `custom.`; supported extensions are `.py`, `.pyw`, `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`, `.go`, `.java`, `.jsp`, `.php`, and `.phtml`. Limit: 64 rules, 256 characters per pattern, 64 KiB file. Regexes can span lines after lexical comment/string stripping; they are not AST or taint analysis. Keep the rule file under normal code review and test changes on representative repos. See the [complete alpha detection coverage](detection-coverage.md) for built-in rule families and SCA manifest limits.

**Every Linux/macOS job:** download the pinned installer from [PANBOX release v0.1.0-alpha.12](https://github.com/alterwriter/PANBOX/releases/tag/v0.1.0-alpha.12). It selects OS/CPU, downloads just the binary, checks [SHA256SUMS](https://github.com/alterwriter/PANBOX/releases/download/v0.1.0-alpha.12/SHA256SUMS), and installs in the job workspace without sudo:

```bash
PANBOX_VERSION=v0.1.0-alpha.12
curl -fsSL "https://github.com/alterwriter/PANBOX/releases/download/${PANBOX_VERSION}/install-agent.sh" -o install-panbox-agent.sh
sh install-panbox-agent.sh "$PANBOX_VERSION" .panbox/bin
.panbox/bin/panbox version
.panbox/bin/panbox go --server "$PANBOX_SERVER" --repo "$PANBOX_REPOSITORY_ID" --path .
```

**Expected:** exit `0` complete/pass; `1` gate failure; `2` incomplete/transport/config error; `3` rejected auth/permission. Copy the [GitHub Actions job](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/deploy/github-actions-local-runner.yml) or [GitLab CI job](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/deploy/gitlab-ci-local-runner.yml). On Windows, download [install-agent.ps1](https://github.com/alterwriter/PANBOX/releases/download/v0.1.0-alpha.12/install-agent.ps1) and run `./install-agent.ps1 -Version v0.1.0-alpha.12`; it installs `./.panbox/bin/panbox.exe` after checksum verification. [Direct agent-only binaries](https://github.com/alterwriter/PANBOX/releases/tag/v0.1.0-alpha.12) are also available.

**Keep CI usage low:** add one PANBOX invocation to an existing protected build job after checkout; do not create a second scan/analysis job if shared-runner minutes are limited. PANBOX reads source and dependency manifests from that checkout. It does not scan the built container image. If no supported manifest exists, ENETRON reports `skipped` and VACCIN can still complete. Use `--modules vaccin` only when you intend to run SAST alone.

VACCIN provides first-party lexical rules for the five supported language families; see the [coverage matrix](detection-coverage.md) for check families and limitations. ENETRON reads npm v1/v2/v3, pnpm, Yarn, Bun JSON locks; Python requirements/Pipfile/Poetry/uv/PDM locks; Go `go.mod`/`go.sum`; Maven `pom.xml`; Gradle `gradle.lockfile`; and PHP `composer.lock`. Maven only reads explicit or locally managed versions, not properties/BOM/parent inheritance. It sends package coordinates and versions to OSV advisory data; OSV supplies data, not scanner execution. Queries are batched and paginated. `PANBOX_ADVISORY_URL` or `--advisory-url` selects an approved OSV-compatible mirror. If no supported dependency manifest exists, ENETRON is recorded as `skipped` and a completed VACCIN scan can still pass; malformed manifests or manifests with no pinned versions remain errors. Feature branches are supported; `baseline unknown` is normal until PANBOX has a prior scan for that branch/base.

**CI-to-dashboard sequence:** (1) the runner downloads the pinned agent; (2) `panbox go` authenticates `GET /v1/repos/{id}/scan-config` with the CI API key; (3) the agent scans enabled modules in the checkout; (4) it posts one normalized JSON bundle to `POST /v1/scans` with `Authorization: Bearer $PANBOX_API_KEY`; (5) the API stores the snapshot and returns the gate verdict; (6) the agent exits 0 (pass), 1 (gate fail), 2 (incomplete/transport), or 3 (auth). There is no separate upload setup. Verify the policy from the runner with `curl -fsS -H "Authorization: Bearer $PANBOX_API_KEY" "$PANBOX_SERVER/v1/repos/$PANBOX_REPOSITORY_ID/scan-config"`.

## 7. Reach private PANBOX from public SCM

- **Local protected runner (recommended):** polls any SCM over outbound HTTPS and posts to PANBOX on its LAN. No public PANBOX port; synchronous gate. Use the [GitHub](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/deploy/github-actions-local-runner.yml) or [GitLab](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/deploy/gitlab-ci-local-runner.yml) example.
- **SSH relay:** PANBOX opens an outbound reverse tunnel to a reachable relay; a shared runner opens a forward tunnel. No PANBOX inbound internet port; synchronous gate. Pin host keys and restrict identities. See the [GitLab relay example](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/deploy/gitlab-ci-ssh-relay.yml).
- **Artifact import:** CI writes `panbox-results.json`; a private host fetches and imports it later. No inbound route or relay; the later gate cannot block that CI job. [GitLab artifact example](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/deploy/gitlab-ci-pull-artifact.yml) and `panbox relay-pull` automate GitLab; other SCMs need their artifact download step before generic `panbox go --bundle` import.

**Check:** from a synchronous runner, `curl -fsS "$PANBOX_SERVER/readyz"` must work. A public repository does not make its CI artifacts public.

## 8. Give people only needed access

**Admin setup:** Settings & Audit -> RBAC -> create a role with explicit permissions -> assign users -> grant repository membership. `admin` is the highest immutable role. Built-in roles include `security_reviewer`, `developer`, `executive_viewer`, and `scanner_ci`; custom roles cannot receive `rbac:manage`.

**Check:** data access needs both permission and repository membership. Pilot permissions are `repos:read`, `repos:write`, `scans:read`, `scans:write`, `findings:read`, `findings:recast`, `reports:export`, `rbac:manage`, `tokens:manage`, and `audit:read`.

## 9. Manage API and access keys

**Where:** Settings & Audit -> API & access keys. Choose label, type, expiry, scopes, and repository when applicable. API keys carry selected integration scopes; access keys are read-only; CI API keys use `scans:write` and optional project scope. Copy the one-time secret into a secret manager. Keys are hashed at rest, expiring, and revocable.

**Read-only smoke test:**

```bash
curl -H "Authorization: Bearer $PANBOX_ACCESS_KEY" "$PANBOX_SERVER/v1/repos"
```

Browser login uses password, HttpOnly session cookie, and CSRF token. The [OpenAPI contract](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.12/api/openapi.yaml) lists pilot endpoints. Use **Rotate** to issue a replacement and revoke the old key atomically; update the CI secret before its next job.

**Revoked key cleanup:** active keys are listed first. Enable **Show revoked keys** to inspect disabled records. Admin can **Delete** a revoked record after confirmation; the credential disappears from the list while its ID and actions remain in the audit log. Active credentials cannot be deleted before revocation.

**Codex MCP from start to finish:** on the workstation running Codex, install the matching `panbox` binary, then verify `curl -fsS "$PANBOX_SERVER/readyz"`. In the dashboard create a read-only Access key with `repos:read`, `scans:read`, and `findings:read`; copy its one-time secret to that workstation's private environment as `PANBOX_TOKEN`. Run `codex login` there, select ChatGPT, and verify `codex login status` as the same OS user. Configure `~/.codex/config.toml` with `[mcp_servers.panbox]`, `command = "/absolute/path/to/panbox"`, `args = ["mcp"]`, and `PANBOX_SERVER`/`PANBOX_TOKEN` under `[mcp_servers.panbox.env]`. Restart Codex, run `codex mcp list`, and ask it to list PANBOX repositories. The dashboard has no Codex login button and cannot see the interactive client's auth status. For network, key, and permission errors see the [full English MCP guide](https://boxsploit.com/products/panbox/#mcp-codex). Automatic reviews require the separate worker on the PANBOX host; see [AI review setup](ai-review.md).

**Plugin route:** set the same protected `PANBOX_SERVER` and `PANBOX_TOKEN` on the Codex workstation, with `panbox` on `PATH`. Run `codex plugin marketplace add alterwriter/PANBOX --ref v0.1.0-alpha.12`, open Codex `/plugins`, choose **PANBOX Local → PANBOX → Install**, start a new session, and verify with `/mcp`. In ChatGPT desktop, the same bridge can be configured directly under **Settings → MCP servers → Add server → STDIO** using `panbox mcp`. ChatGPT web cannot start a local STDIO process. Neither path starts the automatic host worker.

## 10. Confirm and control scans in the dashboard

**Dashboard rows and time:** Repositories, Findings, Scans, and the Overview repository table show 10 rows per page with Previous/Next controls. The Repositories table and repository detail show **Latest scan** from any branch; Overview posture remains based on the latest complete default-branch snapshot. The Scans page shows the newest 100 scans returned by the pilot API, and Findings shows up to 1,000 current/historical rows after filters. Use repository and branch filters for a narrower view; exports are separate from the table window.

**Source and remediation:** A VACCIN finding displays its repository-relative path and line. When SCM identity and commit are valid, **Open source** leads to that exact scanned commit and line. Its detail shows rule-specific or family-level fix advice plus a curated public OWASP or Django reference URL; an ENETRON finding links to its OSV advisory. PANBOX does not send source code to those documentation sites or claim that the link proves exploitability. The copyable fix prompt is local text, not an automatic AI fix.

**CI log:** the default text output prints release/branch/commit, gate verdict, module status, severity counts, up to 10 highest-severity finding locations, and the dashboard URL. On GitLab, the finding list is collapsible in the job log; when SCM metadata is available, each location has a clickable commit-pinned source URL. JSON and SARIF output formats remain machine-readable. Exit codes still distinguish pass (`0`), gate fail (`1`), incomplete (`2`), and authorization (`3`).

**Investigate and triage:** click a repository row for its details and direct **View findings / View scans** actions. Click a scan to see its findings, then click a finding for its path, line, source URL when a safe commit link can be formed, advisory, remediation guidance, and the last 100 eligible complete scans on that branch. An absent finding on a later complete scan of its module appears as **resolved**; earlier history remains visible. **Recast severity** changes effective severity with an audited reason. **Triage** can mark false positive, accepted risk, closed, or reopen, also with a reason; these statuses revise affected gates and remove the finding from active posture counts while retaining it in history and reports. Closure is manual and persists until reopened. The remediation prompt button copies a local template; it does not call AI or modify source. The read-only MCP bridge can supply findings to a client, but the client controls any AI use. No false-positive percentage has been measured for this pilot.

The finding panel now separates source location, scan history, suggested remediation, and triage. Choose a disposition explicitly and enter a 10–500 character reason before saving. Guidance is rule-specific for common Django configuration, SQL, CSRF, template output, redirects, and credentials, with a general review checklist for other rules. These suggestions are not proof of exploitability. For Django applications, the current agent checks `.py` files and HTML files under `templates/`; known bundled JavaScript under `static/` or `assets/` is skipped to reduce noise. See [detection coverage](detection-coverage.md) before presenting scan results.

**Recast:** open **Findings**, clear filters if no rows appear, then select **Recast severity** beside a finding rule (the first column). Choose an effective severity or restore the scanner value -> enter a reason (10-500 characters) -> Save. The button appears only with `findings:recast` and repository access; an admin or `security_reviewer` with repository membership can use it. If no rows appear, complete the first scan or check filters. If rows appear without the button, ask an admin to check role and membership under **Settings & Audit -> RBAC**. Raw severity never changes. The API exposes history at `GET /v1/findings/{id}/recasts`; affected historic gate revisions are recalculated against each scan's original threshold. Recast is not an approval or dismissal.

**Export:** Reports -> choose repository, exact branch, scan module (VACCIN/ENETRON), and optional severity -> Export PDF, CSV, or JSON. Data comes from the latest complete scan per branch. PDF is a readable technical summary; CSV/JSON retain full rows. Requires `reports:export`.

**MCP:** Settings & Audit -> API & access keys -> create a read-only Access key with `repos:read`, `scans:read`, and `findings:read`. Open Settings & Audit -> MCP setup and use its generic stdio host configuration. The MCP host launches `panbox mcp` with `PANBOX_SERVER` and `PANBOX_TOKEN` in its secret environment. Four read-only tools list repositories, findings, scans, and scan detail. There is no public MCP endpoint.


**After CI:** Overview shows coverage and severity; Repositories shows enrolled projects; Scans shows run/gate status; Findings filters by repository/branch/module/severity; Reports exports filtered technical PDF/CSV/JSON; Settings & Audit shows RBAC, keys, and audit events. Light and dark themes are available.

**Interpretation:** a partial scan is unverified and preserves the last successful posture. ARK labels Critical/High and BUG-STER labels Medium/Low while standard severities remain stored and exported. Recast actions and changes to scan policy are audited.

## 11. Operate within the pilot boundary

Keep PostgreSQL on loopback. For remote browser access, use an HTTPS reverse proxy with access control or a private route; set `PANBOX_SECURE_COOKIE=true` for HTTPS. Back up PostgreSQL and test restoration.

The 2 GB Debian host is a **target to validate**, not a guarantee. A small Windows Docker Desktop fixture measured about 5.1 MiB server RAM and 37.3 MiB PostgreSQL RAM; 100 sequential API calls measured 7.1 ms median and 9.3 ms p95. The agent runs on the runner and needs separate sizing. Measure `docker stats --no-stream` with representative repositories and scan bundles.

## 12. Troubleshoot by failed step

- **Dashboard not ready:** run `docker compose --env-file .env -f deploy/docker-compose.yml ps` and `logs db server`; confirm PostgreSQL health.
- **Agent download fails:** check release tag, OS/CPU asset name, outbound GitHub access, `curl`, and SHA-256 tooling. Do not skip the checksum.
- **Runner cannot reach PANBOX:** `127.0.0.1` inside a container is that container; use its reachable private host/network address or the SSH relay.
- **Exit 2:** check manifest, advisory endpoint, work path, PANBOX endpoint, and logs; incomplete is not pass.
- **ENETRON skipped:** the repository has no supported dependency manifest; VACCIN can still complete. Add the ecosystem lockfile to enable SCA. Check `panbox version` to confirm the CI job is using the pinned release.
- **ENETRON error:** a supported manifest is malformed or has no pinned/resolved versions, or advisory lookup failed. Fix/commit the lockfile or network access; the scan stays unverified.
- **Exit 3:** check API key expiry/revocation, `scans:write`, internal repository ID, role, and membership.
- **Artifact import is late:** check timer, `GITLAB_READ_TOKEN`, allowed refs, Jobs API/artifact access, and relay state file.

## 13. Know the alpha limits

Available now: server/UI, native VACCIN source checks, native ENETRON pinned dependency matching with OSV data, repository/branch snapshots, gate, RBAC, scoped keys, audit, filtered PDF/CSV/JSON exports, and the transport examples above. Validate real runners, OSV access or approved mirror, Debian load, backup/restore, TLS, and key rotation in your environment.

Coverage is intentionally narrow. RIDER secrets, TESLA IaC, approval workflows, executive PDF report templates, independent AI vulnerability discovery, OIDC, and API rate limiting are roadmap items. This online guide describes the pilot; PANBOX vulnerability reports are exported separately from the dashboard.

## 14. Review findings with AI on the PANBOX server

**Flow:** CI runs the native VACCIN/ENETRON agent and uploads a normal scan. PANBOX returns the gate immediately. If Admin enabled AI review, PANBOX reads small source windows at the exact scan commit through its GitHub/GitLab connection. Choose an optional Codex CLI worker on the trusted PANBOX host using a ChatGPT login, or the separately billed OpenAI/Anthropic API route. Both store separate advisory assessments and sanitized stage logs. CI does not run AI or wait for it.

**Server variables:**

| Variable | Where | Purpose |
|---|---|---|
| `PANBOX_OPENAI_API_KEY` | PANBOX server `.env`/secret manager | OpenAI coding model API key; only when selecting OpenAI. |
| `PANBOX_ANTHROPIC_API_KEY` | PANBOX server `.env`/secret manager | Claude API key; only when selecting Anthropic. |
| `PANBOX_SCM_ENCRYPTION_KEY` | PANBOX server | Encrypts connected GitHub/GitLab credentials already used for repository discovery. |
| `DATABASE_URL` | Codex host worker only | Connects to PANBOX PostgreSQL over loopback (Compose defaults to port 5434). |
| `PANBOX_MIGRATIONS_DIR` | Codex host worker only | Absolute path to this checkout's `migrations` directory. |
| `CODEX_HOME` | Codex host worker only | Optional dedicated Codex profile containing a ChatGPT login. |

**Setup:** grant the GitHub App `Metadata: read` and `Contents: read`, or grant the GitLab service account `read_api` on permitted projects. For the Codex route, install the `panbox-ai-worker` release binary and Codex CLI on the PANBOX host, then start the worker with the tabled private environment. As its dedicated OS user, run `codex login --device-auth`, open the printed URL in your browser, enter the one-time code, and confirm `codex login status` reports ChatGPT login. The worker can be online while login is required; it waits before processing queued runs. Open **Settings & Audit → Server-side AI review → Configure and view runs**, confirm **worker online** and **ChatGPT login ready**, select **Codex CLI · ChatGPT login**, set 1–10 findings per scan (default 3), and enable. Model ID is optional for Codex. A dashboard redirect alone cannot authenticate the host CLI. No OpenAI or Anthropic API key is required. For the separately billed API route, set the relevant provider key and model ID on the dashboard server. For an older scan, use **Scans → scan detail → Queue AI review on server**. See the [exact worker steps](ai-review.md#codex-plan-route-no-provider-api-key).

**Inspect:** Findings rows show AI evaluation state; open a finding to see **not requested**, **queued**, **reviewing**, **reviewed**, **not reviewed**, **review failed**, **not eligible**, or **not in latest scan**, plus verdict, confidence, evidence, and suggested fix when reviewed. Historical list rows are marked separately. The Admin panel shows queued/running/completed/partial/failed runs and process events, including missing source permission. Only Critical/High/Medium VACCIN findings with source paths and lines are eligible, highest severity first. AI suggestions cannot auto-close findings, recast severity, or change gates; apply those actions manually with an audited reason. This is a review of existing scanner findings, not independent AI SAST discovery or a measured false-positive rate. Read [AI review design and limits](ai-review.md).

**Codex plugin / MCP:** the [local Codex plugin](../plugins/panbox/plugin.json) wraps the existing read-only `panbox mcp` stdio bridge for interactive inspection with a scoped Access key. Plugin installation alone does not trigger automatic review; the separate Codex host worker does. Codex review consumes the account's Codex plan allowance or applicable credits, while provider API routes are billed separately. Neither route needs additional CI variables.
