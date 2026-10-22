# PANBOX MCP with Codex CLI (beta)

**Verified setup:** PANBOX agent `v0.1.0-alpha.12` and Codex CLI `0.163.0` on a Debian PANBOX host. The four read-only MCP tools were discovered, and `panbox_repositories` returned the repository allowed by a scoped Access key. The stdio bridge follows MCP, but other clients have not been validated in this pilot.

```text
Codex CLI → PANBOX plugin → local `panbox mcp` → HTTPS PANBOX API → repository/scan/finding data
```

This is interactive inspection. It does not start a scan or the optional server-side AI reviewer. For automatic review, see [AI review](ai-review.md): CI uploads findings, the separate `panbox-ai-worker` reads source through a GitHub/GitLab connection, and its own Codex CLI login reviews eligible findings. The worker uses no MCP Access key. A successful MCP connection does not mean the worker can read source.

## What failed on the tested host

The PANBOX Codex plugin was installed, but its `mcp.json` only starts `panbox mcp`. In the Codex OS user's process, `panbox` was absent from `PATH`, and `PANBOX_SERVER` and `PANBOX_TOKEN` were unset. The plugin therefore showed `panbox: failed (0 tools)`. We installed the checksum-verified release agent, created a read-only PANBOX Access key scoped to one repository, stored it in an owner-only file, and placed a small launcher named `panbox` on Codex's `PATH`. A direct MCP tool call then succeeded. The active Codex session must be restarted to rediscover the bridge.

## Set up on Linux or macOS

Run these on the **same machine and OS account** that starts Codex. On the tested Debian host that account was `root`; use your own account's `$HOME` elsewhere.

1. Check the dashboard from this host. Replace the URL with your PANBOX URL; loopback only works when Codex and PANBOX are on the same host.

   ```sh
   curl -fsS https://your-panbox.example/readyz
   ```

   Expect `{"status":"ready"}`.

2. Install the matching PANBOX agent from its pinned release. The installer verifies the binary against the release `SHA256SUMS` before installing. It does not install Codex CLI or the AI worker.

   ```sh
   curl -fsSL https://github.com/alterwriter/PANBOX/releases/download/v0.1.0-alpha.12/install-agent.sh -o /tmp/install-panbox-agent.sh
   sh /tmp/install-panbox-agent.sh v0.1.0-alpha.12 "$HOME/.local/libexec/panbox-agent"
   "$HOME/.local/libexec/panbox-agent/panbox" --version
   ```

3. In **Settings & Audit → API & access keys**, create an **Access key**, not a CI scan key. Grant exactly `repos:read`, `scans:read`, and `findings:read`; choose one PANBOX repository for a scoped setup. Copy the secret once. Keep that OS account's key owner as a repository member. Create `~/.config/panbox/mcp.json` with a local editor:

   ```sh
   install -d -m 0700 "$HOME/.config/panbox" "$HOME/.local/bin"
   ${EDITOR:-vi} "$HOME/.config/panbox/mcp.json"
   chmod 0600 "$HOME/.config/panbox/mcp.json"
   ```

   File content (replace both placeholders privately; do not paste the real key into shell history, Codex config, Git, or chat):

   ```json
   {"PANBOX_SERVER":"https://your-panbox.example","PANBOX_TOKEN":"<read-only-access-key>"}
   ```

4. Create `~/.local/bin/panbox` with this launcher and make it executable. It loads the private JSON file and executes the verified agent without putting the key in the plugin's `mcp.json`:

   ```python
   #!/usr/bin/env python3
   import json
   import os
   import sys
   from pathlib import Path

   home = Path.home()
   settings = json.loads((home / ".config/panbox/mcp.json").read_text())
   agent = home / ".local/libexec/panbox-agent/panbox"
   env = os.environ.copy()
   env["PANBOX_SERVER"] = settings["PANBOX_SERVER"]
   env["PANBOX_TOKEN"] = settings["PANBOX_TOKEN"]
   os.execve(str(agent), [str(agent), *sys.argv[1:]], env)
   ```

   ```sh
   chmod 0700 "$HOME/.local/bin/panbox"
   export PATH="$HOME/.local/bin:$PATH"
   command -v panbox
   panbox --version
   ```

   Ensure the **Codex process** also has this directory on `PATH`, then start a new Codex session. A running process does not inherit later shell changes. If using manual Codex MCP configuration instead of the plugin, set its command to the absolute launcher path and args to `["mcp"]`.

5. Install the [PANBOX plugin](../plugins/panbox/plugin.json) in Codex CLI, if it is not already installed:

   ```sh
   codex plugin marketplace add alterwriter/PANBOX --ref v0.1.0-alpha.12
   ```

   Open Codex `/plugins`, select **PANBOX Local → PANBOX → Install**, and start a **new** Codex session. `codex mcp list` should show `panbox` enabled; `/mcp` should show four tools. `codex login status` checks this Codex user's ChatGPT login. It is separate from `PANBOX_TOKEN` and from the worker user's login.

6. Test the bridge before relying on the Codex UI:

   ```sh
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"panbox_repositories","arguments":{}}}' | panbox mcp
   ```

   The JSON result should include the repository visible to the key. Then ask Codex to list PANBOX repositories and the latest scan. PANBOX exposes `panbox_repositories`, `panbox_findings`, `panbox_scans`, and `panbox_scan`. They cannot write findings, change severity, or initiate scans.

## If it still shows `failed (0 tools)`

| Check | What to do |
|---|---|
| Plugin present, command missing | Run `command -v panbox` as the Codex OS user. Confirm the Codex process `PATH` contains the launcher's directory. |
| Server or key missing | Confirm `mcp.json` exists, is valid JSON, and is readable only by that user. Check `/readyz` from the Codex host. |
| `401` from the API | Rotate an expired or revoked PANBOX Access key and update the private JSON file. |
| `403` or empty list | Check the three read scopes, repository scope, and key owner's repository membership. The repo must be enrolled. |
| Direct tool call works, `/mcp` fails | Start a fresh Codex session; use `/mcp verbose` for the process error. Do not restart the PANBOX dashboard for a local MCP launcher change. |

For `django.nv`, the tested bridge listed its already enrolled PANBOX repository. Automatic AI source review still requires a GitHub App connection with `Contents: read` linked to that repository; see [SCM setup](product-guide-en.md#5-manage-github-and-gitlab-scm-connections). Keep the App's PEM private key out of the MCP file.
