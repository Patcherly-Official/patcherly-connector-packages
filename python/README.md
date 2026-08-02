<div align="center">

<a href="https://patcherly.com"><img src="https://patcherly.com/assets/img/logo_patcherly_light.png" alt="Patcherly" width="240" /></a>

# Patcherly Python connector

**Auto-detect and fix production errors in your Python apps.**
Agent for any framework that logs to a file or stdout — pairs with your Patcherly account.

[![PyPI patcherly-connector](https://img.shields.io/pypi/v/patcherly-connector?label=Python&logo=pypi&logoColor=white&style=flat-square)](https://pypi.org/project/patcherly-connector/)
[![Documentation](https://img.shields.io/badge/Documentation-help.patcherly.com-1869f5?style=flat-square)](https://help.patcherly.com/connectors/python/)
[![Discord — join](https://img.shields.io/badge/Discord-join-5865f2?logo=discord&logoColor=white&style=flat-square)](https://discord.gg/7yZkD9KNsS)

> Prefer unpinned `pip install`, or pin from [GitHub Releases](https://github.com/Patcherly-Official/patcherly-connector-packages/releases/latest).

</div>

---

## Recommended install (universal installer)

One command downloads the Python agent and launches OAuth pairing:

| Platform | Command |
|----------|---------|
| macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/install \| sudo CONNECTOR_TYPE=python bash` |
| Windows PowerShell | `$env:CONNECTOR_TYPE = 'python'; irm "https://api.patcherly.com/install.ps1" \| iex` |

The CLI prints a **verification URL** and a short **user code** — open the URL, sign in, pick your target, and confirm. Credentials are saved to `~/.patcherly/credentials.json` (or `/root/.patcherly/` when run as root). Then start the agent — see [After install](#after-install).

Full installer options (paths, `SKIP_LOGIN`, older versions): [Installing a connector](https://help.patcherly.com/getting-started/installing-connector/).

## Package install (PyPI)

```bash
pip install patcherly-connector
patcherly login
```

With the release-tree / universal-installer layout, start the agent:

```bash
python patcherly_agent.py
```

Or from your app (credentials from `~/.patcherly/credentials.json`):

```python
from patcherly_agent import PatcherlyAgent

agent = PatcherlyAgent(log_file="logs/error.log")
await agent.start()
```

Optional on quiet hosts: `patcherly heartbeat` from a daily cron / systemd timer — see the [Python guide](https://help.patcherly.com/connectors/python/#keep-the-connection-alive-on-quiet-hosts-patcherly-heartbeat).

## Pair later (or re-pair)

| Install method | Command |
|----------------|---------|
| Universal installer (Linux/macOS) | `sudo /opt/patcherly-connector/start.sh login` |
| Universal installer (Windows) | `& "$env:USERPROFILE\patcherly-connector\start.ps1" login` |
| pip | `patcherly login` |

> On Linux, use `sudo` when the installer enabled the root-run `patcherly-connector` systemd unit so credentials land in `/root/.patcherly/`.

## After install

- Status and approvals: **Targets** in your [Patcherly dashboard](https://app.patcherly.com/targets).
- Start and keep the agent running — on Linux with the universal installer: `systemctl start patcherly-connector`. Otherwise run `start.sh` / `start.ps1`, or `python patcherly_agent.py`. Details: [Python connector guide](https://help.patcherly.com/connectors/python/).
- Path exclusions and patch policies: [Path rules for targets](https://help.patcherly.com/getting-started/path-exclusion/).

## Test Mode (sample error)

1. In the dashboard: **Targets → your target → Test Mode** ON (30-minute window).
2. On the host:

```bash
patcherly send-test
```

Samples are flagged and do not affect metrics or notifications. See [Verify detection with send-test](https://help.patcherly.com/connectors/python/#verify-detection-end-to-end-with-patcherly-send-test).

## Context consent

Default is **full**. Change with:

```bash
patcherly context get
patcherly context set full|minimal|off
patcherly context upload
```

Env override: `PATCHERLY_CONTEXT_CONSENT` (overrides `{PATCHERLY_CACHE_DIR}/context_consent`). `off` skips uploads; `minimal` sends runtime/OS/framework only.

## Security

OAuth pairing and per-token **HMAC signing**; fix payloads are verified before apply. Built-in redaction runs before ingest; you can add custom sanitizer patterns per target.

- [Connectors overview](https://help.patcherly.com/connectors/overview/)
- [Python connector — HMAC](https://help.patcherly.com/connectors/python/#hmac-signing)
- [Prompt injection protection](https://help.patcherly.com/security/prompt-injection-protection/)
- [Custom sanitizer patterns](https://help.patcherly.com/security/custom-sanitizer-patterns/)
- [Post-apply restart safety](https://help.patcherly.com/security/post-apply-restart-safety/)
- [Hardening: backup folders](https://help.patcherly.com/connectors/overview/#hardening-backup-folders-and-the-public-web)

## Documentation & support

- **[Python connector guide](https://help.patcherly.com/connectors/python/)** — install, systemd, troubleshooting
- **[Connectors overview](https://help.patcherly.com/connectors/overview/)** · **[All connectors](https://github.com/Patcherly-Official/patcherly-connector-packages#readme)**
- **[Discord](https://discord.gg/7yZkD9KNsS)** · **[Dashboard](https://app.patcherly.com)** · **[Report a bug](https://github.com/Patcherly-Official/patcherly-connector-packages/issues)**

## License

[MIT](LICENSE)

Using the **Patcherly service** is governed by our [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use) policy. Official product support applies only to **unmodified** connector releases from our official sources.
