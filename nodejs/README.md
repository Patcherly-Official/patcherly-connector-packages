<div align="center">

<a href="https://patcherly.com"><img src="https://patcherly.com/assets/img/logo_patcherly_light.png" alt="Patcherly" width="240" /></a>

# Patcherly Node.js connector

**Auto-detect and fix production errors in your Node.js apps.**
Agent for Express, Fastify, Next.js, and more — pairs with your Patcherly account.

**For a limited time:** [30-day Pro trial](https://help.patcherly.com/billing/trial/) — no credit card required. Cancel anytime. [Sign up](https://patcherly.com).

[![npm @patcherly/nodejs-connector](https://img.shields.io/npm/v/@patcherly/nodejs-connector?label=Node.js&logo=npm&style=flat-square)](https://www.npmjs.com/package/@patcherly/nodejs-connector)
[![Documentation](https://img.shields.io/badge/Documentation-help.patcherly.com-1869f5?style=flat-square)](https://help.patcherly.com/connectors/nodejs/)
[![Discord — join](https://img.shields.io/badge/Discord-join-5865f2?logo=discord&logoColor=white&style=flat-square)](https://discord.gg/7yZkD9KNsS)

> Prefer `@latest` / unpinned npm installs, or pin from [GitHub Releases](https://github.com/Patcherly-Official/patcherly-connector-packages/releases/latest).

</div>

---

## Recommended install (universal installer)

One command downloads the Node.js agent and launches OAuth pairing:

| Platform | Command |
|----------|---------|
| macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/install \| sudo CONNECTOR_TYPE=nodejs bash` |
| Windows PowerShell | `$env:CONNECTOR_TYPE = 'nodejs'; irm "https://api.patcherly.com/install.ps1" \| iex` |

The CLI prints a **verification URL** and a short **user code** — open the URL, sign in, pick your target, and confirm. Credentials are saved to `~/.patcherly/credentials.json` (or `/root/.patcherly/` when run as root). Then start the agent — see [After install](#after-install).

Full installer options (paths, `SKIP_LOGIN`, older versions): [Installing a connector](https://help.patcherly.com/getting-started/installing-connector/).

## Package install (npm)

```bash
npm install @patcherly/nodejs-connector@latest
npx patcherly login
```

Start monitoring (credentials from `~/.patcherly/credentials.json`):

```javascript
const { NodeConnector } = require('@patcherly/nodejs-connector');

const connector = new NodeConnector({
  logFile: 'logs/error.log',
});
connector.start();
```

Or, with the release-tree / universal-installer layout: run `node patcherly_agent.js` (or `start.sh` / `start.ps1`).

Optional on quiet hosts: `npx patcherly heartbeat` from a daily cron / systemd timer — see the [Node.js guide](https://help.patcherly.com/connectors/nodejs/#keep-the-connection-alive-on-quiet-hosts-patcherly-heartbeat).

## Pair later (or re-pair)

| Install method | Command |
|----------------|---------|
| Universal installer (Linux/macOS) | `sudo /opt/patcherly-connector/start.sh login` |
| Universal installer (Windows) | `& "$env:USERPROFILE\patcherly-connector\start.ps1" login` |
| npm | `npx patcherly login` |

> On Linux, use `sudo` when the installer enabled the root-run `patcherly-connector` systemd unit so credentials land in `/root/.patcherly/`.

## After install

- Status and approvals: **Targets** in your [Patcherly dashboard](https://app.patcherly.com/targets).
- Start and keep the agent running — on Linux with the universal installer: `systemctl start patcherly-connector`. Otherwise run `start.sh` / `start.ps1`, or start the connector from your app as above. Details: [Node.js connector guide](https://help.patcherly.com/connectors/nodejs/).
- Path exclusions and patch policies: [Path rules for targets](https://help.patcherly.com/getting-started/path-exclusion/).

## Test Mode (sample error)

1. In the dashboard: **Targets → your target → Test Mode** ON (30-minute window).
2. On the host:

```bash
npx patcherly send-test
```

Samples are flagged and do not affect metrics or notifications. See [Verify detection with send-test](https://help.patcherly.com/connectors/nodejs/#verify-detection-end-to-end-with-patcherly-send-test).

## Context consent

Default is **full**. Change with:

```bash
npx patcherly context get
npx patcherly context set full|minimal|off
npx patcherly context upload
```

Env override: `PATCHERLY_CONTEXT_CONSENT`.

## Security

OAuth pairing and per-token **HMAC signing**; fix payloads are verified before apply. Built-in redaction runs before ingest; you can add custom sanitizer patterns per target.

- [Connectors overview](https://help.patcherly.com/connectors/overview/)
- [Node.js connector — HMAC](https://help.patcherly.com/connectors/nodejs/#hmac-signing)
- [Prompt injection protection](https://help.patcherly.com/security/prompt-injection-protection/)
- [Custom sanitizer patterns](https://help.patcherly.com/security/custom-sanitizer-patterns/)
- [Post-apply restart safety](https://help.patcherly.com/security/post-apply-restart-safety/)
- [Hardening: backup folders](https://help.patcherly.com/connectors/overview/#hardening-backup-folders-and-the-public-web)

## Documentation & support

- **[Node.js connector guide](https://help.patcherly.com/connectors/nodejs/)** — install, systemd, troubleshooting
- **[Connectors overview](https://help.patcherly.com/connectors/overview/)** · **[All connectors](https://github.com/Patcherly-Official/patcherly-connector-packages#readme)**
- **[Discord](https://discord.gg/7yZkD9KNsS)** · **[Dashboard](https://app.patcherly.com)** · **[Report a bug](https://github.com/Patcherly-Official/patcherly-connector-packages/issues)**

## License

[MIT](LICENSE)

Using the **Patcherly service** is governed by our [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use) policy. Official product support applies only to **unmodified** connector releases from our official sources.
