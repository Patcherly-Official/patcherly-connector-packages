# Connector-side contract check

This folder contains a small script that verifies the **ingest API contract** from the connector’s perspective: it sends a minimal `POST /api/errors/ingest` payload and asserts the response is **201** and matches the **ErrorItem** shape (`id`, `status`, `log_line`, `created_at`). Use it to keep connectors and the API in sync.

## Run (stdlib only, no extra deps)

From the project root:

```bash
API_BASE_URL=https://api.patcherly.com API_KEY=your_agent_key python connectors/contract/check_ingest_contract.py
```

From `connectors/contract/`:

```bash
API_BASE_URL=https://api.patcherly.com API_KEY=your_agent_key python check_ingest_contract.py
```

## Environment

| Variable | Description |
|----------|-------------|
| **API_BASE_URL** | Base URL of the API (default: `http://localhost:8000`) |
| **API_KEY** | Agent API key (`X-API-Key`). Required. |
| **TENANT_ID** | Optional `tenant_id` in payload (default: `1`) |
| **TARGET_ID** | Optional `target_id` in payload (default: `1`) |

You can use `CONTRACT_TEST_AGENT_KEY` instead of `API_KEY` if you already use it for contract tests.

## Exit codes

- **0** – Contract passed (201 + ErrorItem shape).
- **Non-zero** – Missing env, non-201, or response missing required fields.

## Relation to API contract tests

The main contract tests live in [tests/contract/](../../tests/contract/) and are run with `pytest tests/contract/ -v -m contract`. This script is a lightweight, connector-side check that can be run from any environment (e.g. CI for a connector) without pytest or the full test suite.
