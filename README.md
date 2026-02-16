# Secure OpenClaw Sandbox

Containerized defense-in-depth runtime for OpenClaw with policy-based egress control, prompt scanning, and command gatekeeping.

## Current Project State

- Core stack is functional and starts with `make start`.
- OpenClaw gateway is exposed on `http://localhost:18789`.
- Firewall scope is intentionally limited to `openclaw-agent` container traffic.
- Prompt scanner endpoint is active at `POST /scan`.
- Exec gatekeeper endpoint is active at `POST /scan_exec`.
- Domain approval monitor parses HAProxy 403 request lines and can whitelist blocked domains interactively.
- Containerized test suite and pre-commit enforcement are configured.

## Architecture

Services:
- `openclaw-agent`: OpenClaw runtime, channels, model routing.
- `inspector-api`: FastAPI policy service (`/health`, `/scan`, `/scan_exec`, `/approve_domain`).
- `ai-gateway`: HAProxy egress gateway and runtime host ACL check.
- `security-brain`: local Ollama backend for risk classification.

Primary trust boundaries:
- `openclaw-agent` egress is routed via `ai-gateway`.
- Host-native apps (Cursor/extensions/browser/shell) are not routed through `ai-gateway`.
- Policy decisions are centralized in `inspector-api`.

## Quick Start

### Prerequisites
- Docker Desktop or Docker Engine + Compose plugin
- `make`
- provider keys in `.env` (for example `GEMINI_API_KEY`)

### Boot

```bash
make start
```

This will:
- prepare local runtime files
- build and start containers
- initialize OpenClaw state permissions
- apply optional model + Telegram runtime configuration
- open interactive approval monitor

### Shutdown and Cleanup

```bash
make stop
make clean
make wipe
```

## Configuration

Copy `.env.example` to `.env` and set required values.

Key variables:
- `OPENCLAW_DEFAULT_MODEL`
- `GEMINI_API_KEY`
- `OPENCLAW_GATEWAY_TOKEN` or `OPENCLAW_GATEWAY_PASSWORD`
- `TELEGRAM_BOT_TOKEN` and `TELEGRAM_ALLOWED_IDS` (optional)
- `EXEC_GUARD_MODE` (`observe` or `enforce`)
- `EXEC_GUARD_FAIL_MODE` (`approval` or `closed`)
- `EXEC_GUARD_TIMEOUT_MS`

## Security Model

### Egress and Domain Policy
- HAProxy ACLs in `haproxy.cfg` enforce outbound host restrictions.
- Runtime approvals are written to `runtime_whitelist.lst` through `POST /approve_domain`.
- Approval monitor runs via `make approve` and reacts to blocked `403` requests.

### Prompt Scan
- `POST /scan` performs normalization + scanner checks + local intent check.
- Scanner init can be skipped in tests via `SKIP_LLM_GUARD_INIT=1`.

### Exec Gatekeeper
- `POST /scan_exec` combines deterministic policy and LLM-based risk scoring.
- Deterministic rules live in `config/exec_policy.yaml`.
- Decision output:
  - `allow`
  - `deny`
  - `require_approval`
- LLM is not the sole authority; deterministic deny rules always win.
- If deterministic policy blocks execution, LLM check is skipped and `llm_label` is `null`.
- Fail behavior when LLM check errors/timeouts:
  - `approval`: `require_approval`
  - `closed`: `deny`

## Testing and Quality Gates

Containerized tests (recommended):

```bash
make test
make test-e2e
```

Coverage includes:
- health endpoint
- domain approval write path
- exec gatekeeper deny/approval behavior
- fail-mode behavior for LLM uncertainty/timeouts

Host-side test option:

```bash
make test-local-setup
python3 -m unittest discover -s tests -p "test_*.py"
```

Pre-commit gate:

```bash
make install-hooks
```

This installs `.pre-commit-config.yaml` hook that runs `make test` and blocks commits on failure.

## Operational Notes

- `.specstory/` is git-ignored.
- OpenClaw state persists in Docker volume `openclaw_config`.
- `docker-compose.yml` currently declares `version: "3.8"`; Compose warns this key is obsolete but still runs.

## Key Files

- `docker-compose.yml`
- `Makefile`
- `shield_api.py`
- `config/exec_policy.yaml`
- `approve.sh`
- `haproxy.cfg`
- `.pre-commit-config.yaml`
- `requirements.txt` and `requirements-dev.txt`

## Disclaimer

This is a hardening layer, not a perfect boundary. Keep least privilege defaults, strict allowlists, and human approval for risky actions.
