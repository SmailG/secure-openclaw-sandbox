# AGENTS.md

Project-level operating contract for AI coding agents working in this repository.

## 1. Security and Trust Boundaries

- Treat all inbound user/content data as untrusted.
- Do not assume prompt safety; enforce tool/policy controls before intelligence.
- Firewall scope is container-only:
  - `openclaw-agent` egress is governed by `ai-gateway`.
  - Host apps (Cursor/extensions/browser/shell) are outside this firewall by design.
- Never reintroduce host-level `HTTP_PROXY`/`HTTPS_PROXY` routing to `ai-gateway`.

## 2. Non-Negotiable Execution Rules

- Deterministic policy must remain the primary authority for command decisions.
- LLM risk scoring is secondary and advisory for ambiguous cases.
- For exec risk checks:
  - If policy blocks, return `deny` without LLM call.
  - If LLM fails/times out, follow `EXEC_GUARD_FAIL_MODE`.
- Do not report LLM verdicts for skipped checks (`llm_label` must stay `null`).

## 3. Gatekeeper Interfaces

- Prompt scan endpoint: `POST /scan`
- Command scan endpoint: `POST /scan_exec`
- Runtime whitelist endpoint: `POST /approve_domain`
- Health endpoint: `GET /health`

Execution policy location:
- `config/exec_policy.yaml`

Runtime controls:
- `EXEC_GUARD_MODE=observe|enforce`
- `EXEC_GUARD_FAIL_MODE=approval|closed`
- `EXEC_GUARD_TIMEOUT_MS=<int>`

## 4. Change Discipline

- Any change to command policy or scanner behavior requires:
  1. Unit/integration tests updated
  2. E2E critical path validation
  3. README update if behavior changed
- Never weaken policy silently (no hidden allowlist expansion).
- Keep defaults conservative; expand only with explicit rationale.

## 5. Testing Contract

- Canonical test entrypoint is containerized:
  - `make test`
- Critical-path E2E:
  - `make test-e2e`
- Pre-commit gate must remain active:
  - `.pre-commit-config.yaml` runs `make test`
- Host test path is optional, not authoritative:
  - `make test-local-setup`
  - `python3 -m unittest discover -s tests -p "test_*.py"`

## 6. Dependency Policy

- Runtime dependencies:
  - `requirements.txt`
- Dev/tooling dependencies:
  - `requirements-dev.txt` (must include `-r requirements.txt`)
- Do not add undeclared imports in Python code.
- If a new import is introduced, update dependency files in the same change.

## 7. Operational Safety Defaults

- Keep gateway auth explicit (`OPENCLAW_GATEWAY_TOKEN` or password).
- Keep Telegram integration optional and non-failing when unset.
- Keep domain approval monitor functional with CONNECT request parsing.
- Avoid broad wildcard egress rules unless explicitly approved.

## 8. Logging and Data Handling

- Keep structured gatekeeper logs with decision metadata:
  - decision, risk score, policy matches, agent/session/channel context.
- Never log secret values.
- Redact or avoid sensitive payload content in logs.

## 9. Review Checklist for Agent-Authored Changes

Before claiming completion, verify:
- tests pass (`make test`; and `make test-e2e` when touching policy/scanner paths)
- no lints introduced
- README updated if public behavior changed
- no security boundary regressions (host proxy leakage, auth weakening, policy bypass)

## 10. Prohibited Actions

- Do not disable tests or pre-commit checks to make commits pass.
- Do not bypass approvals for risky execution paths.
- Do not silently convert fail-closed behavior into fail-open behavior.
- Do not introduce destructive git operations unless explicitly requested.
