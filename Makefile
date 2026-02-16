# --- SETTINGS & DETECTION ---
DOCKER_COMPOSE := docker compose
MODEL_NAME := qwen2.5:0.5b
UNAME_S := $(shell uname -s)
APPROVE_SCRIPT := ./approve.sh

# Load environment variables from .env
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Keep firewall scope container-only: never forward host proxy env into recipes.
# `openclaw-agent` gets explicit proxy vars via docker-compose service env.
unexport HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy

# --- OS-SPECIFIC MONITOR LOGIC (macOS Focus) ---
ifeq ($(UNAME_S),Darwin)
    OPEN_MONITOR := osascript -e 'tell application "Terminal" to do script "cd \"$(PWD)\" && make approve"'
    CLOSE_MONITOR := osascript -e 'tell application "Terminal" to close (every window whose name contains "Sandbox-Monitor")'
else
    OPEN_MONITOR := sh -c 'if command -v x-terminal-emulator >/dev/null 2>&1; then x-terminal-emulator -e make approve & elif command -v gnome-terminal >/dev/null 2>&1; then gnome-terminal -- bash -lc "cd \"$(PWD)\" && make approve" >/dev/null 2>&1 & else echo "⚠️ No GUI terminal launcher found. Run '\''make approve'\'' manually in another terminal."; fi'
    CLOSE_MONITOR := pkill -f "make approve" >/dev/null 2>&1 || true
endif

# --- CORE TARGETS ---

.PHONY: setup start stop clean wipe generate-config approve test test-e2e test-local-setup install-hooks help

help:
	@echo "🛡️  Secure AI Sandbox - Command Center"
	@echo "  make start   - 🚀 Launch full stack (Build-Safe & Zero-Touch)"
	@echo "  make stop    - 🛑 Stop services and close monitor"
	@echo "  make clean   - 🧹 Remove containers (Keeps Data & Cache)"
	@echo "  make wipe    - ☢️  Nuclear Clean (Destroys Data & Cache)"
	@echo "  make test    - 🧪 Run containerized Python tests"
	@echo "  make test-e2e - 🧪 Run critical-path E2E tests"
	@echo "  make test-local-setup - 🧪 Install local Python test dependencies"
	@echo "  make install-hooks - 🧪 Install pre-commit hook (runs make test)"

# 1. Environment Preparation (Reinforced for Out-of-the-Box stability)
setup:
	@echo "🔧 Preparing environment and permissions..."
	@mkdir -p workspace haproxy_run
	@touch runtime_whitelist.lst
	@chmod -R 777 haproxy_run
	@chmod 666 runtime_whitelist.lst
	@if [ ! -f .env ]; then cp .env.example .env && echo "⚠️ Created .env. Please edit it!"; fi
	@if [ -n "$(HTTP_PROXY)$(HTTPS_PROXY)$(http_proxy)$(https_proxy)" ]; then echo "⚠️ Host-level proxy vars are set in your shell/.env. They are intentionally ignored by Makefile so only OpenClaw container traffic is governed by ai-gateway."; fi
	@if [ -z "$(OPENCLAW_GATEWAY_TOKEN)" ] && [ -z "$(OPENCLAW_GATEWAY_PASSWORD)" ] && [ -z "$(GATEWAY_TOKEN)" ]; then echo "⚠️ Gateway auth is not explicitly configured. Set OPENCLAW_GATEWAY_TOKEN (or OPENCLAW_GATEWAY_PASSWORD) in .env."; fi

# 2. Dynamic Configuration Injection (Bypasses Professor Falken)
generate-config:
	@# FIX: We now use Environment Variables in docker-compose.yml
	@# We skip generating openclaw.json to prevent Root Permission/EISDIR errors.
	@echo "✅ Configuration injected via Environment Variables."
	@rm -f openclaw.json

# 3. Intelligent Launch (Build-Safe)
start: setup generate-config
	@echo "🚦 Starting Sandbox Stack..."
	@# FIX: Disabling proxies for build so it doesn't look for the non-existent 'ai-gateway'
	HTTP_PROXY="" HTTPS_PROXY="" http_proxy="" https_proxy="" $(DOCKER_COMPOSE) build
	
	@echo "🔧 Fixing volume permissions (Canvas, Cron, Config)..."
	@# Initialize the named volume with writeable dirs before the main container starts.
	@# NOTE: --entrypoint takes only the executable; command args must come after the service.
	$(DOCKER_COMPOSE) run --rm --no-deps --user root --entrypoint /bin/sh openclaw-agent -lc "mkdir -p /home/node/.openclaw /home/node/.openclaw/canvas /home/node/.openclaw/cron && chmod -R 0777 /home/node/.openclaw"
	
	$(DOCKER_COMPOSE) up -d

	@echo "🤖 Applying OpenClaw runtime config (model + Telegram)..."
	@# Set default model from env (e.g., google/gemini-2.5-flash) to avoid expensive defaults.
	@docker exec openclaw-agent /bin/sh -lc "if [ -n \"$$OPENCLAW_DEFAULT_MODEL\" ]; then npx openclaw models set \"$$OPENCLAW_DEFAULT_MODEL\" || echo \"⚠️ Could not set OPENCLAW_DEFAULT_MODEL\"; else echo \"ℹ️ OPENCLAW_DEFAULT_MODEL not set, keeping current default model\"; fi"
	@# Enable Telegram plugin and channel when TELEGRAM_TOKEN is present.
	@docker exec openclaw-agent /bin/sh -lc "if [ -n \"$$TELEGRAM_TOKEN\" ]; then npx openclaw plugins enable telegram || echo \"⚠️ Could not enable telegram plugin\"; npx openclaw channels add --channel telegram --token \"$$TELEGRAM_TOKEN\" --name telegram-default || echo \"⚠️ Could not configure telegram channel\"; else echo \"ℹ️ TELEGRAM_TOKEN not set, skipping Telegram channel setup\"; fi"
	@# Apply Telegram allowlist from env (comma-separated IDs) for plug-and-play onboarding.
	@docker exec openclaw-agent /bin/sh -lc "if [ -n \"$$TELEGRAM_TOKEN\" ] && [ -n \"$$TELEGRAM_ALLOWED_IDS\" ]; then node -e 'const fs=require(\"fs\"); const p=\"/home/node/.openclaw/openclaw.json\"; const cfg=JSON.parse(fs.readFileSync(p,\"utf8\")); const ids=(process.env.TELEGRAM_ALLOWED_IDS||\"\").split(\",\").map(s=>s.trim()).filter(Boolean); cfg.channels=cfg.channels||{}; cfg.channels.telegram=cfg.channels.telegram||{}; cfg.channels.telegram.dmPolicy=\"allowlist\"; cfg.channels.telegram.allowFrom=ids; cfg.meta=cfg.meta||{}; cfg.meta.lastTouchedAt=new Date().toISOString(); fs.writeFileSync(p, JSON.stringify(cfg,null,2)+\"\\n\"); console.log(\"Telegram allowlist IDs:\", ids.join(\",\") || \"(none)\");' || echo \"⚠️ Could not apply TELEGRAM_ALLOWED_IDS\"; elif [ -n \"$$TELEGRAM_ALLOWED_IDS\" ]; then echo \"ℹ️ TELEGRAM_ALLOWED_IDS set but TELEGRAM_TOKEN is empty; skipping Telegram allowlist\"; else echo \"ℹ️ TELEGRAM_ALLOWED_IDS not set, Telegram DMs will use channel default policy\"; fi"
	@echo "📥 Checking for $(MODEL_NAME)..."
	@docker exec security-brain ollama list | grep -q "$(MODEL_NAME)" || \
		(echo "⬇️ Pulling security weights..." && docker exec security-brain ollama pull $(MODEL_NAME))
	@echo "🖥️  Launching Sandbox-Monitor..."
	@$(OPEN_MONITOR)
	@echo "✅ Sandbox active at http://localhost:18789"

# 4. Graceful Shutdown
stop:
	@echo "🛑 Stopping Sandbox Stack..."
	$(DOCKER_COMPOSE) down --remove-orphans
	@pkill -f "make approve" || true
	@$(CLOSE_MONITOR) || true

# 5. Maintenance (Cache-Aware)
clean: stop
	@echo "🧹 Cleaning containers (Preserving volumes/cache)..."
	$(DOCKER_COMPOSE) down --remove-orphans

wipe: stop
	@echo "☢️ Destroying all volumes, data, and configs..."
	$(DOCKER_COMPOSE) down --volumes --remove-orphans
	@rm -f openclaw.json
	@rm -rf haproxy_run/*
	@docker network prune -f

# 6. Tests
test:
	@echo "🧪 Running containerized tests..."
	$(DOCKER_COMPOSE) build inspector-api
	$(DOCKER_COMPOSE) run --rm --no-deps -e SKIP_LLM_GUARD_INIT=1 -e EXEC_GUARD_MODE=enforce -e EXEC_GUARD_FAIL_MODE=approval inspector-api \
		python -m unittest discover -s tests -p "test_*.py"

test-e2e:
	@echo "🧪 Running critical-path E2E tests..."
	$(DOCKER_COMPOSE) build inspector-api
	$(DOCKER_COMPOSE) run --rm --no-deps -e SKIP_LLM_GUARD_INIT=1 -e EXEC_GUARD_MODE=enforce -e EXEC_GUARD_FAIL_MODE=approval inspector-api \
		python -m unittest tests.test_e2e_critical_paths

test-local-setup:
	@echo "🧪 Installing local Python dependencies for host-side unittest runs..."
	python3 -m pip install -r requirements-dev.txt

install-hooks:
	@echo "🧪 Installing pre-commit and registering git hook..."
	python3 -m pip install -r requirements-dev.txt
	pre-commit install

# 7. Monitor Loop
approve:
	@printf "\033]2;Sandbox-Monitor\007"
	@echo "⚖️  APPROVAL MONITOR ACTIVE"
	@if [ -f "$(APPROVE_SCRIPT)" ]; then bash "$(APPROVE_SCRIPT)"; else echo "❌ Missing $(APPROVE_SCRIPT)"; exit 1; fi