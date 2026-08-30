#!/usr/bin/env bash
# --------------------------------------------------------------------------- #
# Guardrailed AI SOC Agent — deployment / bring-up script
#
# Verifies required tooling and dependencies, then builds the images and brings
# the hardened Compose stack (ollama, soc-engine, streamlit) up with health
# checks. Safe to re-run; idempotent.
#
# Usage:
#   ./deploy.sh                 # verify deps + up -d with health validation
#   ./deploy.sh up              # build images and start the stack
#   ./deploy.sh status          # show container status + engine health
#   ./deploy.sh verify          # dependency + compose validation only
#   ./deploy.sh down            # stop and remove the stack
# --------------------------------------------------------------------------- #
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"

say()  { printf '\033[1;32m>>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m>>>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Dependency verification
# --------------------------------------------------------------------------- #
verify_deps() {
    say "Verifying dependencies..."

    command -v docker >/dev/null 2>&1 || fail "Required command 'docker' is not installed."
    command -v curl >/dev/null 2>&1 || fail "Required command 'curl' is not installed."

    # Check the compose plugin / subcommand.
    if ! docker compose version >/dev/null 2>&1; then
        fail "Docker Compose v2 plugin is not available (try 'docker compose version')."
    fi

    [ -f "$COMPOSE_FILE" ] || fail "Compose file '$COMPOSE_FILE' not found."

    # Validate the compose file parses cleanly.
    docker compose -f "$COMPOSE_FILE" config --quiet || fail "Compose file failed validation."

    # The engine bind-mounts security.log read-only; ensure it exists.
    if [ ! -f security.log ]; then
        warn "security.log not found; creating an empty one (SIEM will be empty until populated)."
        : > security.log
    fi

    say "Dependencies OK."
}

# --------------------------------------------------------------------------- #
# Bring the stack up and wait for engine health
# --------------------------------------------------------------------------- #
compose_up() {
    verify_deps

    say "Building images and starting the stack (model=$OLLAMA_MODEL)..."
    OLLAMA_MODEL="$OLLAMA_MODEL" docker compose -f "$COMPOSE_FILE" up -d --build

    wait_for_health
    say "Stack is up. Dashboard: http://localhost:8501   Engine: http://localhost:8000/health"
}

wait_for_health() {
    say "Waiting for soc-engine /health (timeout=${HEALTH_TIMEOUT}s)..."
    local elapsed=0
    until curl -fsS "http://localhost:8000/health" >/dev/null 2>&1; do
        if [ "$elapsed" -ge "$HEALTH_TIMEOUT" ]; then
            warn "Engine health not reached within ${HEALTH_TIMEOUT}s."
            docker compose -f "$COMPOSE_FILE" ps
            return 1
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    say "Engine is healthy."
}

# --------------------------------------------------------------------------- #
# Command dispatch
# --------------------------------------------------------------------------- #
case "${1:-up}" in
    up)
        compose_up
        ;;
    status)
        verify_deps
        docker compose -f "$COMPOSE_FILE" ps
        say "Engine health:"
        curl -fsS "http://localhost:8000/health" 2>/dev/null || warn "Engine not reachable."
        ;;
    verify)
        verify_deps
        say "Configuration is valid: $COMPOSE_FILE"
        ;;
    down)
        verify_deps
        docker compose -f "$COMPOSE_FILE" down
        say "Stack stopped and removed."
        ;;
    *)
        warn "Unknown command: ${1:-}"
        say "Usage: $0 {up|status|verify|down}"
        exit 2
        ;;
esac
