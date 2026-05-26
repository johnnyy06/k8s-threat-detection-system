#!/usr/bin/env bash
# ============================================================================
# _env.sh — shared config loader pentru attack-scenarios/*/attack.sh
# ============================================================================
# Source din attack.sh:
#   source "$(dirname "$0")/../_env.sh"
#
# Citește .env (la repo root) → fallback la env vars → eroare clară dacă lipsă.
# Niciun secret/IP nu e hardcoded în scripturi.
# ============================================================================

# Detect repo root (caută .env / .env.example / .git)
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$_SCRIPT_DIR/.."

# Load .env if it exists (line by line, ignore comments/empty)
if [[ -f "$_REPO_ROOT/.env" ]]; then
    set -a  # auto-export
    # shellcheck disable=SC1091
    source "$_REPO_ROOT/.env"
    set +a
fi

# Required vars (sanity check)
: "${ES_URL:?ES_URL not set. Copy .env.example to .env at repo root and fill values.}"

# Backward compat alias: scripturile vechi folosesc $ES
export ES="$ES_URL"
