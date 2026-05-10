#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

echo ""
echo -e "${BOLD}${CYAN}  Fides · NORDA Bank${RESET}"
echo -e "${CYAN}  Autonomous Fraud Detection — Governance Operations Center${RESET}"
echo ""

# ── 1. Docker context ────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/4]${RESET} Connecting to Docker Desktop..."

if docker info &>/dev/null; then
  echo -e "      ${GREEN}✓ Docker already reachable${RESET}"
else
  docker context use desktop-linux &>/dev/null 2>&1 || true
  if ! docker info &>/dev/null; then
    echo -e "${RED}      ✗ Docker Desktop is not running.${RESET}"
    echo ""
    echo "      Start Docker Desktop first, wait for the whale icon,"
    echo "      then run this script again."
    echo ""
    exit 1
  fi
  echo -e "      ${GREEN}✓ Switched to desktop-linux context${RESET}"
fi

# ── 2. Stack up ──────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/4]${RESET} Starting Fides stack..."

if docker compose ps --status running 2>/dev/null | grep -q "orchestrator"; then
  echo -e "      ${GREEN}✓ Stack already running — skipping rebuild${RESET}"
else
  docker compose up -d --build 2>&1 | grep -E "(Starting|Started|Creating|Created|Building|Built|Error|error)" | \
    sed "s/^/      /" || true
  echo -e "      ${GREEN}✓ Stack started${RESET}"
fi

# ── 3. Wait for orchestrator health ─────────────────────────────────────────
echo -e "${YELLOW}[3/4]${RESET} Waiting for orchestrator to be ready..."

RETRIES=30
until curl -sf http://localhost:8000/health &>/dev/null; do
  RETRIES=$((RETRIES - 1))
  if [ "$RETRIES" -le 0 ]; then
    echo -e "${RED}      ✗ Orchestrator didn't start in time. Check logs:${RESET}"
    echo "        docker compose logs orchestrator"
    exit 1
  fi
  sleep 1
done
echo -e "      ${GREEN}✓ Orchestrator healthy${RESET}"

# ── 4. Simulator ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/4]${RESET} Starting transaction simulator..."

if ! python3 -c "import httpx" &>/dev/null; then
  pip install httpx --quiet --break-system-packages 2>/dev/null || \
  pip3 install httpx --quiet --break-system-packages 2>/dev/null || true
fi

python3 simulator/simulate.py &
SIM_PID=$!
echo -e "      ${GREEN}✓ Simulator running (PID $SIM_PID)${RESET}"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}  Fides is live.${RESET}"
echo ""
echo -e "  Dashboard   →  ${CYAN}http://localhost:3000${RESET}"
echo -e "  API         →  ${CYAN}http://localhost:8000${RESET}"
echo -e "  API docs    →  ${CYAN}http://localhost:8000/docs${RESET}"
echo ""
echo -e "  ${YELLOW}Ctrl+C${RESET} stops the simulator (stack keeps running)"
echo -e "  ${YELLOW}docker compose down${RESET} shuts down everything"
echo ""

# Keep script alive so Ctrl+C kills the simulator cleanly
trap "kill $SIM_PID 2>/dev/null; echo ''; echo '  Simulator stopped. Stack is still running.'; echo ''" INT TERM
wait $SIM_PID
