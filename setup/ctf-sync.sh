#!/bin/zsh
# =============================================================================
# ctf-sync.sh — CTF Repo CTF Sync
# =============================================================================
# ABOUT:
#   Checks if the CTF_Public repo exists locally.
#   If yes  → pulls latest changes from GitHub
#   If no   → clones the full repo
#   Then    → fixes ownership and makes all scripts executable
#
# USAGE:
#   ./ctf-sync.sh              # uses defaults below
#   ./ctf-sync.sh --help       # show help
#
# DEV vs PRODUCTION:
#   Production machines clone to /opt/CTF_Public (default).
#   Dev machines are detected automatically if ~/github/CTF_Public exists,
#   or if CTF_REPO_DIR is already exported in the environment.
#   On a brand new dev machine (no repo yet), the script will prompt for
#   an install path so the clone lands in the right place from the start.
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================

# --- Configuration ------------------------------------------------------------
REPO_URL="https://github.com/Ghost-Glitch04/CTF_Public"
REPO_OWNER="$USER"

# --- Colors -------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# =============================================================================
# INSTALL DIR RESOLUTION
# =============================================================================
# TEACHING NOTE — Layered fallback for path resolution.
# We resolve INSTALL_DIR in three passes, in order of precedence:
#
#   1. CTF_REPO_DIR already set in the environment (user or prior session set it)
#   2. Auto-detect: ~/github/CTF_Public already exists on disk (dev machine)
#   3. No repo found anywhere → prompt the user on first run so the clone
#      lands in the correct place rather than silently defaulting to /opt/
#
# The prompt only fires during a fresh clone (no existing repo). On re-runs
# (repo already present), detection finds it and skips the prompt entirely.
# =============================================================================

_resolve_install_dir() {
  # Pass 1: respect an already-exported CTF_REPO_DIR
  if [[ -n "$CTF_REPO_DIR" ]]; then
    echo "$CTF_REPO_DIR"
    return
  fi

  # Pass 2: auto-detect known dev path
  if [[ -d "$HOME/github/CTF_Public" ]]; then
    echo "$HOME/github/CTF_Public"
    return
  fi

  # Pass 3: auto-detect production path
  if [[ -d "/opt/CTF_Public" ]]; then
    echo "/opt/CTF_Public"
    return
  fi

  # Pass 4: nothing found — prompt on first run
  # TEACHING NOTE — We only reach here when no repo exists anywhere on disk.
  # Rather than silently cloning to /opt/ on a dev machine, we ask once.
  # The default shown in brackets is the production path; a dev just types
  # their preferred path instead. Empty input accepts the default.
  echo ""
  echo "${CYAN}[SETUP]${RESET}  No existing repo found. Where should it be cloned?" >&2
  echo "         ${DIM}Production default: /opt/CTF_Public${RESET}" >&2
  echo "         ${DIM}Dev example:        ~/github/CTF_Public${RESET}" >&2
  echo -n "         Install path [/opt/CTF_Public]: " >&2
  read custom_dir

  # Expand ~ manually since read doesn't expand it
  custom_dir="${custom_dir/#\~/$HOME}"
  echo "${custom_dir:-/opt/CTF_Public}"
}

INSTALL_DIR="$(_resolve_install_dir)"

# --- Help ---------------------------------------------------------------------
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  echo ""
  echo "${BOLD}ctf-sync.sh${RESET} — CTF Repo CTF Sync"
  echo ""
  echo "  Pulls latest changes if repo exists, clones fresh if it doesn't."
  echo "  Then fixes ownership and makes all .sh scripts executable."
  echo ""
  echo "  ${CYAN}Repo:${RESET}    $REPO_URL"
  echo "  ${CYAN}Target:${RESET}  $INSTALL_DIR"
  echo ""
  echo "  ${BOLD}Usage:${RESET}"
  echo "  ./ctf-sync.sh          Run sync"
  echo "  ./ctf-sync.sh --help   Show this message"
  echo ""
  echo "  ${BOLD}Dev Override:${RESET}"
  echo "  export CTF_REPO_DIR=~/github/CTF_Public"
  echo "  ./ctf-sync.sh"
  echo ""
  exit 0
fi

# --- Header -------------------------------------------------------------------
echo ""
echo "${BOLD}${CYAN}=== CTF Repo CTF Sync ===${RESET}"
echo "${DIM}  Repo:   $REPO_URL${RESET}"
echo "${DIM}  Target: $INSTALL_DIR${RESET}"
echo ""

# --- Step 1: Clone or Pull ----------------------------------------------------
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  # Repo exists — pull latest
  echo "${CYAN}[SYNC]${RESET}  Local repo found. Pulling latest changes..."
  echo ""

  cd "$INSTALL_DIR" || { echo "${RED}[ERROR]${RESET} Cannot cd into $INSTALL_DIR"; exit 1; }

  # Show current branch
  CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
  echo "${DIM}  Branch: $CURRENT_BRANCH${RESET}"

  # Capture git pull output
  PULL_OUTPUT=$(git pull origin "$CURRENT_BRANCH" 2>&1)
  PULL_EXIT=$?

  if [[ $PULL_EXIT -ne 0 ]]; then
    echo "${RED}[ERROR]${RESET} Git pull failed:"
    echo "$PULL_OUTPUT"
    exit 1
  fi

  # Check if anything actually changed
  if echo "$PULL_OUTPUT" | grep -q "Already up to date"; then
    echo "${GREEN}[OK]${RESET}    Already up to date — no changes pulled."
  else
    # Show a summary of what changed
    CHANGED_FILES=$(echo "$PULL_OUTPUT" | grep -E "^\s+[A-Za-z]" | wc -l | tr -d ' ')
    echo "${GREEN}[OK]${RESET}    Pull successful."
    echo ""
    echo "${DIM}  Changed files:${RESET}"
    echo "$PULL_OUTPUT" | grep -E "^\s+[A-Za-z]" | while read -r line; do
      echo "    ${DIM}$line${RESET}"
    done
  fi

elif [[ -d "$INSTALL_DIR" && ! -d "${INSTALL_DIR}/.git" ]]; then
  # Directory exists but isn't a git repo — warn and abort
  echo "${YELLOW}[WARN]${RESET}  Directory exists but is not a git repo:"
  echo "         ${BOLD}$INSTALL_DIR${RESET}"
  echo ""
  echo "  Options:"
  echo "  1. Remove it and re-run: ${BOLD}sudo rm -rf $INSTALL_DIR${RESET}"
  echo "  2. Set a different path: ${BOLD}export CTF_REPO_DIR=<path>${RESET} then re-run"
  echo ""
  exit 1

else
  # Repo doesn't exist — fresh clone
  echo "${CYAN}[CLONE]${RESET} No local repo found. Cloning fresh copy..."
  echo ""

  # Use sudo only for /opt — dev paths under $HOME don't need it
  if [[ "$INSTALL_DIR" == /opt/* ]]; then
    sudo git clone "$REPO_URL" "$INSTALL_DIR" 2>&1
  else
    # Ensure parent directory exists for dev paths
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone "$REPO_URL" "$INSTALL_DIR" 2>&1
  fi
  CLONE_EXIT=$?

  if [[ $CLONE_EXIT -ne 0 ]]; then
    echo ""
    echo "${RED}[ERROR]${RESET} Git clone failed. Check:"
    echo "  - Network connection:  ${BOLD}ping -c 2 github.com${RESET}"
    echo "  - Repo URL is valid:   ${BOLD}curl -sI $REPO_URL | grep HTTP${RESET}"
    exit 1
  fi

  echo ""
  echo "${GREEN}[OK]${RESET}    Repo cloned to: ${BOLD}$INSTALL_DIR${RESET}"
fi

# --- Step 2: Fix ownership ----------------------------------------------------
echo ""
echo "${CYAN}[PERMS]${RESET} Setting ownership to: ${BOLD}${REPO_OWNER}${RESET}"

# Use sudo only when the path requires elevated permissions
if [[ "$INSTALL_DIR" == /opt/* ]]; then
  sudo chown -R "${REPO_OWNER}":"${REPO_OWNER}" "$INSTALL_DIR"
else
  chown -R "${REPO_OWNER}":"${REPO_OWNER}" "$INSTALL_DIR"
fi

if [[ $? -eq 0 ]]; then
  echo "${GREEN}[OK]${RESET}    Ownership set."
else
  echo "${RED}[ERROR]${RESET} chown failed — try running with sudo"
  exit 1
fi

# --- Step 3: Make all scripts executable -------------------------------------
echo ""
echo "${CYAN}[CHMOD]${RESET} Making all .sh scripts executable..."

find "$INSTALL_DIR" -type f -name "*.sh" | while read -r script; do
  chmod +x "$script"
  echo "  ${GREEN}+x${RESET}  ${DIM}${script#$INSTALL_DIR/}${RESET}"
done

TOTAL=$(find "$INSTALL_DIR" -type f -name "*.sh" | wc -l | tr -d ' ')
echo "${GREEN}[OK]${RESET}    ${BOLD}${TOTAL}${RESET} script(s) set to executable."

# --- Step 4: Summary ----------------------------------------------------------
echo ""
echo "${BOLD}${CYAN}=== Sync Complete ===${RESET}"
echo ""
echo "  ${CYAN}Location:${RESET}  $INSTALL_DIR"
echo "  ${CYAN}Owner:${RESET}     $REPO_OWNER"
echo "  ${CYAN}Scripts:${RESET}   $TOTAL executable"
echo ""
echo "  ${DIM}Tip: Add this to your toolkit:${RESET}"
echo "  ${BOLD}sudo ln -sf ${INSTALL_DIR}/setup/ctf-sync.sh /usr/local/bin/ctf-sync${RESET}"
echo "  ${DIM}Then run ${BOLD}ctf-sync${RESET}${DIM} from anywhere to stay up to date.${RESET}"
echo ""