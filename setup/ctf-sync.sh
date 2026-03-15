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
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================

# --- Configuration ------------------------------------------------------------
# Change these if your repo URL or install path ever changes
REPO_URL="https://github.com/Ghost-Glitch04/CTF_Public"
INSTALL_DIR="/opt/CTF_Public"
REPO_OWNER="$USER"

# --- Colors -------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

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
  echo "  2. Clone elsewhere and update INSTALL_DIR in this script"
  echo ""
  exit 1

else
  # Repo doesn't exist — fresh clone
  echo "${CYAN}[CLONE]${RESET} No local repo found. Cloning fresh copy..."
  echo ""

  sudo git clone "$REPO_URL" "$INSTALL_DIR" 2>&1
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
sudo chown -R "${REPO_OWNER}":"${REPO_OWNER}" "$INSTALL_DIR"

if [[ $? -eq 0 ]]; then
  echo "${GREEN}[OK]${RESET}    Ownership set."
else
  echo "${RED}[ERROR]${RESET} chown failed — try running with sudo"
  exit 1
fi

# --- Step 3: Make all scripts executable -------------------------------------
echo ""
echo "${CYAN}[CHMOD]${RESET} Making all .sh scripts executable..."

SCRIPT_COUNT=0
find "$INSTALL_DIR" -type f -name "*.sh" | while read -r script; do
  chmod +x "$script"
  echo "  ${GREEN}+x${RESET}  ${DIM}${script#$INSTALL_DIR/}${RESET}"
  (( SCRIPT_COUNT++ ))
done

# Count separately since subshell loses the counter
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
