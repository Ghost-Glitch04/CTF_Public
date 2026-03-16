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
# TEACHING NOTE — Inline if/elif/else replaces the previous _resolve_install_dir
# function. (Refactor #6)
#
# The original version wrapped this logic in a function called exactly once,
# immediately after its definition. A function is the right tool when you need
# to reuse logic in multiple places, or when the logic is complex enough to
# deserve its own name and scope. Neither was true here — it ran once, and the
# logic is a simple layered fallback that reads naturally top-to-bottom.
#
# Using a plain if/elif/else block instead has two advantages:
#   1. Consistency — ctf-install.sh solves the same problem the same way,
#      making the codebase easier to read as a whole.
#   2. Cleanliness — functions defined in a script persist for the lifetime
#      of that script's execution. _resolve_install_dir served no purpose
#      after being called and left an unused name in the namespace.
#
# The logic itself is unchanged — same four passes, same prompt fallback.
# Only the structure changed.
#
# Pass 1: CTF_REPO_DIR already set in the environment (user or prior session)
# Pass 2: Auto-detect ~/github/CTF_Public on disk (known dev path)
# Pass 3: Auto-detect /opt/CTF_Public on disk (production path)
# Pass 4: Nothing found — prompt once so the clone lands in the right place
#
# The prompt only fires on a brand new machine with no repo anywhere on disk.
# On all subsequent runs, one of the first three passes will match.
# =============================================================================

if [[ -n "$CTF_REPO_DIR" ]]; then
  INSTALL_DIR="$CTF_REPO_DIR"
elif [[ -d "$HOME/github/CTF_Public" ]]; then
  INSTALL_DIR="$HOME/github/CTF_Public"
elif [[ -d "/opt/CTF_Public" ]]; then
  INSTALL_DIR="/opt/CTF_Public"
else
  # TEACHING NOTE — Prompting as a last resort, not a first resort.
  # We only reach this branch when no repo exists anywhere on disk. Rather
  # than silently defaulting to /opt/ on a dev machine, we ask once.
  # Empty input accepts the production default via the :- fallback operator.
  #
  # Tilde expansion: the `read` builtin stores input as a literal string —
  # it does NOT expand shell metacharacters like ~. If a user types
  # ~/github/CTF_Public, the variable holds the literal characters "~/"
  # rather than "/home/username/". The ${var/#\~/$HOME} substitution fixes
  # this by replacing a leading ~ with the expanded value of $HOME.
  echo ""
  echo "${CYAN}[SETUP]${RESET}  No existing repo found. Where should it be cloned?"
  echo "         ${DIM}Production default: /opt/CTF_Public${RESET}"
  echo "         ${DIM}Dev example:        ~/github/CTF_Public${RESET}"
  echo -n "         Install path [/opt/CTF_Public]: "
  read custom_dir
  custom_dir="${custom_dir/#\~/$HOME}"
  INSTALL_DIR="${custom_dir:-/opt/CTF_Public}"
fi

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

# TEACHING NOTE — Conditional sudo in the symlink tip. (Refactor #8)
#
# The previous version always printed `sudo ln -sf ...` regardless of where
# INSTALL_DIR resolved to. On a dev machine where INSTALL_DIR is under $HOME,
# sudo is unnecessary — you own the file and /usr/local/bin is writable by
# your user if sudo was used to create the symlink originally. Printing sudo
# unconditionally implies elevated privileges are always required, which is
# misleading and trains a habit of reaching for sudo when it isn't needed.
#
# The fix: check whether INSTALL_DIR is a system path (/opt/*) or a user
# path. Show sudo only when the path genuinely requires it. The produced tip
# is now accurate on both dev and production machines.
echo "  ${DIM}Tip: Add this to your toolkit:${RESET}"
if [[ "$INSTALL_DIR" == /opt/* ]]; then
  echo "  ${BOLD}sudo ln -sf ${INSTALL_DIR}/setup/ctf-sync.sh /usr/local/bin/ctf-sync${RESET}"
else
  echo "  ${BOLD}ln -sf ${INSTALL_DIR}/setup/ctf-sync.sh /usr/local/bin/ctf-sync${RESET}"
fi
echo "  ${DIM}Then run ${BOLD}ctf-sync${RESET}${DIM} from anywhere to stay up to date.${RESET}"
echo ""