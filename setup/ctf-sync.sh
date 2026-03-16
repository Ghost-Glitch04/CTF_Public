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
#   ./ctf-sync.sh              # auto-detect install (dev path wins if both exist)
#   ./ctf-sync.sh --prod       # force production path (/opt/CTF_Public)
#   ./ctf-sync.sh --help       # show help
#
# DEV vs PRODUCTION:
#   Production machines clone to /opt/CTF_Public (default).
#   Dev machines are detected automatically if ~/github/CTF_Public exists,
#   or if CTF_REPO_DIR is already exported in the environment.
#   On a brand new dev machine (no repo yet), the script will prompt for
#   an install path so the clone lands in the right place from the start.
#
#   If BOTH a dev and production install exist on the same machine (e.g. a
#   Kali VM used for both purposes), use --prod to explicitly target the
#   production install. Without it, the dev path always takes priority.
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
# ARGUMENT PARSING
# =============================================================================
# TEACHING NOTE — Parse ALL flags first, before any other logic runs.
#
# All flags are parsed into boolean variables in a single loop so that flag
# order doesn't matter. `ctf-sync --prod --help` and `ctf-sync --help --prod`
# both show help and exit. Checking $1 directly later in the script would
# break for any combination where --help isn't first.
# =============================================================================

FORCE_PROD=false
SHOW_HELP=false

for arg in "$@"; do
  case "$arg" in
    --prod)    FORCE_PROD=true ;;
    --help|-h) SHOW_HELP=true ;;
    *)
      echo "${RED}[ERROR]${RESET} Unknown argument: ${BOLD}${arg}${RESET}"
      echo "  Run ${BOLD}ctf-sync --help${RESET} for usage."
      exit 1
      ;;
  esac
done

# =============================================================================
# INSTALL DIR RESOLUTION
# =============================================================================
# TEACHING NOTE — --prod short-circuits the detection chain.
#
# Without --prod, the detection order is:
#   Pass 1: CTF_REPO_DIR already exported in the environment
#   Pass 2: ~/github/CTF_Public exists on disk (dev path)
#   Pass 3: /opt/CTF_Public exists on disk (production path)
#   Pass 4: nothing found — prompt once on first run
#
# --prod bypasses all passes and assigns /opt/CTF_Public directly, with an
# immediate existence check so a missing production install fails loudly.
# =============================================================================

if $FORCE_PROD; then
  INSTALL_DIR="/opt/CTF_Public"
  if [[ ! -d "$INSTALL_DIR" ]]; then
    echo "${RED}[ERROR]${RESET} --prod specified but no production install found at:"
    echo "         ${BOLD}${INSTALL_DIR}${RESET}"
    echo ""
    echo "  To set up a production install, run without --prod first, or:"
    echo "  ${BOLD}sudo git clone ${REPO_URL} ${INSTALL_DIR}${RESET}"
    exit 1
  fi
elif [[ -n "$CTF_REPO_DIR" ]]; then
  INSTALL_DIR="$CTF_REPO_DIR"
elif [[ -d "$HOME/github/CTF_Public" ]]; then
  INSTALL_DIR="$HOME/github/CTF_Public"
elif [[ -d "/opt/CTF_Public" ]]; then
  INSTALL_DIR="/opt/CTF_Public"
else
  # TEACHING NOTE — Prompting as a last resort, not a first resort.
  # We only reach this branch when no repo exists anywhere on disk and
  # --prod was not passed. Empty input accepts the production default.
  #
  # Tilde expansion: the `read` builtin stores input as a literal string.
  # The ${var/#\~/$HOME} substitution replaces a leading ~ with $HOME.
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
if $SHOW_HELP; then
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
  echo "  ctf-sync              Auto-detect install location"
  echo "  ctf-sync --prod       Force production path (/opt/CTF_Public)"
  echo "  ctf-sync --help       Show this message"
  echo ""
  echo "  ${BOLD}Dual-Install Note:${RESET}"
  echo "  If both ~/github/CTF_Public and /opt/CTF_Public exist, the dev"
  echo "  path is used by default. Use --prod to explicitly target prod."
  echo ""
  echo "  ${BOLD}Dev Override:${RESET}"
  echo "  export CTF_REPO_DIR=~/github/CTF_Public"
  echo "  ctf-sync"
  echo ""
  exit 0
fi

# --- Header -------------------------------------------------------------------
echo ""
echo "${BOLD}${CYAN}=== CTF Repo CTF Sync ===${RESET}"
echo "${DIM}  Repo:   $REPO_URL${RESET}"
echo "${DIM}  Target: $INSTALL_DIR${RESET}"

if $FORCE_PROD; then
  echo "${YELLOW}  Mode:   production (--prod)${RESET}"
elif [[ "$INSTALL_DIR" == "$HOME"* ]]; then
  echo "${DIM}  Mode:   dev (auto-detected)${RESET}"
else
  echo "${DIM}  Mode:   production (auto-detected)${RESET}"
fi
echo ""

# --- Step 1: Clone or Pull ----------------------------------------------------
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  # Repo exists — pull latest
  echo "${CYAN}[SYNC]${RESET}  Local repo found. Pulling latest changes..."
  echo ""

  cd "$INSTALL_DIR" || { echo "${RED}[ERROR]${RESET} Cannot cd into $INSTALL_DIR"; exit 1; }

  # ==========================================================================
  # TEACHING NOTE — Applying core.fileMode false before pulling. (New)
  #
  # Every time ctf-install.sh or ctf-sync.sh runs chmod +x on the scripts
  # in setup/, git records the execute bit change as a local modification.
  # From git's perspective the file has been edited, even though the content
  # is identical to what's in the remote. This causes `git pull` to fail
  # with "Your local changes would be overwritten" on every subsequent sync,
  # forcing a manual `git checkout` on each affected file before pulling.
  #
  # `git config core.fileMode false` tells git to stop tracking execute bit
  # changes entirely for this repository. Once set, chmod +x no longer makes
  # files appear modified, and pulls proceed cleanly regardless of what
  # permission changes have been applied locally.
  #
  # We apply it here — before the pull — so that any permission-related dirt
  # in the working tree is immediately invisible to git, allowing the pull to
  # succeed without manual intervention. Running it on every sync is harmless:
  # setting a git config value that is already set is a no-op. This also means
  # existing installations that were set up without this config get fixed
  # automatically the next time ctf-sync runs, with no manual steps required.
  # ==========================================================================
  echo "${CYAN}[CONFIG]${RESET} Setting core.fileMode false..."
  git config core.fileMode false
  echo "${GREEN}[OK]${RESET}    Permission changes will not be tracked by git."
  echo ""

  CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
  echo "${DIM}  Branch: $CURRENT_BRANCH${RESET}"

  PULL_OUTPUT=$(git pull origin "$CURRENT_BRANCH" 2>&1)
  PULL_EXIT=$?

  if [[ $PULL_EXIT -ne 0 ]]; then
    echo "${RED}[ERROR]${RESET} Git pull failed:"
    echo "$PULL_OUTPUT"
    exit 1
  fi

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

  # ==========================================================================
  # TEACHING NOTE — Applying core.fileMode false after a fresh clone. (New)
  #
  # A fresh clone starts with a clean working tree, so there are no dirty
  # files to worry about yet. However ctf-install.sh (which runs next) will
  # immediately call chmod +x on every script in setup/. Without this config,
  # those permission changes would be recorded as local modifications, and
  # the very first `ctf-sync` after install would fail.
  #
  # Setting it immediately after clone means the repo is correctly configured
  # before any other tooling touches it. The sequence is:
  #   1. Clone               — clean working tree
  #   2. core.fileMode false — git stops watching execute bits
  #   3. ctf-install chmod   — permissions change, but git doesn't notice
  #   4. ctf-sync pull       — succeeds cleanly every time
  #
  # Using `git -C "$INSTALL_DIR"` runs the git command inside the repo
  # directory without requiring a `cd` first. This keeps the script's working
  # directory unchanged and avoids any side effects from directory switching.
  # ==========================================================================
  echo ""
  echo "${CYAN}[CONFIG]${RESET} Setting core.fileMode false..."
  git -C "$INSTALL_DIR" config core.fileMode false
  echo "${GREEN}[OK]${RESET}    Permission changes will not be tracked by git."
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
echo "  ${DIM}Tip: Add this to your toolkit:${RESET}"
if [[ "$INSTALL_DIR" == /opt/* ]]; then
  echo "  ${BOLD}sudo ln -sf ${INSTALL_DIR}/setup/ctf-sync.sh /usr/local/bin/ctf-sync${RESET}"
else
  echo "  ${BOLD}ln -sf ${INSTALL_DIR}/setup/ctf-sync.sh /usr/local/bin/ctf-sync${RESET}"
fi
echo "  ${DIM}Then run ${BOLD}ctf-sync${RESET}${DIM} from anywhere to stay up to date.${RESET}"
echo ""