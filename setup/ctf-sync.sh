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
# TEACHING NOTE — Parse flags before resolving paths.
#
# Flags need to be read before any path resolution happens, because the
# --prod flag directly controls which path gets selected. If we resolved
# the path first and parsed flags second, --prod would have no effect.
#
# We use a simple loop over "$@" (all positional arguments) rather than
# getopts, because we only have a small number of known flags and no flags
# that take values. getopts is worth reaching for when you have many options
# or options with arguments (e.g. --dir /some/path). For two or three
# boolean flags, a loop is clearer and has no dependencies.
#
# FORCE_PROD starts as false. If --prod is passed, it becomes true, and the
# path resolution block below uses it to skip auto-detection entirely and
# jump straight to the production path. This makes the flag's effect
# explicit and easy to trace.
# =============================================================================

FORCE_PROD=false

for arg in "$@"; do
  case "$arg" in
    --prod)   FORCE_PROD=true ;;
    --help|-h) ;; # handled below after path resolution
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
# TEACHING NOTE — --prod short-circuits the detection chain. (New behaviour)
#
# Without --prod, the detection order is:
#   Pass 1: CTF_REPO_DIR already exported in the environment
#   Pass 2: ~/github/CTF_Public exists on disk (dev path)
#   Pass 3: /opt/CTF_Public exists on disk (production path)
#   Pass 4: nothing found — prompt once on first run
#
# This ordering means the dev path always wins when both installs exist,
# which is the right default for a machine that is primarily used for
# development. But on a dual-install machine (e.g. a Kali VM with both
# a personal dev checkout and a shared production install), there's no
# way to reach the production install without an explicit signal.
#
# --prod provides that signal. When FORCE_PROD is true, we skip all
# detection passes and assign /opt/CTF_Public directly. The check still
# validates that the path exists and is a real git repo before proceeding
# — we don't want --prod to silently succeed on a machine where production
# was never installed.
# =============================================================================

if $FORCE_PROD; then
  INSTALL_DIR="/opt/CTF_Public"
  # Validate immediately — fail loudly if prod doesn't exist
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
  # --prod was not passed. Rather than silently defaulting to /opt/ on a
  # dev machine, we ask once. Empty input accepts the production default.
  #
  # Tilde expansion: the `read` builtin stores input as a literal string —
  # it does NOT expand shell metacharacters like ~. The ${var/#\~/$HOME}
  # substitution replaces a leading ~ with the expanded value of $HOME.
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

# TEACHING NOTE — Surface the active mode clearly in the header.
# When --prod is passed, print a visible label so there's no ambiguity
# about which install is being targeted. This is especially important on
# a dual-install machine where the wrong target could cause real confusion.
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