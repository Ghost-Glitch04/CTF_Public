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
# The previous version handled --help with a separate `if [[ "$1" == ... ]]`
# check placed after path resolution. This created a subtle bug: flag
# combinations like `ctf-sync --prod --help` would silently skip the help
# output and proceed to sync, because $1 was "--prod", not "--help".
# (Bug fix #2)
#
# The fix moves ALL flag handling into the argument parsing loop, using
# boolean variables (FORCE_PROD, SHOW_HELP) that are then acted on at
# the appropriate point later in the script. This is the same pattern
# ctf-install.sh already used correctly — now both scripts are consistent.
#
# The rule to remember: flags should be parsed once, early, into named
# booleans. Never check $1/$2 directly later in the script — by the time
# you need the information, positional variables may have shifted or the
# check may be reachable via multiple code paths with different $1 values.
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
# This ordering means the dev path always wins when both installs exist,
# which is the right default for a machine primarily used for development.
# On a dual-install machine (e.g. a Kali VM), --prod provides an explicit
# signal to bypass detection and target production directly.
#
# The existence check after FORCE_PROD assignment ensures that --prod
# fails loudly if production was never installed, rather than creating
# a new unexpected directory or proceeding with a broken path.
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
# TEACHING NOTE — Help is now gated on SHOW_HELP, not on $1.
# Because all flags were parsed into booleans above, we can check SHOW_HELP
# here regardless of what order the flags were passed in. This correctly
# handles `ctf-sync --prod --help`, `ctf-sync --help --prod`, and
# `ctf-sync --help` all the same way — show help and exit.
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
    # TEACHING NOTE — Removed unused CHANGED_FILES variable. (Refactor #5)
    #
    # The previous version computed:
    #   CHANGED_FILES=$(echo "$PULL_OUTPUT" | grep -E ... | wc -l | tr -d ' ')
    #
    # This ran a three-stage subshell pipeline (grep → wc → tr) and stored
    # the result in CHANGED_FILES — but then never used that variable anywhere.
    # The file list was printed directly from $PULL_OUTPUT on the very next
    # line, making CHANGED_FILES pure dead code.
    #
    # Removing it is a small but meaningful improvement: the pipeline had real
    # cost (three forked processes), and a reader seeing CHANGED_FILES would
    # naturally search for where it's used, finding nothing. Dead code that
    # looks like it might matter is more confusing than dead code that's
    # obviously unused.
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