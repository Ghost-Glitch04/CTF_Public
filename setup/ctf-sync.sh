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
# EARLY HELP EXIT — before path resolution
# =============================================================================
# TEACHING NOTE — Check SHOW_HELP immediately after argument parsing, before
# any path resolution runs. (Bug fix #2)
#
# The previous version placed the help check after the full path resolution
# block. This meant that on a machine with no repo anywhere on disk, running
# `ctf-sync --help` would fall through to the Pass 4 prompt and ask the user
# where to clone the repo — before they had even seen the help text.
#
# The fix moves the help check here, right after we know what flags were
# passed and before we touch the filesystem. If --help was requested, we
# print the static help text and exit immediately. Path resolution is
# irrelevant for a help request, so there is no reason to run it first.
#
# Note: the help block below still prints the resolved INSTALL_DIR in the
# target line. Since we exit before resolution, we show the production
# default (/opt/CTF_Public) as a representative value. This is acceptable —
# the help output documents how the tool works, not the current machine state.
# =============================================================================
if $SHOW_HELP; then
  echo ""
  echo "${BOLD}ctf-sync.sh${RESET} — CTF Repo CTF Sync"
  echo ""
  echo "  Pulls latest changes if repo exists, clones fresh if it doesn't."
  echo "  Then fixes ownership and makes all .sh scripts executable."
  echo ""
  echo "  ${CYAN}Repo:${RESET}    $REPO_URL"
  echo "  ${CYAN}Target:${RESET}  auto-detected (see detection order below)"
  echo ""
  echo "  ${BOLD}Usage:${RESET}"
  echo "  ctf-sync              Auto-detect install location"
  echo "  ctf-sync --prod       Force production path (/opt/CTF_Public)"
  echo "  ctf-sync --help       Show this message"
  echo ""
  echo "  ${BOLD}Detection Order (without --prod):${RESET}"
  echo "  1. \$CTF_REPO_DIR if already exported"
  echo "  2. ~/github/CTF_Public if it exists"
  echo "  3. /opt/CTF_Public if it exists"
  echo "  4. Prompt on first run"
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

  skip_status_check=false
  PULL_OUTPUT=$(git pull origin "$CURRENT_BRANCH" 2>&1)
  PULL_EXIT=$?

  if [[ $PULL_EXIT -ne 0 ]]; then
    # ==========================================================================
    # TEACHING NOTE — Graceful conflict recovery. (New)
    #
    # When git pull fails because local files would be overwritten, it prints
    # the conflicting filenames in a consistent format:
    #
    #   error: Your local changes to the following files would be overwritten:
    #           setup/ctf-sync.sh
    #           setup/ctf-install.sh
    #
    # Each filename is indented by a tab character on its own line. We parse
    # them using grep to isolate lines that start with whitespace (the filename
    # lines), then awk to strip the leading whitespace and print just the path.
    # The result is a clean array of affected file paths.
    #
    # We check specifically for this known failure pattern before offering
    # recovery. Any other kind of pull failure (network error, merge conflict
    # in content, authentication problem) falls through to a plain error exit —
    # auto-recovery only makes sense when the cause is local file conflicts.
    #
    # The confirmation prompt is deliberate. Overwriting local files is a
    # destructive action. You may occasionally have an intentional local edit
    # you want to keep, and a prompt gives you the chance to bail out and
    # resolve it manually. The [y/N] default-no convention means hitting Enter
    # without reading the prompt will always abort safely.
    #
    # If the user confirms:
    #   1. We iterate the conflict list and run `git checkout -- <file>` on
    #      each one individually, reporting each reset as it happens.
    #   2. We retry the pull. If it succeeds, sync continues normally.
    #      If it fails again (a different error emerged), we exit with the
    #      new error output so the user has accurate diagnostic information.
    #
    # `git checkout -- <file>` resets a tracked file to its last committed
    # state, discarding any local modifications. The -- separator is important:
    # it tells git that everything after it is a filename, not a branch name.
    # Without it, a file named like a branch could be misinterpreted.
    #
    # Note on scope: this recovery only handles files git is already tracking.
    # Untracked local files (new files you created that aren't in the repo)
    # will never appear in this conflict list and are never touched.
    # ==========================================================================

    # Check whether this is a "local changes would be overwritten" failure
    if echo "$PULL_OUTPUT" | grep -q "Your local changes to the following files would be overwritten"; then

      # Parse the conflicting filenames from git's error output.
      # TEACHING NOTE — Robust whitespace stripping with sed. (Refactor #4)
      #
      # The previous version used `awk '{print $1}'` to strip leading
      # whitespace from each indented filename line. awk splits on any
      # whitespace, so a filename containing a space would be silently
      # truncated to just the first word — the rest would be discarded.
      # Shell script filenames rarely contain spaces, but "rarely" is not
      # "never", and a parser that corrupts input silently is worse than
      # one that fails loudly.
      #
      # `sed 's/^[[:space:]]*//'` removes only the leading whitespace from
      # each line, preserving everything after it including any spaces within
      # the filename itself. [[:space:]] is the POSIX character class for
      # whitespace (spaces, tabs, etc.), and the * makes it match zero or
      # more — so lines with no leading whitespace pass through unchanged.
      conflict_files=()
      while IFS= read -r file; do
        [[ -n "$file" ]] && conflict_files+=("$file")
      done < <(echo "$PULL_OUTPUT" | grep -E "^\s+" | sed 's/^[[:space:]]*//')

      # Display the conflict list clearly
      echo ""
      echo "${YELLOW}[WARN]${RESET}  Pull blocked — local changes conflict with remote:"
      echo ""
      for file in "${conflict_files[@]}"; do
        echo "  ${YELLOW}!${RESET}  ${BOLD}${file}${RESET}"
      done
      echo ""
      echo "  These local changes are likely permission-only modifications"
      echo "  from a previous ${BOLD}chmod +x${RESET} run. Overwriting is safe in that case."
      echo "  If you have intentional edits in these files, answer N and"
      echo "  resolve them manually before re-running ${BOLD}ctf-sync${RESET}."
      echo ""
      echo -n "${YELLOW}  Overwrite all conflicting local changes with remote? [y/N]:${RESET} "
      read recovery_confirm

      if [[ "$recovery_confirm" == [yY] ]]; then
        echo ""
        echo "${CYAN}[RECOVER]${RESET} Resetting conflicting files to remote version..."
        echo ""

        # TEACHING NOTE — Plain variable, not local, at script scope. (Bug fix #1)
        #
        # `local` is only valid inside a function body. Using it at the top
        # level of a script (outside any function) is undefined behaviour in
        # zsh — it may be silently ignored, produce a warning, or behave
        # inconsistently across zsh versions. The variable ends up as a plain
        # global either way, but relying on undefined behaviour is fragile.
        #
        # The conflict recovery block lives directly in the script body, not
        # inside a function, so `local` is wrong here. Plain variable
        # assignment is correct. The variable is still scoped to this script's
        # execution — it just isn't function-local, which doesn't matter since
        # there's no function scope to be local to.
        #
        # The same fix applies to conflict_files above.
        recover_failed=false
        for file in "${conflict_files[@]}"; do
          if git checkout -- "$file" 2>/dev/null; then
            echo "  ${GREEN}reset${RESET}  ${DIM}${file}${RESET}"
          else
            echo "  ${RED}fail${RESET}   ${BOLD}${file}${RESET} — could not reset, skipping"
            recover_failed=true
          fi
        done

        echo ""

        # Retry the pull now that conflicts are cleared
        echo "${CYAN}[SYNC]${RESET}  Retrying pull..."
        PULL_OUTPUT=$(git pull origin "$CURRENT_BRANCH" 2>&1)
        PULL_EXIT=$?

        if [[ $PULL_EXIT -ne 0 ]]; then
          echo "${RED}[ERROR]${RESET} Pull failed again after recovery attempt:"
          echo "$PULL_OUTPUT"
          exit 1
        fi

        echo "${GREEN}[OK]${RESET}    Pull successful after conflict recovery."
        if $recover_failed; then
          echo ""
          echo "${YELLOW}[WARN]${RESET}  One or more files could not be reset automatically."
          echo "         Run ${BOLD}git status${RESET} inside ${BOLD}${INSTALL_DIR}${RESET} to inspect remaining issues."
        fi

        # TEACHING NOTE — Skip the post-pull status check after recovery.
        #
        # After a successful conflict recovery and retry, we have already
        # printed a clear success message above. Falling through to the
        # status check below would print a second line — and if the retry
        # happened to return "Already up to date", that message would be
        # factually wrong (changes were pulled). A boolean flag is the
        # correct solution: it skips the status block entirely without
        # corrupting PULL_OUTPUT, which may be needed for accurate display.
        skip_status_check=true

      else
        echo ""
        echo "${DIM}  Aborted. Nothing changed.${RESET}"
        echo ""
        echo "  To resolve manually, run:"
        for file in "${conflict_files[@]}"; do
          echo "  ${BOLD}git -C ${INSTALL_DIR} checkout -- ${file}${RESET}"
        done
        echo "  Then re-run ${BOLD}ctf-sync${RESET}."
        echo ""
        exit 0
      fi

    else
      # A different kind of pull failure — not a local conflict issue
      echo "${RED}[ERROR]${RESET} Git pull failed:"
      echo "$PULL_OUTPUT"
      exit 1
    fi
  fi

  if ! $skip_status_check; then
    if echo "$PULL_OUTPUT" | grep -q "Already up to date"; then
      echo "${GREEN}[OK]${RESET}    Already up to date — no changes pulled."
    else
      echo "${GREEN}[OK]${RESET}    Pull successful."
      echo ""
      echo "${DIM}  Changed files:${RESET}"
      # TEACHING NOTE — Match git stat lines by their distinguishing structure.
      # git pull --stat output looks like: " setup/ctf-sync.sh | 5 +----"
      # The pattern "| <digits>" is unique to file stat lines and avoids
      # matching unrelated output like "Updating abc..def" or remote messages.
      echo "$PULL_OUTPUT" | grep -E "\|\s+[0-9]" | while read -r line; do
        echo "    ${DIM}$line${RESET}"
      done
    fi
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
# TEACHING NOTE — Capture $? immediately after the command you care about. (Bug fix #2)
#
# $? holds the exit code of the last command that ran. The danger with
# checking it inside an `if [[ $? -eq 0 ]]` block that follows an if/fi
# construct is subtle: in zsh, `fi` does not reset $? — so checking $?
# right after fi happens to work. However this is fragile by nature.
# If any line is ever inserted between the fi and the $? check — even a
# print_info call, a blank subshell evaluation, or a debug echo — $? will
# silently reflect that new command instead of chown, and error detection
# breaks without any visible sign.
#
# The safe, unambiguous pattern is to capture $? on the very next line
# after the command you care about, assign it to a named variable, and
# then check that variable. Named variables survive any number of
# intervening lines and make the intent explicit to any reader.
CHOWN_EXIT=$?

if [[ $CHOWN_EXIT -eq 0 ]]; then
  echo "${GREEN}[OK]${RESET}    Ownership set."
else
  echo "${RED}[ERROR]${RESET} chown failed — try running with sudo"
  exit 1
fi

# --- Step 3: Make all scripts executable -------------------------------------
echo ""
echo "${CYAN}[CHMOD]${RESET} Making all .sh scripts executable..."

# TEACHING NOTE — Single find pass with an internal counter. (Refactor #4)
#
# The previous version called `find` twice: once to iterate and chmod each
# script, and again to count the total. Every `find` call walks the entire
# directory tree from scratch, which is redundant when the two passes are
# doing the same traversal back to back.
#
# The fix uses a counter variable (script_count) that increments inside
# the while loop. Because we use a while loop fed by process substitution
# < <(...) rather than a pipe, the loop body runs in the current shell —
# NOT a subshell. This is the critical distinction:
#
#   find ... | while read ...   — runs in a SUBSHELL, counter is lost
#   while read ... < <(find ...) — runs in current shell, counter persists
#
# Piping into while is one of the most common shell scripting mistakes
# because it looks like it should work but silently loses any state
# changes (variable assignments, counter increments) made inside the loop.
# Process substitution < <(...) is the correct zsh/bash pattern when you
# need the loop body to modify variables in the current shell.
script_count=0
while IFS= read -r script; do
  chmod +x "$script"
  echo "  ${GREEN}+x${RESET}  ${DIM}${script#$INSTALL_DIR/}${RESET}"
  (( script_count++ ))
done < <(find "$INSTALL_DIR" -type f -name "*.sh")

echo "${GREEN}[OK]${RESET}    ${BOLD}${script_count}${RESET} script(s) set to executable."

# --- Step 4: Summary ----------------------------------------------------------
echo ""
echo "${BOLD}${CYAN}=== Sync Complete ===${RESET}"
echo ""
echo "  ${CYAN}Location:${RESET}  $INSTALL_DIR"
echo "  ${CYAN}Owner:${RESET}     $REPO_OWNER"
echo "  ${CYAN}Scripts:${RESET}   $script_count executable"
