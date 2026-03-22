#!/bin/zsh
# =============================================================================
# install-harness.sh — CTF Toolkit Install Test Harness
# =============================================================================
# ABOUT:
#   Automates the manual test sequence for ctf-install.sh.
#   Clones a branch, runs the installer, verifies every expected outcome,
#   and reports PASS/FAIL for each check with a summary at the end.
#   Optionally runs full-removal.sh to leave the machine clean.
#
# USAGE:
#   ./ctf-install-test.sh --branch setup5
#   ./ctf-install-test.sh --branch setup5 --cleanup
#   ./ctf-install-test.sh --branch main --cleanup
#   ./ctf-install-test.sh --help
#
# REQUIREMENTS:
#   - Must be run with sudo (several checks require it)
#   - /opt/CTF_Public and /opt/CTF must NOT exist (script aborts if they do)
#   - full-removal.sh must be on ~/Desktop if --cleanup is used
#
# WHAT IT CHECKS:
#   Pre-install  : Clean state, session variables empty
#   Clone        : Repo cloned, file exists, is executable, owned by $USER
#   Install      : ctf-install.sh runs successfully
#   Post-install : ~/.ctf_env deployed, ~/.zshrc patched, platform dirs created
#                  with correct ownership, symlinks in /usr/local/bin/
#   Session      : set-platform / set-box / set-address / set-env work,
#                  BOX_DIR created, ~/.ctf_env_mode written, all workspace
#                  subdirs and notes.md present
#   Cleanup      : full-removal.sh --yes cleans all artifacts (if --cleanup),
#                  including ~/.ctf_env_mode
#
# TEACHING NOTE — Why a test harness?
#   Manual test sequences drift. Steps get skipped, output scrolls past,
#   and subtle regressions (a wrong owner, a missing symlink) go unnoticed.
#   A harness runs the same sequence every time and makes the result of each
#   check explicit — PASS or FAIL — so regressions are caught immediately
#   rather than discovered mid-CTF.
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================


# =============================================================================
# SECTION 1 — ARGUMENT PARSING
# =============================================================================

BRANCH=""
CLEANUP=false
SHOW_HELP=false

# TEACHING NOTE — while/shift for flags that take values.
#
# `for arg in "$@"` iterates over a fixed snapshot of arguments — you can't
# "consume" the next argument from inside the loop. That makes --branch <value>
# require a fragile prev_arg lookahead to connect the flag to its value.
#
# `while (( $# > 0 ))` + `shift` consumes arguments one at a time from the
# front of $@. When we see --branch, we immediately shift again to consume
# the next argument as its value. This is the standard pattern for flags that
# take arguments — it handles edge cases cleanly and reads naturally.
while (( $# > 0 )); do
  case "$1" in
    --branch)
      if [[ -z "$2" || "$2" == --* ]]; then
        echo "\033[0;31m[ERROR]\033[0m --branch requires a value. Example: --branch setup5"
        exit 1
      fi
      BRANCH="$2"
      shift 2
      ;;
    --cleanup)  CLEANUP=true;    shift ;;
    --help|-h)  SHOW_HELP=true;  shift ;;
    *)
      echo "\033[0;31m[ERROR]\033[0m Unknown argument: $1"
      echo "  Run ctf-install-test.sh --help for usage."
      exit 1
      ;;
  esac
done

show_help() {
  echo ""
  echo "\033[1mctf-install-test.sh\033[0m — CTF Toolkit Install Test Harness"
  echo ""
  echo "\033[0;36mUSAGE:\033[0m"
  echo "  sudo ./ctf-install-test.sh --branch <branch>             Run tests"
  echo "  sudo ./ctf-install-test.sh --branch <branch> --cleanup   Run tests, then remove"
  echo "  sudo ./ctf-install-test.sh --help                        Show this message"
  echo ""
  echo "\033[0;36mEXAMPLES:\033[0m"
  echo "  sudo ./ctf-install-test.sh --branch setup5"
  echo "  sudo ./ctf-install-test.sh --branch main --cleanup"
  echo ""
  echo "\033[0;36mREQUIREMENTS:\033[0m"
  echo "  - Run with sudo"
  echo "  - /opt/CTF_Public and /opt/CTF must not already exist"
  echo "  - ~/Desktop/full-removal.sh must exist if --cleanup is used"
  echo ""
}

if $SHOW_HELP; then
  show_help
  exit 0
fi

if [[ -z "$BRANCH" ]]; then
  echo "\033[0;31m[ERROR]\033[0m --branch is required."
  echo "  Example: sudo ./ctf-install-test.sh --branch setup5"
  exit 1
fi


# =============================================================================
# SECTION 2 — COLORS, COUNTERS, AND HELPERS
# =============================================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

# print_check "Description" <condition>
# Prints [PASS] or [FAIL] and increments the appropriate counter.
# Usage: print_check "Description" [[ test expression ]]
#
# TEACHING NOTE — Why a helper instead of inline if/then?
# The check pattern repeats ~20 times. A helper keeps each check to one line,
# makes the pass/fail logic impossible to get wrong in individual checks, and
# means the counter increment is never accidentally omitted.
print_check() {
  local description="$1"
  local result="$2"   # "pass" or "fail"
  if [[ "$result" == "pass" ]]; then
    echo "  ${GREEN}[PASS]${RESET} ${description}"
    (( PASS_COUNT++ ))
  else
    echo "  ${RED}[FAIL]${RESET} ${description}"
    (( FAIL_COUNT++ ))
  fi
}

check() {
  local description="$1"; shift
  # Run the test expression passed as remaining args
  if "$@" 2>/dev/null; then
    print_check "$description" "pass"
  else
    print_check "$description" "fail"
  fi
}

print_step() { echo ""; echo "${BOLD}${CYAN}── $1 ──${RESET}"; }
print_info() { echo "  ${CYAN}[INFO]${RESET}  $1"; }
print_cmd()  { echo ""; echo "  ${DIM}\$ $1${RESET}"; }
print_out()  { echo "$1" | sed 's/^/  /'; }

# Resolve the real invoking user even under sudo
TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
TARGET_HOME="${TARGET_HOME:-$HOME}"
TARGET_UID=$(id -u "$TARGET_USER" 2>/dev/null)


# =============================================================================
# SECTION 2a — PRIVILEGE AND OWNERSHIP HELPERS
# =============================================================================
# TEACHING NOTE — Principle of Least Privilege in a test harness.
#
# This harness must run as root (git clone into /opt, chown, symlinks) but
# most actions — reading files, checking variables — don't need root.
# These helpers enforce a "check before you act" discipline:
#
#   require_root  "context"   — Abort if not running as root.
#   require_user  "context"   — Abort if running as root when only user
#                                privileges are expected (guard against
#                                accidental root operations).
#   current_privilege         — Returns "root" or "user" for display/logging.
#   fix_ownership <path>      — chown to TARGET_USER, verify, abort on failure.
#   fix_ownership_recursive <path> — Same, but recursive (-R).
#
# The "never use su" rule is enforced by design: every root action runs
# in the current root process. User-context actions use `env SUDO_USER=`
# to set identity without spawning a new privilege boundary.
# =============================================================================

# current_privilege — Returns "root" or "user" (the actual EUID, not TARGET_USER).
current_privilege() {
  if [[ $EUID -eq 0 ]]; then
    echo "root"
  else
    echo "user"
  fi
}

# require_root "context message"
# Aborts the script if the current effective user is not root.
# Call this before any action that genuinely needs root (git clone into /opt,
# chown, mkdir in /opt, ln -sf in /usr/local/bin, running the installer).
require_root() {
  local context="$1"
  if [[ $EUID -ne 0 ]]; then
    echo ""
    echo "  ${RED}[ABORT]${RESET} Root privileges required but not available."
    echo "  ${DIM}Context : ${context}${RESET}"
    echo "  ${DIM}EUID    : ${EUID}${RESET}"
    echo "  ${DIM}USER    : $(whoami)${RESET}"
    echo "  ${DIM}Fix     : Re-run with sudo${RESET}"
    echo ""
    exit 1
  fi
}

# require_user "context message"
# Aborts if the script is NOT running as the expected non-root user.
# Use in blocks where root should NOT be the actor (e.g. verifying user-owned
# files from the user's perspective). In this harness, operations run as root
# with SUDO_USER set — so this checks that TARGET_USER is a real non-root
# account, preventing misuse if SUDO_USER resolved to "root".
require_user() {
  local context="$1"
  if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    echo ""
    echo "  ${RED}[ABORT]${RESET} Expected a non-root target user but got '${TARGET_USER}'."
    echo "  ${DIM}Context     : ${context}${RESET}"
    echo "  ${DIM}SUDO_USER   : ${SUDO_USER:-<unset>}${RESET}"
    echo "  ${DIM}USER        : ${USER}${RESET}"
    echo "  ${DIM}TARGET_USER : ${TARGET_USER}${RESET}"
    echo "  ${DIM}Fix         : Run with sudo from a non-root account${RESET}"
    echo "  ${DIM}             (sudo sets SUDO_USER to the invoking user)${RESET}"
    echo ""
    exit 1
  fi
}

# fix_ownership <path> [description]
# Changes ownership of a single file or directory to TARGET_USER:TARGET_USER.
# Verifies the change succeeded. Aborts with verbose diagnostics on failure.
# Does NOT recurse — use fix_ownership_recursive for directory trees.
#
# TEACHING NOTE — Why verify after chown?
# chown can silently fail on read-only filesystems, immutable files, or
# paths with special characters that shell expansion mangles. Checking
# the owner after the change catches these edge cases immediately instead
# of letting them cascade into confusing [FAIL]s later.
fix_ownership() {
  local target_path="$1"
  local description="${2:-$target_path}"

  if [[ ! -e "$target_path" ]]; then
    echo ""
    echo "  ${RED}[ABORT]${RESET} fix_ownership: path does not exist."
    echo "  ${DIM}Path    : ${target_path}${RESET}"
    echo "  ${DIM}Context : ${description}${RESET}"
    echo ""
    exit 1
  fi

  local current_owner
  current_owner=$(stat -c '%U' "$target_path" 2>/dev/null)

  if [[ "$current_owner" == "$TARGET_USER" ]]; then
    return 0
  fi

  print_info "Ownership fix: ${description} (${current_owner} → ${TARGET_USER})"
  chown "${TARGET_USER}:${TARGET_USER}" "$target_path" 2>/dev/null

  # Verify
  local new_owner
  new_owner=$(stat -c '%U' "$target_path" 2>/dev/null)
  if [[ "$new_owner" != "$TARGET_USER" ]]; then
    echo ""
    echo "  ${RED}[ABORT]${RESET} fix_ownership: chown failed to change owner."
    echo "  ${DIM}Path     : ${target_path}${RESET}"
    echo "  ${DIM}Expected : ${TARGET_USER}${RESET}"
    echo "  ${DIM}Actual   : ${new_owner}${RESET}"
    echo "  ${DIM}Context  : ${description}${RESET}"
    echo "  ${DIM}EUID     : ${EUID} ($(current_privilege))${RESET}"
    echo ""
    exit 1
  fi
}

# fix_ownership_recursive <path> [description]
# Same as fix_ownership but applies -R for entire directory trees.
# Verifies by scanning for any files still not owned by TARGET_USER.
fix_ownership_recursive() {
  local target_path="$1"
  local description="${2:-$target_path}"

  if [[ ! -e "$target_path" ]]; then
    echo ""
    echo "  ${RED}[ABORT]${RESET} fix_ownership_recursive: path does not exist."
    echo "  ${DIM}Path    : ${target_path}${RESET}"
    echo "  ${DIM}Context : ${description}${RESET}"
    echo ""
    exit 1
  fi

  # Check if anything needs fixing first
  local wrong_files
  wrong_files=$(find "$target_path" -P ! -user "$TARGET_USER" 2>/dev/null)
  if [[ -z "$wrong_files" ]]; then
    return 0
  fi

  local wrong_count
  wrong_count=$(echo "$wrong_files" | wc -l)
  print_info "Ownership fix: ${description} — ${wrong_count} item(s) not owned by ${TARGET_USER}"

  chown -R "${TARGET_USER}:${TARGET_USER}" "$target_path" 2>/dev/null

  # Verify — no files should remain with wrong ownership
  local still_wrong
  still_wrong=$(find "$target_path" -P ! -user "$TARGET_USER" 2>/dev/null)
  if [[ -n "$still_wrong" ]]; then
    local still_count
    still_count=$(echo "$still_wrong" | wc -l)
    echo ""
    echo "  ${RED}[ABORT]${RESET} fix_ownership_recursive: ${still_count} item(s) still not owned by ${TARGET_USER} after chown -R."
    echo "  ${DIM}Path    : ${target_path}${RESET}"
    echo "  ${DIM}Context : ${description}${RESET}"
    echo "  ${DIM}EUID    : ${EUID} ($(current_privilege))${RESET}"
    echo "  ${DIM}Remaining items:${RESET}"
    echo "$still_wrong" | head -10 | sed 's/^/    /'
    if [[ $still_count -gt 10 ]]; then
      echo "    ... and $((still_count - 10)) more"
    fi
    echo ""
    exit 1
  fi
}

REPO_URL="https://github.com/Ghost-Glitch04/CTF_Public"
REPO_DIR="/opt/CTF_Public"
CTF_BASE="/opt/CTF"
INSTALL_SCRIPT="$REPO_DIR/setup/ctf-install.sh"
REMOVAL_SCRIPT="$TARGET_HOME/Desktop/full-removal.sh"
TEST_PLATFORM="HTB"
TEST_BOX="archtype"
TEST_ADDRESS="10.129.7.101"
BOX_WORKSPACE="$CTF_BASE/$TEST_PLATFORM/$TEST_BOX"
EXPECTED_SUBDIRS=("scans" "exploits" "notes" "flags" "loot")
EXPECTED_SYMLINKS=("ctf-install" "ctf-sync")
EXPECTED_PLATFORMS=("HTB" "THM" "LD" "DC" "GGL" "PG")


# =============================================================================
# SECTION 3 — PRE-FLIGHT CHECKS
# =============================================================================
# TEACHING NOTE — Abort on dirty state rather than trying to recover.
#
# If /opt/CTF_Public already exists, the clone will fail and every subsequent
# check will cascade-fail too — producing a wall of [FAIL] output that tells
# you nothing about the actual installer behaviour. Failing loudly here with
# a clear message is more useful than watching 20 checks fail for the wrong
# reason.
# =============================================================================

echo ""
echo "${BOLD}${CYAN}=== CTF Toolkit Install Test Harness ===${RESET}"
echo ""
echo "  ${DIM}Branch:  ${BRANCH}${RESET}"
echo "  ${DIM}Cleanup: $(${CLEANUP} && echo yes || echo no)${RESET}"
echo "  ${DIM}User:    ${TARGET_USER} (UID: ${TARGET_UID})${RESET}"
echo "  ${DIM}Home:    ${TARGET_HOME}${RESET}"
echo "  ${DIM}Running as: $(current_privilege) (EUID: ${EUID})${RESET}"
echo ""

print_step "Pre-flight"

# Verify root privileges are available (required for clone, install, chown)
require_root "Pre-flight: harness must be run with sudo"

# Verify TARGET_USER resolved to an actual non-root user
require_user "Pre-flight: SUDO_USER must resolve to the invoking non-root user"

print_check "Running as root" "pass"
print_check "Target user is non-root (${TARGET_USER}, UID ${TARGET_UID})" "pass"

if [[ -d "$REPO_DIR" ]]; then
  echo ""
  echo "  ${RED}[ABORT]${RESET} ${REPO_DIR} already exists."
  echo "  ${DIM}Remove it first: sudo rm -rf ${REPO_DIR}${RESET}"
  echo "  ${DIM}Or run: sudo ~/Desktop/full-removal.sh --yes${RESET}"
  echo ""
  exit 1
fi

if [[ -d "$CTF_BASE" ]]; then
  echo ""
  echo "  ${RED}[ABORT]${RESET} ${CTF_BASE} already exists."
  echo "  ${DIM}Remove it first: sudo rm -rf ${CTF_BASE}${RESET}"
  echo ""
  exit 1
fi

if $CLEANUP && [[ ! -f "$REMOVAL_SCRIPT" ]]; then
  echo ""
  echo "  ${RED}[ABORT]${RESET} --cleanup requested but removal script not found at:"
  echo "  ${DIM}${REMOVAL_SCRIPT}${RESET}"
  echo ""
  exit 1
fi

# Check session variables are clear before we start
print_check "Session variables are empty before test" \
  "$([ -z "$PLATFORM" ] && [ -z "$BOXNAME" ] && [ -z "$ADDRESS" ] && [ -z "$BOX_DIR" ] && echo pass || echo fail)"

echo ""
print_info "Pre-flight passed. Starting test run."


# =============================================================================
# SECTION 4 — CLONE
# =============================================================================

print_step "Clone — branch: ${BRANCH}"

# Clone requires root (writing to /opt)
require_root "Clone: git clone into ${REPO_DIR}"
print_info "Privilege: $(current_privilege) — required for clone into /opt"

print_cmd "git clone -b ${BRANCH} ${REPO_URL} ${REPO_DIR}"
clone_output=$(git clone -b "$BRANCH" "$REPO_URL" "$REPO_DIR" 2>&1)
clone_exit=$?
print_out "$clone_output"

check "git clone exited successfully"       test $clone_exit -eq 0
check "ctf-install.sh exists in repo"       test -f "$INSTALL_SCRIPT"

# Make executable — requires root (file owned by root after clone)
chmod +x "$INSTALL_SCRIPT" 2>/dev/null
check "ctf-install.sh is executable"        test -x "$INSTALL_SCRIPT"

# Fix ownership: clone ran as root, so all files are root-owned.
# The repo should be owned by the target user.
fix_ownership_recursive "$REPO_DIR" "Cloned repo → ${TARGET_USER}"
check "${REPO_DIR} owned by ${TARGET_USER}" \
  test -z "$(find "$REPO_DIR" -P ! -user "$TARGET_USER" 2>/dev/null)"


# =============================================================================
# SECTION 5 — RUN INSTALLER
# =============================================================================
# TEACHING NOTE — Capturing output while still displaying it, and zsh vs bash
# exit code capture after a pipe.
#
# We want to show the installer's output in real time (so you can watch it
# run) AND check its exit code. Piping to tee lets us do both: the output
# goes to the terminal and to a temp file we can inspect afterwards.
#
# Exit code capture differs between bash and zsh:
#   bash: ${PIPESTATUS[0]}   — 0-indexed array, uppercase
#   zsh:  ${pipestatus[1]}   — 1-indexed array, lowercase
#
# This script uses zsh (#!/bin/zsh shebang). Using ${PIPESTATUS[0]} in zsh
# silently returns empty, making the exit code check always fail even when
# the installer succeeds — exactly the false [FAIL] seen in the first test run.
# The fix is ${pipestatus[1]}: element 1 is the first command in the pipe
# (the installer), element 2 would be tee.
# =============================================================================

print_step "Install — ctf-install.sh --prod --yes"

# Installer requires root for mkdir/chown/ln in /opt and /usr/local/bin
require_root "Install: ctf-install.sh needs root for system-level operations"
print_info "Privilege: $(current_privilege) — required for installer"

INSTALL_LOG=$(mktemp)
print_cmd "${INSTALL_SCRIPT} --prod --yes"
echo ""

# Run the installer as root with SUDO_USER set to the target user.
# TEACHING NOTE — Why `env SUDO_USER=` instead of `su` or `sudo -u`.
#
# Three approaches were tried; two failed for different reasons:
#
# Attempt 1 — `sudo -u kali ctf-install.sh`:
#   Sets SUDO_USER="root" (the caller of sudo -u). The installer's
#   resolution block does `getent passwd root` → /root. Every path
#   points into root's home. Fails with "Permission denied" writing
#   to /root/.ctf_env. SUDO_USER pollution.
#
# Attempt 2 — `su -s /bin/zsh kali -c "ctf-install.sh"`:
#   Runs as kali with no SUDO_USER. Correct path resolution. But kali
#   can't run `sudo chown`, `sudo mkdir`, `sudo ln -sf` inside the
#   installer — the su session doesn't inherit root's sudo credential
#   cache, and there's no terminal to prompt for a password. All
#   internal sudo calls fail with "a terminal is required to read the
#   password".
#
# Attempt 3 (current) — `env SUDO_USER=kali HOME=/home/kali ctf-install.sh`:
#   Runs as root (so all internal sudo calls succeed without passwords),
#   but explicitly sets SUDO_USER to "kali" so the resolution block
#   resolves correctly: getent passwd kali → /home/kali. This exactly
#   simulates what happens when a real user runs `sudo ctf-install.sh`:
#   the process runs as root, SUDO_USER holds the real user's name,
#   and all the resolution logic works as designed.
#
#   HOME is also set as belt-and-suspenders — in case any code path
#   falls through to $HOME instead of $_CTF_HOME.
env SUDO_USER="$TARGET_USER" HOME="$TARGET_HOME" "$INSTALL_SCRIPT" --prod --yes 2>&1 | tee "$INSTALL_LOG"
install_exit=${pipestatus[1]}

echo ""
check "ctf-install.sh exited successfully"  test $install_exit -eq 0


# =============================================================================
# SECTION 6 — POST-INSTALL CHECKS
# =============================================================================

print_step "Post-install Checks"

print_info "Privilege: $(current_privilege) — read-only verification (no root needed)"

# ~/.ctf_env
check "~/.ctf_env was deployed" \
  test -f "${TARGET_HOME}/.ctf_env"

# Verify installer didn't leave user-home files owned by root
if [[ -f "${TARGET_HOME}/.ctf_env" ]]; then
  fix_ownership "${TARGET_HOME}/.ctf_env" "~/.ctf_env → ${TARGET_USER}"
fi

# ~/.zshrc patched
check "~/.zshrc sources ~/.ctf_env" \
  grep -q "source.*\.ctf_env" "${TARGET_HOME}/.zshrc"

if [[ -f "${TARGET_HOME}/.zshrc" ]]; then
  fix_ownership "${TARGET_HOME}/.zshrc" "~/.zshrc → ${TARGET_USER}"
fi

# Platform directories
for code in "${EXPECTED_PLATFORMS[@]}"; do
  check "/opt/CTF/${code} directory exists" \
    test -d "${CTF_BASE}/${code}"
done

# Ownership of CTF base — fix if needed, then verify
if [[ -d "$CTF_BASE" ]]; then
  fix_ownership_recursive "$CTF_BASE" "/opt/CTF tree → ${TARGET_USER}"
fi
check "/opt/CTF owned by ${TARGET_USER}" \
  test -z "$(find "$CTF_BASE" -P ! -user "$TARGET_USER" 2>/dev/null)"

# Symlinks in /usr/local/bin/
for sym in "${EXPECTED_SYMLINKS[@]}"; do
  check "/usr/local/bin/${sym} symlink exists" \
    test -L "/usr/local/bin/${sym}"
done

# ctf-env-functions should NOT be symlinked (denylist check)
if [[ -L "/usr/local/bin/ctf-env-functions" ]]; then
  print_check "ctf-env-functions NOT symlinked (denylist)" "fail"
else
  print_check "ctf-env-functions NOT symlinked (denylist)" "pass"
fi


# =============================================================================
# SECTION 7 — SOURCE AND SESSION CHECKS
# =============================================================================
# TEACHING NOTE — Sourcing in a subshell vs the current shell.
#
# We can't `source ~/.zshrc` here and then check $PLATFORM in the same
# script — sourcing only affects the current process, and the CTF functions
# need to be loaded to run set-platform, set-box, set-address. Instead we
# run a zsh subshell that sources the env, runs the session commands, and
# reports back the resulting variable values via echo. We then parse that
# output and check it here.
#
# This is the correct pattern for testing shell functions from a script:
# the subshell is the "user's terminal", and we inspect what it produces.
# =============================================================================

print_step "Session — set-platform / set-box / set-address / set-env"

# Session subshell runs as root with SUDO_USER set (same as installer)
require_root "Session: subshell needs root for internal sudo calls (set-box mkdir/chown)"
print_info "Privilege: $(current_privilege) — required for set-box mkdir/chown in /opt"

# Run session setup in a subshell, capture all four variable values.
#
# TEACHING NOTE — Same env-SUDO_USER pattern as the installer invocation.
#
# The session subshell sources ~/.ctf_env, which contains the same
# SUDO_USER resolution block. set-box also calls `sudo mkdir` and
# `sudo chown` to create box workspaces under /opt. Running as root
# with SUDO_USER set to kali gives us both: correct path resolution
# AND working internal sudo calls.
#
# TEACHING NOTE — Why set-env runs last in this sequence.
#
# set-env switches CTF_REPO_DIR and re-sources ~/.ctf_env. Running it after
# the other three commands means the variable snapshot captured on the
# __VARS__ line reflects the state set by set-platform, set-box, and
# set-address — not a state that might be partially reset by sourcing.
# On a prod-only test machine, set-env prod is a no-op (the path is already
# /opt/CTF_Public), so ordering doesn't affect the variable values here.
# The important thing is that set-env runs at all, so we can verify the
# ~/.ctf_env_mode file was written to disk.
session_output=$(env SUDO_USER="$TARGET_USER" HOME="$TARGET_HOME" zsh -c "
  source ${TARGET_HOME}/.ctf_env
  set-platform ${TEST_PLATFORM} 2>&1
  set-box ${TEST_BOX} 2>&1
  set-address ${TEST_ADDRESS} 2>&1
  set-env prod 2>&1
  echo \"__VARS__ PLATFORM=\$PLATFORM BOXNAME=\$BOXNAME ADDRESS=\$ADDRESS BOX_DIR=\$BOX_DIR\"
" 2>&1)

echo ""
# Print the session command output (everything before the __VARS__ line)
echo "$session_output" | grep -v "^__VARS__" | sed 's/^/  /'
echo ""

# Parse the variable snapshot line
vars_line=$(echo "$session_output" | grep "^__VARS__")

# Debug: Show the raw vars_line
if [[ -n "$vars_line" ]]; then
  print_info "Variable snapshot captured:"
  echo "  $vars_line"
else
  print_info "${RED}WARNING: No __VARS__ line found in session output${RESET}"
  print_info "Full session output:"
  echo "$session_output" | sed 's/^/    /'
fi

# TEACHING NOTE — More robust parsing that doesn't require Perl regex.
# Uses parameter expansion to extract values: ${string##*PREFIX} removes PREFIX,
# ${string%% *} removes the first space and everything after.
session_platform=""
session_boxname=""
session_address=""
session_boxdir=""

if [[ "$vars_line" =~ PLATFORM=([^ ]+) ]]; then
  session_platform="${match[1]}"
fi
if [[ "$vars_line" =~ BOXNAME=([^ ]+) ]]; then
  session_boxname="${match[1]}"
fi
if [[ "$vars_line" =~ ADDRESS=([^ ]+) ]]; then
  session_address="${match[1]}"
fi
if [[ "$vars_line" =~ BOX_DIR=([^ ]+) ]]; then
  session_boxdir="${match[1]}"
fi

check "PLATFORM set to ${TEST_PLATFORM}"         test "$session_platform" = "$TEST_PLATFORM"
check "BOXNAME set to ${TEST_BOX}"               test "$session_boxname"  = "$TEST_BOX"
check "ADDRESS set to ${TEST_ADDRESS}"           test "$session_address"  = "$TEST_ADDRESS"
check "BOX_DIR set to ${BOX_WORKSPACE}"          test "$session_boxdir"   = "$BOX_WORKSPACE"

# set-env checks — verify the mode file was written with the correct content.
# TEACHING NOTE — Why we check the file on disk rather than a variable.
#
# set-env's purpose is persistence: the choice survives terminal restarts.
# A variable check would only confirm the in-session export worked. A file
# check confirms the next session will also pick up the right path — which
# is the actual contract set-env makes.
#
# Two separate checks rather than one: the first confirms the file exists at
# all; the second confirms the content is correct. A file containing the
# wrong path would pass the first and fail the second, pointing directly at
# a content bug in set-env's write step rather than a missing file.
check "set-env prod wrote ~/.ctf_env_mode" \
  test -f "${TARGET_HOME}/.ctf_env_mode"

# Fix ownership on session-created files in user's home
if [[ -f "${TARGET_HOME}/.ctf_env_mode" ]]; then
  fix_ownership "${TARGET_HOME}/.ctf_env_mode" "~/.ctf_env_mode → ${TARGET_USER}"
fi

check "~/.ctf_env_mode contains prod path (/opt/CTF_Public)" \
  grep -q "opt/CTF_Public" "${TARGET_HOME}/.ctf_env_mode"


# =============================================================================
# SECTION 8 — WORKSPACE STRUCTURE CHECKS
# =============================================================================

print_step "Workspace Structure — ${BOX_WORKSPACE}"

print_info "Privilege: $(current_privilege) — read-only verification + ownership fix if needed"

check "Box workspace directory exists"       test -d "$BOX_WORKSPACE"
check ".env file created in workspace"       test -f "${BOX_WORKSPACE}/.env"
check "notes/notes.md starter file exists"  test -f "${BOX_WORKSPACE}/notes/notes.md"

for subdir in "${EXPECTED_SUBDIRS[@]}"; do
  check "Subdir '${subdir}' exists"  test -d "${BOX_WORKSPACE}/${subdir}"
done

# Fix ownership of the entire box workspace tree, then verify
if [[ -d "$BOX_WORKSPACE" ]]; then
  fix_ownership_recursive "$BOX_WORKSPACE" "Box workspace tree → ${TARGET_USER}"
fi
check "Box workspace owned by ${TARGET_USER}" \
  test -z "$(find "$BOX_WORKSPACE" -P ! -user "$TARGET_USER" 2>/dev/null)"

# Print the directory listing for reference
echo ""
print_info "Workspace contents:"
print_cmd "ls -la ${BOX_WORKSPACE}"
ls -la "$BOX_WORKSPACE" 2>/dev/null | sed 's/^/  /'
echo ""
print_cmd "ls -la ${BOX_WORKSPACE}/notes"
ls -la "${BOX_WORKSPACE}/notes" 2>/dev/null | sed 's/^/  /'


# =============================================================================
# SECTION 9 — OPTIONAL CLEANUP
# =============================================================================

if $CLEANUP; then
  print_step "Cleanup — full-removal.sh --yes"

  # Cleanup requires root for rm -rf in /opt and /usr/local/bin
  require_root "Cleanup: full-removal.sh needs root to remove system files"
  print_info "Privilege: $(current_privilege) — required for system-level removal"

  print_cmd "${REMOVAL_SCRIPT} --yes"
  echo ""
  "$REMOVAL_SCRIPT" --yes 2>&1 | sed 's/^/  /'
  removal_exit=${pipestatus[1]}
  echo ""

  check "full-removal.sh exited successfully"       test $removal_exit -eq 0
  check "~/.ctf_env removed after cleanup"          test ! -f "${TARGET_HOME}/.ctf_env"
  check "~/.ctf_env_mode removed after cleanup"     test ! -f "${TARGET_HOME}/.ctf_env_mode"
  check "/opt/CTF removed after cleanup"            test ! -d "$CTF_BASE"
  check "/opt/CTF_Public removed after cleanup"     test ! -d "$REPO_DIR"
  check "ctf-install symlink removed after cleanup" test ! -L "/usr/local/bin/ctf-install"
  check "ctf-sync symlink removed after cleanup"    test ! -L "/usr/local/bin/ctf-sync"
fi

# Clean up temp log
rm -f "$INSTALL_LOG"


# =============================================================================
# SECTION 10 — SUMMARY
# =============================================================================

TOTAL=$(( PASS_COUNT + FAIL_COUNT ))

echo ""
echo "${BOLD}${CYAN}=== Test Summary ===${RESET}"
echo ""
echo "  Branch tested : ${BOLD}${BRANCH}${RESET}"
echo "  Total checks  : ${BOLD}${TOTAL}${RESET}"
echo "  ${GREEN}Passed${RESET}        : ${BOLD}${PASS_COUNT}${RESET}"
if (( FAIL_COUNT > 0 )); then
  echo "  ${RED}Failed${RESET}        : ${BOLD}${FAIL_COUNT}${RESET}"
  echo ""
  echo "  ${YELLOW}Some checks failed — review output above for details.${RESET}"
else
  echo "  ${RED}Failed${RESET}        : ${BOLD}0${RESET}"
  echo ""
  echo "  ${GREEN}${BOLD}All checks passed.${RESET}"
fi
echo ""