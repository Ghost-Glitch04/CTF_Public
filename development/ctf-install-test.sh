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
echo "  ${DIM}User:    ${TARGET_USER}${RESET}"
echo ""

print_step "Pre-flight"

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

print_cmd "sudo git clone -b ${BRANCH} ${REPO_URL} ${REPO_DIR}"
clone_output=$(sudo git clone -b "$BRANCH" "$REPO_URL" "$REPO_DIR" 2>&1)
clone_exit=$?
print_out "$clone_output"

check "git clone exited successfully"       test $clone_exit -eq 0
check "ctf-install.sh exists in repo"       test -f "$INSTALL_SCRIPT"

# Make executable and fix ownership
sudo chmod +x "$INSTALL_SCRIPT" 2>/dev/null
sudo chown -R "${TARGET_USER}:${TARGET_USER}" "$REPO_DIR" 2>/dev/null

check "ctf-install.sh is executable"        test -x "$INSTALL_SCRIPT"
check "${REPO_DIR} owned by ${TARGET_USER}" \
  test -z "$(find "$REPO_DIR" ! -user "$TARGET_USER" 2>/dev/null)"


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

INSTALL_LOG=$(mktemp)
print_cmd "${INSTALL_SCRIPT} --prod --yes"
echo ""

# Run as the target user (not root) to match real usage.
# -n (non-interactive) prevents sudo from prompting for a password mid-test.
# The outer `sudo` that launched this script already holds credentials;
# a nested `sudo -u` for a different user would prompt again without -n.
sudo -u "$TARGET_USER" -n "$INSTALL_SCRIPT" --prod --yes 2>&1 | tee "$INSTALL_LOG"
install_exit=${pipestatus[1]}

echo ""
check "ctf-install.sh exited successfully"  test $install_exit -eq 0


# =============================================================================
# SECTION 6 — POST-INSTALL CHECKS
# =============================================================================

print_step "Post-install Checks"

# ~/.ctf_env
check "~/.ctf_env was deployed" \
  test -f "${TARGET_HOME}/.ctf_env"

# ~/.zshrc patched
check "~/.zshrc sources ~/.ctf_env" \
  grep -q "source.*\.ctf_env" "${TARGET_HOME}/.zshrc"

# Platform directories
for code in "${EXPECTED_PLATFORMS[@]}"; do
  check "/opt/CTF/${code} directory exists" \
    test -d "${CTF_BASE}/${code}"
done

# Ownership of CTF base
check "/opt/CTF owned by ${TARGET_USER}" \
  test -z "$(find "$CTF_BASE" ! -user "$TARGET_USER" 2>/dev/null)"

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

# Run session setup in a subshell, capture all four variable values.
# -n prevents sudo from prompting mid-test (same reason as the installer call).
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
session_output=$(sudo -u "$TARGET_USER" -n zsh -c "
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
session_platform=$(echo "$vars_line" | grep -oP 'PLATFORM=\K[^ ]+')
session_boxname=$(echo  "$vars_line" | grep -oP 'BOXNAME=\K[^ ]+')
session_address=$(echo  "$vars_line" | grep -oP 'ADDRESS=\K[^ ]+')
session_boxdir=$(echo   "$vars_line" | grep -oP 'BOX_DIR=\K[^ ]+')

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

check "~/.ctf_env_mode contains prod path (/opt/CTF_Public)" \
  grep -q "opt/CTF_Public" "${TARGET_HOME}/.ctf_env_mode"


# =============================================================================
# SECTION 8 — WORKSPACE STRUCTURE CHECKS
# =============================================================================

print_step "Workspace Structure — ${BOX_WORKSPACE}"

check "Box workspace directory exists"       test -d "$BOX_WORKSPACE"
check ".env file created in workspace"       test -f "${BOX_WORKSPACE}/.env"
check "notes/notes.md starter file exists"  test -f "${BOX_WORKSPACE}/notes/notes.md"

for subdir in "${EXPECTED_SUBDIRS[@]}"; do
  check "Subdir '${subdir}' exists"  test -d "${BOX_WORKSPACE}/${subdir}"
done

# Ownership of the box workspace
check "Box workspace owned by ${TARGET_USER}" \
  test -z "$(find "$BOX_WORKSPACE" ! -user "$TARGET_USER" 2>/dev/null)"

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

  print_cmd "sudo ${REMOVAL_SCRIPT} --yes"
  echo ""
  sudo "$REMOVAL_SCRIPT" --yes 2>&1 | sed 's/^/  /'
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