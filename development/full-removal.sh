#!/bin/zsh
# =============================================================================
# full-removal.sh — CTF Toolkit Full Uninstaller
# =============================================================================
# ABOUT:
#   Removes everything that ctf-install.sh puts in place. Designed for clean
#   reinstall cycles and accurate install testing. Safe to run multiple times —
#   every step checks before acting and reports what it found.
#
# WHAT IT REMOVES:
#   1. ~/.ctf_env          — deployed env/functions file
#   2. /opt/CTF            — CTF workspace directory tree
#   3. /opt/CTF_Public     — production repo clone
#   4. ~/.zshrc patch      — the source line ctf-install added
#   5. /usr/local/bin/     — all ctf-* symlinks
#
# WHAT IT DOES NOT TOUCH:
#   ~/.ctf_backups         — your backups are preserved by default
#   ~/github/CTF_Public    — dev repo is never removed by this script
#   ~/.zshrc itself        — only the CTF source block is removed
#
# USAGE:
#   ./full-removal.sh              # standard removal, prompts for confirmation
#   ./full-removal.sh --dry-run    # preview what would be removed, no changes
#   ./full-removal.sh --yes        # skip confirmation prompt (for scripting)
#   ./full-removal.sh --backups    # also remove ~/.ctf_backups
#   ./full-removal.sh --help       # show this message
#
# TEACHING NOTE — Why a dedicated removal script?
#   Manual cleanup is error-prone: you forget a symlink, miss the zshrc patch,
#   or rm the wrong lines. A script removes that friction, ensures every
#   artifact is accounted for, and reports exactly what happened. It also
#   doubles as living documentation: reading this file tells you everything
#   ctf-install.sh installs, which is hard to reconstruct from the installer
#   alone without reading every step carefully.
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================


# =============================================================================
# SECTION 1 — ARGUMENT PARSING
# =============================================================================

DRY_RUN=false
SKIP_CONFIRM=false
REMOVE_BACKUPS=false
SHOW_HELP=false

for arg in "$@"; do
  case "$arg" in
    --dry-run)  DRY_RUN=true ;;
    --yes|-y)   SKIP_CONFIRM=true ;;
    --backups)  REMOVE_BACKUPS=true ;;
    --help|-h)  SHOW_HELP=true ;;
    *)
      echo "\033[0;31m[ERROR]\033[0m Unknown argument: ${arg}"
      echo "  Run full-removal.sh --help for usage."
      exit 1
      ;;
  esac
done


# =============================================================================
# SECTION 2 — COLORS AND HELPERS
# =============================================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

print_ok()      { echo "${GREEN}[OK]${RESET}    $1"; }
print_skip()    { echo "${DIM}[SKIP]  $1${RESET}"; }
print_warn()    { echo "${YELLOW}[WARN]${RESET}  $1"; }
print_err()     { echo "${RED}[ERROR]${RESET} $1"; }
print_info()    { echo "${CYAN}[INFO]${RESET}  $1"; }
print_step()    { echo ""; echo "${BOLD}${CYAN}── $1 ──${RESET}"; }
print_dry()     { echo "${YELLOW}[DRY]${RESET}   $1"; }

# Wrapper: run a command for real, or announce it during --dry-run.
# Usage: run_cmd <description> <command...>
# The description is shown in dry-run mode; the rest is executed normally.
run_cmd() {
  local desc="$1"; shift
  if $DRY_RUN; then
    print_dry "$desc"
  else
    "$@"
  fi
}


# =============================================================================
# SECTION 3 — USER RESOLUTION
# =============================================================================
# TEACHING NOTE — Why $HOME can't be trusted when running under sudo.
#
# When this script is run as `sudo ./full-removal.sh`, the process runs as
# root. In that context, $HOME resolves to /root — not /home/kali. Any path
# built from $HOME (like ~/.ctf_env or ~/.zshrc) will silently target the
# wrong user's home directory, causing the "already gone" false-positive you
# saw when the file was actually still sitting in /home/kali untouched.
#
# The fix: read the *invoking* user from $SUDO_USER (set by sudo to the
# original caller) and derive their real home from /etc/passwd via `getent`.
# If the script is run without sudo, $SUDO_USER is empty and we fall back to
# $USER and $HOME as normal. This makes the script correct in both cases.
#
# getent passwd is more reliable than `echo ~username` or `eval echo ~$user`
# because it reads directly from the system user database rather than relying
# on shell expansion, which can behave differently across shells and contexts.
# =============================================================================

TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)

# Fallback in case getent is unavailable (unlikely on Kali, but safe)
TARGET_HOME="${TARGET_HOME:-$HOME}"


# =============================================================================
# SECTION 4 — HELP
# =============================================================================

show_help() {
  echo ""
  echo "${BOLD}full-removal.sh${RESET} — CTF Toolkit Full Uninstaller"
  echo ""
  echo "${CYAN}USAGE:${RESET}"
  echo "  ./full-removal.sh              Remove everything (with confirmation)"
  echo "  ./full-removal.sh --dry-run    Preview what would be removed, no changes"
  echo "  ./full-removal.sh --yes        Skip confirmation prompt"
  echo "  ./full-removal.sh --backups    Also remove ~/.ctf_backups"
  echo "  ./full-removal.sh --help       Show this message"
  echo ""
  echo "${CYAN}WHAT GETS REMOVED:${RESET}"
  echo "  ~/.ctf_env                     Deployed env/functions file"
  echo "  /opt/CTF                       CTF workspace directory tree"
  echo "  /opt/CTF_Public                Production repo clone"
  echo "  ~/.zshrc (CTF block only)      Source line added by ctf-install"
  echo "  /usr/local/bin/ctf-*           All CTF symlinks"
  echo ""
  echo "${CYAN}WHAT IS PRESERVED:${RESET}"
  echo "  ~/github/CTF_Public            Dev repo (never touched)"
  echo "  ~/.ctf_backups                 Backups (unless --backups is passed)"
  echo ""
}

if $SHOW_HELP; then
  show_help
  exit 0
fi


# =============================================================================
# SECTION 4 — PRE-FLIGHT SUMMARY AND CONFIRMATION
# =============================================================================
# TEACHING NOTE — Show the user exactly what will happen before doing it.
#
# The summary lists every target path so there are no surprises. This matters
# especially because several removals require sudo. A user who didn't expect
# that gets a warning here rather than a mid-run sudo prompt they didn't
# anticipate.
# =============================================================================

echo ""
echo "${BOLD}${RED}=== CTF Toolkit Full Removal ===${RESET}"
echo ""

if $DRY_RUN; then
  echo "  ${YELLOW}${BOLD}DRY RUN — no changes will be made.${RESET}"
  echo ""
fi

echo "  The following will be removed:"
echo "  ${DIM}~/.ctf_env${RESET}"
echo "  ${DIM}/opt/CTF          (requires sudo)${RESET}"
echo "  ${DIM}/opt/CTF_Public   (requires sudo)${RESET}"
echo "  ${DIM}~/.zshrc CTF block${RESET}"
echo "  ${DIM}/usr/local/bin/ctf-* symlinks  (requires sudo)${RESET}"

if $REMOVE_BACKUPS; then
  echo "  ${YELLOW}~/.ctf_backups   (--backups flag set)${RESET}"
fi

echo ""
echo "  ${DIM}Preserved: ~/github/CTF_Public (dev repo)${RESET}"

if ! $REMOVE_BACKUPS; then
  echo "  ${DIM}Preserved: ~/.ctf_backups${RESET}"
fi

echo ""

if ! $SKIP_CONFIRM && ! $DRY_RUN; then
  echo -n "${YELLOW}  Continue? [y/N]:${RESET} "
  read confirm
  if [[ "$confirm" != [yY] ]]; then
    echo ""
    echo "${DIM}  Aborted. Nothing changed.${RESET}"
    echo ""
    exit 0
  fi
fi


# =============================================================================
# STEP 1 — REMOVE ~/.ctf_env
# =============================================================================

remove_env_file() {
  print_step "Removing ~/.ctf_env"

  local target="$TARGET_HOME/.ctf_env"

  if [[ -e "$target" ]]; then
    run_cmd "rm -f $target" rm -f "$target"
    if $DRY_RUN || [[ ! -e "$target" ]]; then
      print_ok "Removed: ${BOLD}${target}${RESET}"
    else
      print_err "Failed to remove: ${BOLD}${target}${RESET}"
    fi
  else
    print_skip "~/.ctf_env not found — already gone."
  fi
}


# =============================================================================
# STEP 2 — REMOVE /opt/CTF (workspace directory tree)
# =============================================================================
# TEACHING NOTE — /opt belongs to root. Anything written there by ctf-install
# (which uses sudo mkdir + sudo chown) still needs sudo to delete, even if
# chown made it user-owned afterwards. We use sudo rm -rf to be safe.
# =============================================================================

remove_ctf_workspace() {
  print_step "Removing /opt/CTF"

  local target="/opt/CTF"

  if [[ -e "$target" ]]; then
    run_cmd "sudo rm -rf $target" sudo rm -rf "$target"
    if $DRY_RUN || [[ ! -e "$target" ]]; then
      print_ok "Removed: ${BOLD}${target}${RESET}"
    else
      print_err "Failed to remove: ${BOLD}${target}${RESET}"
      print_info "Try manually: ${BOLD}sudo rm -rf ${target}${RESET}"
    fi
  else
    print_skip "/opt/CTF not found — already gone."
  fi
}


# =============================================================================
# STEP 3 — REMOVE /opt/CTF_Public (production repo clone)
# =============================================================================

remove_prod_repo() {
  print_step "Removing /opt/CTF_Public"

  local target="/opt/CTF_Public"

  if [[ -e "$target" ]]; then
    run_cmd "sudo rm -rf $target" sudo rm -rf "$target"
    if $DRY_RUN || [[ ! -e "$target" ]]; then
      print_ok "Removed: ${BOLD}${target}${RESET}"
    else
      print_err "Failed to remove: ${BOLD}${target}${RESET}"
      print_info "Try manually: ${BOLD}sudo rm -rf ${target}${RESET}"
    fi
  else
    print_skip "/opt/CTF_Public not found — already gone."
  fi
}


# =============================================================================
# STEP 4 — REMOVE THE CTF SOURCE BLOCK FROM ~/.zshrc
# =============================================================================
# TEACHING NOTE — Why sed instead of line numbers?
#
# The manual notes suggest finding the line numbers with grep -n and then
# running `sed -i '260,261d'`. That works, but it couples the deletion to
# specific line numbers that shift every time .zshrc is edited. If the block
# has moved since you last checked, you delete the wrong lines.
#
# This approach is more robust:
#   1. Grep for the comment anchor ctf-install writes ("# CTF Toolkit")
#      to confirm the block is present and find its line numbers dynamically.
#   2. Use sed to delete any line matching the comment OR the source command.
#      The pattern is narrow enough that it won't hit unrelated config.
#
# The blank line above the block is handled separately: we look for a
# trailing blank line only when both CTF lines have been removed, so we don't
# accidentally eat blank lines that belong to other config blocks.
#
# We make a dated backup of .zshrc before touching it, because sed -i is
# irreversible if something goes wrong.
# =============================================================================

remove_zshrc_patch() {
  print_step "Removing CTF Block from ~/.zshrc"

  local zshrc="$TARGET_HOME/.zshrc"
  local backup_dir="$TARGET_HOME/.ctf_backups"
  local timestamp
  timestamp=$(date +"%Y%m%d_%H%M%S")
  local backup_file="${backup_dir}/.zshrc.pre-removal.${timestamp}"

  # Check if the CTF block exists at all
  if ! grep -q "CTF Toolkit" "$zshrc" 2>/dev/null && \
     ! grep -q "source.*\.ctf_env" "$zshrc" 2>/dev/null; then
    print_skip "No CTF block found in ~/.zshrc — already clean."
    return 0
  fi

  # Show what we found (useful in both dry-run and normal mode)
  echo ""
  print_info "Found CTF lines in ~/.zshrc:"
  grep -n "CTF Toolkit\|source.*\.ctf_env" "$zshrc" | while read -r line; do
    echo "    ${DIM}${line}${RESET}"
  done
  echo ""

  if $DRY_RUN; then
    print_dry "Would back up ~/.zshrc to ${backup_file}"
    print_dry "Would remove lines matching '# CTF Toolkit' and 'source ~/.ctf_env'"
    return 0
  fi

  # Back up .zshrc before modifying it
  mkdir -p "$backup_dir"
  cp "$zshrc" "$backup_file"
  print_ok "Backed up ~/.zshrc to: ${BOLD}${backup_file}${RESET}"

  # TEACHING NOTE — sed -i on macOS requires an extension argument (even '').
  # On Linux/Kali (GNU sed), -i works without one. We target Kali here, so
  # `sed -i` is fine. If you ever port this to macOS, change to `sed -i ''`.
  #
  # The two patterns:
  #   /^# CTF Toolkit/  — matches the comment header line
  #   /^source.*\.ctf_env/  — matches the source command line
  # The d command deletes matching lines. Both patterns run in one sed pass.
  sed -i '/^# CTF Toolkit/d; /^source.*\.ctf_env/d' "$zshrc"

  # Validate
  if ! grep -q "source.*\.ctf_env" "$zshrc"; then
    print_ok "CTF block removed from ~/.zshrc"
  else
    print_err "CTF source line still present in ~/.zshrc — manual cleanup needed."
    print_info "Run: ${BOLD}grep -n 'ctf' ~/.zshrc${RESET} to locate it."
  fi
}


# =============================================================================
# STEP 5 — REMOVE CTF SYMLINKS FROM /usr/local/bin/
# =============================================================================
# TEACHING NOTE — Dynamic discovery vs. hardcoded list.
#
# The manual notes hardcode the symlink names to remove:
#   sudo rm -f /usr/local/bin/ctf-install /usr/local/bin/ctf-sync ...
#
# That list goes stale whenever a new script is added to setup/. This version
# instead discovers all ctf-* symlinks at runtime using `find`, so it stays
# correct as the toolkit grows. It also reports exactly what it found and
# removed, rather than silently succeeding even when nothing was there.
#
# We filter for symlinks specifically (-type l) so we don't accidentally
# delete a real file that happens to start with "ctf-".
# =============================================================================

remove_symlinks() {
  print_step "Removing CTF Symlinks from /usr/local/bin/"

  # Collect all ctf-* symlinks in /usr/local/bin/
  local symlinks=()
  while IFS= read -r link; do
    [[ -n "$link" ]] && symlinks+=("$link")
  done < <(find /usr/local/bin -maxdepth 1 -type l -name "ctf-*" 2>/dev/null)

  if [[ ${#symlinks[@]} -eq 0 ]]; then
    print_skip "No ctf-* symlinks found in /usr/local/bin/ — already clean."
    return 0
  fi

  print_info "Found ${#symlinks[@]} CTF symlink(s):"
  for link in "${symlinks[@]}"; do
    local target
    target=$(readlink "$link")
    echo "    ${DIM}${link} → ${target}${RESET}"
  done
  echo ""

  if $DRY_RUN; then
    for link in "${symlinks[@]}"; do
      print_dry "Would remove: $link"
    done
    return 0
  fi

  local removed=0
  local failed=0
  for link in "${symlinks[@]}"; do
    local linkname="${link##*/}"
    if sudo rm -f "$link"; then
      print_ok "Removed: ${BOLD}${linkname}${RESET}"
      (( removed++ ))
    else
      print_err "Failed to remove: ${BOLD}${link}${RESET}"
      (( failed++ ))
    fi
  done

  echo ""
  print_info "${removed} symlink(s) removed."
  if (( failed > 0 )); then
    print_warn "${failed} symlink(s) could not be removed — check permissions."
  fi
}


# =============================================================================
# STEP 6 — CLEAR SESSION VARIABLES
# =============================================================================
# TEACHING NOTE — Why the removal script clears session variables.
#
# Shell environment variables are in-memory only — they live in the running
# shell process, not on disk. The removal script can delete ~/.ctf_env and
# /opt/CTF, but that doesn't affect variables that are already loaded into
# your current shell session. Without this step, PLATFORM/BOXNAME/ADDRESS/
# BOX_DIR survive the removal and ctf-status would still show stale values
# even though everything on disk has been wiped.
#
# We handle this in two places:
#   1. unset — removes the variables from the current shell immediately.
#   2. Rewrite ~/.ctf_env export lines — if the file still exists at this
#      point (possible since remove_env_file runs first but may have been
#      skipped), blank the persisted values so they don't reload on next
#      shell open.
#
# We cannot call ctf-clear here because: (a) it prompts for confirmation
# which we've already collected, (b) it calls _ctf_persist which may not
# be available if the env functions were already removed, and (c) it uses
# `export VAR=""` rather than `unset`. Direct unset is the right tool here.
#
# Why unset rather than export VAR=""?
# `unset` removes the variable from the environment entirely. A script that
# checks [[ -n "$PLATFORM" ]] to detect an active session will correctly
# see "not set" after unset. An empty export string would pass through as
# an empty value, which some checks treat as "set but empty" — ambiguous.
# =============================================================================

remove_session_vars() {
  print_step "Clearing Session Variables"

  # Unset from current shell
  unset ADDRESS PLATFORM BOXNAME BOX_DIR
  print_ok "Session variables cleared from current shell."

  # Also blank the persisted values in ~/.ctf_env if the file still exists.
  # This covers the case where remove_env_file was skipped (file not found
  # at step 1) but somehow exists now, or a future ordering change.
  local env_file="$TARGET_HOME/.ctf_env"
  if [[ -f "$env_file" ]]; then
    if $DRY_RUN; then
      print_dry "Would blank export lines in $env_file"
    else
      sed -i \
        -e 's|^export ADDRESS=.*|export ADDRESS=""|' \
        -e 's|^export PLATFORM=.*|export PLATFORM=""|' \
        -e 's|^export BOXNAME=.*|export BOXNAME=""|' \
        -e 's|^export BOX_DIR=.*|export BOX_DIR=""|' \
        "$env_file"
      print_ok "Persisted session values blanked in: ${BOLD}${env_file}${RESET}"
    fi
  fi
}


# =============================================================================
# STEP 7 — OPTIONALLY REMOVE ~/.ctf_backups
# =============================================================================

remove_backups() {
  print_step "Removing ~/.ctf_backups"

  local target="$TARGET_HOME/.ctf_backups"

  if [[ -e "$target" ]]; then
    local count
    count=$(ls -A "$target" 2>/dev/null | wc -l | tr -d ' ')
    print_info "Found ${count} file(s) in ~/.ctf_backups"

    run_cmd "rm -rf $target" rm -rf "$target"
    if $DRY_RUN || [[ ! -e "$target" ]]; then
      print_ok "Removed: ${BOLD}${target}${RESET}"
    else
      print_err "Failed to remove: ${BOLD}${target}${RESET}"
    fi
  else
    print_skip "~/.ctf_backups not found — already gone."
  fi
}


# =============================================================================
# STEP 8 — VALIDATE
# =============================================================================
# TEACHING NOTE — Always verify. A removal script that only removes (and
# doesn't confirm) gives you false confidence. Each check uses the same
# condition that the removal logic used, so if a step silently failed, the
# validation will catch it and tell you what needs manual attention.
# =============================================================================

run_validation() {
  print_step "Validation"

  local all_clean=true

  # ~/.ctf_env
  if [[ ! -e "$TARGET_HOME/.ctf_env" ]]; then
    print_ok "~/.ctf_env — gone"
  else
    print_err "~/.ctf_env — still present"
    all_clean=false
  fi

  # /opt/CTF
  if [[ ! -e "/opt/CTF" ]]; then
    print_ok "/opt/CTF — gone"
  else
    print_err "/opt/CTF — still present"
    all_clean=false
  fi

  # /opt/CTF_Public
  if [[ ! -e "/opt/CTF_Public" ]]; then
    print_ok "/opt/CTF_Public — gone"
  else
    print_err "/opt/CTF_Public — still present"
    all_clean=false
  fi

  # ~/.zshrc CTF source line
  if ! grep -q "source.*\.ctf_env" "$TARGET_HOME/.zshrc" 2>/dev/null; then
    print_ok "~/.zshrc CTF block — gone"
  else
    print_err "~/.zshrc CTF block — still present"
    print_info "Remaining lines:"
    grep -n "ctf" "$TARGET_HOME/.zshrc" | while read -r line; do
      echo "    ${DIM}${line}${RESET}"
    done
    all_clean=false
  fi

  # /usr/local/bin/ctf-* symlinks
  local remaining_links
  remaining_links=$(find /usr/local/bin -maxdepth 1 -type l -name "ctf-*" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$remaining_links" -eq 0 ]]; then
    print_ok "/usr/local/bin/ctf-* symlinks — gone"
  else
    print_err "/usr/local/bin/ctf-* — ${remaining_links} symlink(s) still present"
    find /usr/local/bin -maxdepth 1 -type l -name "ctf-*" | while read -r link; do
      echo "    ${DIM}${link}${RESET}"
    done
    all_clean=false
  fi

  # Backups (only check if --backups was passed)
  if $REMOVE_BACKUPS; then
    if [[ ! -e "$TARGET_HOME/.ctf_backups" ]]; then
      print_ok "~/.ctf_backups — gone"
    else
      print_err "~/.ctf_backups — still present"
      all_clean=false
    fi
  fi

  echo ""
  if $all_clean; then
    echo "${BOLD}${GREEN}All targets confirmed clean.${RESET}"
  else
    echo "${BOLD}${YELLOW}Some targets were not fully removed — see errors above.${RESET}"
    echo "${DIM}You may need to remove them manually.${RESET}"
  fi
}


# =============================================================================
# ENTRY POINT
# =============================================================================

remove_env_file
remove_ctf_workspace
remove_prod_repo
remove_zshrc_patch
remove_symlinks
remove_session_vars

if $REMOVE_BACKUPS; then
  remove_backups
fi

if ! $DRY_RUN; then
  run_validation
fi

# --- Done ---------------------------------------------------------------------
echo ""
echo "${BOLD}${CYAN}=== Removal Complete ===${RESET}"
echo ""

if $DRY_RUN; then
  echo "  ${YELLOW}Dry run only — nothing was changed.${RESET}"
  echo "  Re-run without ${BOLD}--dry-run${RESET} to perform actual removal."
else
  echo "  ${DIM}Dev repo preserved: ${TARGET_HOME}/github/CTF_Public${RESET}"
  if ! $REMOVE_BACKUPS; then
    echo "  ${DIM}Backups preserved:  ${TARGET_HOME}/.ctf_backups${RESET}"
  fi
  echo ""
  echo "  To reinstall from your dev repo:"
  echo "  ${BOLD}${TARGET_HOME}/github/CTF_Public/setup/ctf-install.sh${RESET}"
  echo ""

  # TEACHING NOTE — Why `kill $PPID` and not `exit` or `exec zsh`.
  #
  # `exit` closes the script but leaves the terminal open with stale exports.
  # `exec zsh` replaces the shell binary but inherits the exported environment
  # of the current process — variables like PLATFORM and BOXNAME survive it
  # because they're already in the process's environment table, not loaded
  # from a file.
  #
  # The only clean break is terminating the terminal emulator process itself.
  # $PPID is the PID of the parent of the current shell — the terminal emulator
  # that launched it. `kill $PPID` sends SIGTERM to that process, which causes
  # it to close cleanly. This works regardless of which terminal emulator is
  # in use (qterminal, xterm, gnome-terminal, etc.) because $PPID always
  # resolves to whichever process launched this shell session.
  echo "  ${YELLOW}Note:${RESET} Exported session variables (PLATFORM, BOXNAME, ADDRESS, BOX_DIR)"
  echo "  ${DIM}survive exec zsh. A new terminal window starts fully clean.${RESET}"
  echo ""
  echo -n "  ${YELLOW}Close this terminal now to clear all exported variables? [y/N]:${RESET} "
  read close_term
  if [[ "$close_term" == [yY] ]]; then
    echo ""
    echo "  ${DIM}Closing terminal...${RESET}"
    kill $PPID
  else
    echo ""
    echo "  ${DIM}Open a new terminal window when ready to start clean.${RESET}"
    echo "  ${DIM}Or reload your shell:${RESET} ${BOLD}exec zsh${RESET}"
  fi
fi

echo ""