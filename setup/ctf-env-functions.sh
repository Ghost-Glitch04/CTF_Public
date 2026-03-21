#!/bin/zsh
# =============================================================================
# ctf-env-functions.sh — CTF Session Functions
# =============================================================================
# ABOUT:
#   Defines all interactive CTF session commands available in your shell.
#   Sourced automatically by ~/.zshrc (patched in by ctf-install.sh).
#   Safe to edit directly — changes take effect in the next terminal session,
#   or immediately with: source ~/.ctf_env
#
# COMMANDS:
#   set-platform <code>    — Set active CTF platform (HTB, THM, etc.)
#   set-box      <n>       — Set active box and create workspace
#   set-address  <ip>      — Set target IP address
#   set-env      <mode>    — Switch active environment (dev or prod)
#   ctf-status             — Display current session state
#   ctf-clear              — Clear all session variables
#   ctf-help               — List all available CTF commands
#
# EXTENDING THIS FILE:
#   - Add a new command: define a function, add it to ctf-help
#   - Add a platform: append to KNOWN_PLATFORMS (CODE:Full Name format)
#   - Add a workspace folder: append to _CTF_BOX_DIRS array
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================

# =============================================================================
# TEACHING NOTE — Why this file exists as a separate file
# =============================================================================
# The original ctf-install.sh wrote all these functions into ~/.ctf_env via a
# heredoc. That works, but it couples two different jobs together:
#
#   Job A: Setting up a machine (install deps, create dirs, patch .zshrc)
#   Job B: Defining what your shell can DO during a CTF session
#
# Separating them means:
#   - You can update a session command (e.g. improve ctf-status) with just:
#       git push && ctf-sync && source ~/.ctf_env
#   - No need to re-run ctf-install just to change a function
#   - The installer becomes simpler — it just deploys THIS file
#
# Rule of thumb: one file, one job.
# =============================================================================


# =============================================================================
# SECTION 1 — CONFIGURATION
# =============================================================================
# TEACHING NOTE — Put all your "magic values" at the top, named as constants.
# This is called "configuration over code". When something changes (a new path,
# a new platform), you change ONE line here instead of hunting through the file.
# Variables in ALL_CAPS are a convention meaning "treat this as a constant".
# =============================================================================

# =============================================================================
# SUDO-AWARE HOME RESOLUTION
# =============================================================================
# TEACHING NOTE — Why $HOME can't be trusted directly.
#
# When this file is sourced under `sudo` (e.g. `sudo zsh` or a script that
# sources this file with elevated privileges), the shell sets $HOME to the
# root user's home directory (/root). Any path built from $HOME then points
# into root's home instead of the invoking user's — meaning _ctf_persist
# would rewrite /root/.ctf_env, set-env would write /root/.ctf_env_mode, and
# the repo dir resolution would look for /root/github/CTF_Public. None of
# those are where your actual files live.
#
# The fix: resolve the real user's home once, at the top, into _CTF_HOME.
# Every path in this file is built from $_CTF_HOME instead of $HOME.
#
# How it works:
#   1. If $SUDO_USER is set, the script is running under sudo. We use
#      `getent passwd` to look up that user's home directory from the system
#      user database — this is more reliable than `eval echo ~$SUDO_USER`
#      because it doesn't depend on shell expansion or the sudoers environment.
#   2. If $SUDO_USER is not set, we're running as the normal user and $HOME
#      is already correct. Fall back to it directly.
#
# The leading underscore follows the private-variable convention used
# throughout this file — $_CTF_HOME is an internal detail, not something
# a user would set or reference directly.
# =============================================================================

if [[ -n "$SUDO_USER" ]]; then
  _CTF_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  _CTF_HOME="$HOME"
fi

# =============================================================================
# REPO DIR RESOLUTION
# =============================================================================
# TEACHING NOTE — Three-tier resolution for CTF_REPO_DIR. (Bug fix #A)
#
# The original two-tier logic was:
#   1. If ~/github/CTF_Public exists → dev
#   2. Otherwise → prod (/opt/CTF_Public)
#
# The problem: on a dual-install machine (common when doing active dev on the
# same Kali VM you use for CTF work), BOTH paths exist. Auto-detection always
# resolved to dev with no way to switch — and even after `set-env prod`
# exported CTF_REPO_DIR to /opt/CTF_Public for the current session, the NEXT
# terminal window would silently revert to dev because the export was never
# persisted anywhere.
#
# The fix introduces a three-tier resolution:
#   1. If ~/.ctf_env_mode exists, source it — this is written by `set-env`
#      and represents an explicit user choice that survives terminal restarts.
#   2. If no mode file, fall back to auto-detection (dev if ~/github path
#      exists, prod otherwise) — same as before for machines that have never
#      called set-env.
#   3. The [[ -z "$CTF_REPO_DIR" ]] outer guard still applies: if the variable
#      is already set (e.g. exported in ~/.zshrc above the source line), skip
#      all detection entirely and respect the user's override.
#
# This means:
#   - First-time users: auto-detection works as before, no behaviour change.
#   - Users who run `set-env prod`: the choice is written to ~/.ctf_env_mode
#     and persists across all future terminal sessions automatically.
#   - Power users: set CTF_REPO_DIR in ~/.zshrc for a hardcoded override that
#     wins over everything else.
# =============================================================================

if [[ -z "$CTF_REPO_DIR" ]]; then
  if [[ -f "$_CTF_HOME/.ctf_env_mode" ]]; then
    # Explicit mode set by `set-env` — always wins over auto-detection.
    source "$_CTF_HOME/.ctf_env_mode"
  elif [[ -d "$_CTF_HOME/github/CTF_Public" ]]; then
    export CTF_REPO_DIR="$_CTF_HOME/github/CTF_Public"
  else
    # TEACHING NOTE — Collapsed redundant elif/else. (Prior bug fix #1)
    #
    # Both the elif and else previously assigned the same value. Collapsed
    # into a single else — whether /opt/CTF_Public exists or not, the
    # fallback is the production path. ctf-sync.sh creates it on first run.
    export CTF_REPO_DIR="/opt/CTF_Public"
  fi
fi

# Base directory where all CTF workspaces live.
# TEACHING NOTE — CTF_BASE_DIR follows the same override pattern as CTF_REPO_DIR.
# On a dev machine you might want workspaces under ~/CTF rather than /opt/CTF.
# Export CTF_BASE_DIR before sourcing this file (or set it in your .zshrc above
# the source line) to redirect all workspace creation automatically.
CTF_BASE="${CTF_BASE_DIR:-/opt/CTF}"

# Sub-directories created for every new box workspace.
# To add a new folder to every box: append to this array.
_CTF_BOX_DIRS=(
  "scans"
  "exploits"
  "notes"
  "flags"
  "loot"
)

# Known platforms — format: "CODE:Full Name"
# CODE is what you type (e.g. set-platform HTB)
# Full Name is used in ctf-status and directory creation.
# To add a platform: append a new "CODE:Full Name" line.
KNOWN_PLATFORMS=(
  "HTB:Hack The Box"
  "THM:TryHackMe"
  "LD:LetsDefend"
  "DC:DefCon"
  "GGL:Google CTF"
  "PG:Proving Grounds"
)

# =============================================================================
# SECTION 2 — SESSION STATE
# =============================================================================
# TEACHING NOTE — Explicit initialization matters.
# Always declare your state variables at the top, even if they'll be empty.
# This makes it immediately obvious what state this file manages.
# Using `export` makes these available to child processes (scripts you run
# from your terminal), not just the current shell.
#
# We only initialize them if they're not already set. The := operator means
# "assign this value only if the variable is currently unset or empty".
# This preserves your session if you re-source the file mid-session.
# =============================================================================

export ADDRESS="${ADDRESS:=}"
export PLATFORM="${PLATFORM:=}"
export BOXNAME="${BOXNAME:=}"
export BOX_DIR="${BOX_DIR:=}"


# =============================================================================
# SECTION 3 — COLOR CONSTANTS
# =============================================================================
# TEACHING NOTE — Prefix internal/private names with an underscore.
# The leading _ is a convention meaning "this is an implementation detail,
# not part of the public interface". Colors are used internally by all the
# functions below, but a user would never call _CTF_RED directly.
#
# Using variables for colors (instead of hardcoding escape codes each time)
# means you can change your color scheme in one place.
# =============================================================================

_CTF_RED='\033[0;31m'
_CTF_YELLOW='\033[1;33m'
_CTF_GREEN='\033[0;32m'
_CTF_CYAN='\033[0;36m'
_CTF_BOLD='\033[1m'
_CTF_DIM='\033[2m'
_CTF_RESET='\033[0m'


# =============================================================================
# SECTION 4 — PRIVATE HELPER FUNCTIONS
# =============================================================================
# TEACHING NOTE — Extract repeated patterns into helpers.
# These four print functions get called dozens of times across the file.
# If you want to change how [OK] looks, you change it in ONE place.
# That's the DRY principle: Don't Repeat Yourself.
#
# Notice they're all prefixed with _ctf_ — same convention as the colors.
# Public commands (set-box, ctf-status) have no underscore prefix.
# =============================================================================

_ctf_ok()   { echo "${_CTF_GREEN}[OK]${_CTF_RESET}    $1"; }
_ctf_warn() { echo "${_CTF_YELLOW}[WARN]${_CTF_RESET}  $1"; }
_ctf_err()  { echo "${_CTF_RED}[ERROR]${_CTF_RESET} $1"; }
_ctf_info() { echo "${_CTF_CYAN}[INFO]${_CTF_RESET}  $1"; }


# =============================================================================
# _ctf_persist
# =============================================================================
# TEACHING NOTE — Persistence: writing state back to disk.
# Shell variables are in-memory only. If you open a new terminal, they're gone.
# This function rewrites the export lines in ~/.ctf_env so your session
# survives across terminal windows and reboots.
#
# The pattern used here (read line-by-line into a temp file, then replace
# the original) is called an "atomic write". It avoids corruption: if
# something goes wrong mid-write, the original file is still intact because
# we only replace it at the very end with `mv`.
#
# mktemp creates a uniquely named temp file — safer than hardcoding /tmp/foo.
#
# TEACHING NOTE — Why CTF_BASE is not persisted here.
#
# _ctf_persist intentionally only writes the four session state variables
# (ADDRESS, PLATFORM, BOXNAME, BOX_DIR). CTF_BASE is a configuration value,
# not session state — it reflects where your workspaces live, and that is
# determined at startup by CTF_BASE_DIR (or the default /opt/CTF).
#
# If you want a non-default CTF_BASE to survive across terminal sessions,
# set it in ~/.zshrc above the `source ~/.ctf_env` line:
#   export CTF_BASE_DIR="$HOME/CTF"
#   source ~/.ctf_env
# =============================================================================

_ctf_persist() {
  local tmp
  tmp=$(mktemp) || { _ctf_err "Could not create temp file for persist."; return 1; }

  # TEACHING NOTE — Strip \r on read to handle legacy CRLF deployments. (Bug fix #1)
  #
  # _ctf_persist works by reading ~/.ctf_env line-by-line and rewriting the
  # four session state variables in place. It uses a case statement to match
  # lines like "export ADDRESS=..." and replace them with fresh values.
  #
  # The bug: if ~/.ctf_env was deployed when the scripts still had Windows
  # CRLF line endings, each line in the file ends with \r. The case pattern
  # "export ADDRESS="* does NOT match "export ADDRESS=...\r" because the \r
  # is part of the string being matched. Every line falls through to the catch-
  # all branch and is echoed unchanged — session state appears to save but
  # the values are never actually updated on disk.
  #
  # The fix: pipe the file through sed to strip \r before the while loop sees
  # it. This uses process substitution < <(...) rather than a pipe so that
  # the while loop runs in the current shell — a pipe would create a subshell
  # and any variable assignments inside the loop would be lost.
  #
  # This is a defensive measure. A machine that was set up after the CRLF fix
  # will have a clean ~/.ctf_env and sed will find nothing to strip — it is a
  # no-op in that case. Machines set up before the fix are silently healed the
  # first time _ctf_persist runs after updating to this version.
  while IFS= read -r line; do
    case "$line" in
      "export ADDRESS="*)  echo "export ADDRESS=\"${ADDRESS}\""   ;;
      "export PLATFORM="*) echo "export PLATFORM=\"${PLATFORM}\"" ;;
      "export BOXNAME="*)  echo "export BOXNAME=\"${BOXNAME}\""   ;;
      "export BOX_DIR="*)  echo "export BOX_DIR=\"${BOX_DIR}\""   ;;
      *)                   echo "$line"                            ;;
    esac
  done < <(sed 's/\r//' "$_CTF_HOME/.ctf_env") > "$tmp"

  mv "$tmp" "$_CTF_HOME/.ctf_env"
}


# =============================================================================
# _ctf_write_box_env
# =============================================================================
# TEACHING NOTE — Box-local .env files.
# This writes a .env file into the current box's workspace directory.
# The benefit: if you `cd` into a box folder later and forget what session
# variables you had set, you can `cat .env` to see them — or even
# `source .env` to restore the session.
#
# The `-n` check guards against writing to a path that doesn't exist yet.
# Always validate your inputs before doing filesystem operations.
# =============================================================================

_ctf_write_box_env() {
  [[ -n "$BOX_DIR" && -d "$BOX_DIR" ]] || return 0

  cat > "${BOX_DIR}/.env" << BOXENV
# Auto-generated by ctf-env-functions.sh — $(date)
# Restore this session: source ${BOX_DIR}/.env
export ADDRESS="${ADDRESS}"
export PLATFORM="${PLATFORM}"
export BOXNAME="${BOXNAME}"
export BOX_DIR="${BOX_DIR}"
BOXENV
}


# =============================================================================
# _ctf_lookup_platform_name <code>
# =============================================================================
# TEACHING NOTE — Lookup functions keep logic out of display code.
# Instead of looping through KNOWN_PLATFORMS every time ctf-status needs the
# full name, we isolate that logic here. ctf-status just calls this function.
# Single responsibility: this function does one thing — return a display name.
# =============================================================================

_ctf_lookup_platform_name() {
  local code="$1"
  for entry in "${KNOWN_PLATFORMS[@]}"; do
    if [[ "${entry%%:*}" == "$code" ]]; then
      echo "${entry##*:}"
      return 0
    fi
  done
  echo "$code"   # Fall back to the code itself if no match found
}


# =============================================================================
# SECTION 5 — PUBLIC COMMANDS
# =============================================================================
# TEACHING NOTE — Public vs private interface.
# Everything below this line is what users actually type. These functions
# form the "public API" of this file. They're named without underscores,
# they validate their inputs, give clear feedback, and call private helpers
# to do the actual work.
#
# A good public function:
#   1. Validates input early, returns an error if bad (fail fast)
#   2. Does the state change
#   3. Gives feedback to the user
#   4. Calls helpers to persist/sync the change
# =============================================================================


# =============================================================================
# set-address <ip>
# =============================================================================
# TEACHING NOTE — Input validation with regex.
# The =~ operator tests a string against a regex pattern.
# The pattern ^([0-9]{1,3}\.){3}[0-9]{1,3}$ means:
#   ^                  start of string
#   ([0-9]{1,3}\.){3}  three groups of 1-3 digits followed by a dot
#   [0-9]{1,3}         one final group of 1-3 digits
#   $                  end of string
#
# This catches obvious bad input (letters, wrong format) before the octet
# range check (0-255) catches values like 999.0.0.1.
#
# Validate early and return immediately on bad input — don't let invalid
# state propagate into the rest of the function.
# =============================================================================

set-address() {
  local new_ip="$1"

  # Guard: require an argument
  if [[ -z "$new_ip" ]]; then
    _ctf_err "Usage: set-address <ip_address>"
    return 1
  fi

  # Guard: basic IP format check
  if ! [[ "$new_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    _ctf_err "Invalid IP format: ${_CTF_BOLD}${new_ip}${_CTF_RESET}"
    return 1
  fi

  # Guard: octet range check (each part must be 0–255)
  # TEACHING NOTE — Bug fix #B: removed redundant `local IFS='.'`.
  #
  # The original code set `local IFS='.'` immediately before using zsh's
  # `(@s/./)` flag to split the IP. These two things are doing the same job
  # by different mechanisms, and they don't interact — zsh's @s flag splits
  # explicitly on a delimiter and does NOT consult $IFS at all. The local IFS
  # line was a bash idiom that had no effect here.
  #
  # The risk was misleading future readers: someone might remove the (@s/./)
  # form thinking $IFS was already handling the split, silently breaking the
  # octet check. Removing the dead code makes the intent unambiguous.
  #
  # Bug fix #C: added quotes to the for loop — `"${octets[@]}"` instead of
  # `$octets`. Without quotes, zsh word-splitting fires on array elements that
  # contain whitespace or glob characters. Impossible with IP octets in
  # practice, but inconsistent with how every other loop in this file handles
  # arrays. Standardized for safety.
  local octets=("${(@s/./)new_ip}")
  for octet in "${octets[@]}"; do
    if (( octet > 255 )); then
      _ctf_err "Invalid IP address (octet out of range): ${_CTF_BOLD}${new_ip}${_CTF_RESET}"
      return 1
    fi
  done

  # State change — show what changed
  local old="$ADDRESS"
  export ADDRESS="$new_ip"

  if [[ -n "$old" && "$old" != "$new_ip" ]]; then
    echo "${_CTF_CYAN}[ADDRESS]${_CTF_RESET}  ${_CTF_DIM}${old}${_CTF_RESET} → ${_CTF_BOLD}${new_ip}${_CTF_RESET}"
  else
    echo "${_CTF_CYAN}[ADDRESS]${_CTF_RESET}  Set to ${_CTF_BOLD}${new_ip}${_CTF_RESET}"
  fi

  _ctf_persist
  _ctf_write_box_env
}


# =============================================================================
# set-env <mode>
# =============================================================================
# TEACHING NOTE — Explicit environment toggle with persistent mode file.
#
# CTF_REPO_DIR was previously set by auto-detection at shell startup: if
# ~/github/CTF_Public existed it was treated as dev, otherwise /opt/CTF_Public
# was used as prod. On a machine where BOTH paths exist (a common setup when
# doing active development on the same Kali VM you use for CTF work), the
# auto-detection always resolved to dev with no way to switch.
#
# A previous version of this function fixed the in-session problem by
# exporting CTF_REPO_DIR to the requested path — but that export lived only
# in memory. The next terminal window would source this file fresh, the
# auto-detection block at the top would run again, and the choice would
# silently revert to dev.
#
# TEACHING NOTE — Bug fix #A: persist the mode choice to ~/.ctf_env_mode.
#
# The fix is to write a single export line to ~/.ctf_env_mode when the user
# calls set-env. The resolution block at the top of this file now checks for
# that file first, before any auto-detection runs. This means:
#
#   set-env prod   →  writes `export CTF_REPO_DIR="/opt/CTF_Public"` to
#                     ~/.ctf_env_mode, which is sourced on every subsequent
#                     terminal open, overriding auto-detection permanently
#                     until the user explicitly calls set-env again.
#
# Why a separate file and not _ctf_persist?
# _ctf_persist rewrites ~/.ctf_env, which is sourced by ~/.zshrc. CTF_REPO_DIR
# is not a session state variable like ADDRESS — it is a configuration value
# about the machine layout. Writing it into ~/.ctf_env would create a chicken-
# and-egg problem: the file that sets CTF_REPO_DIR would be the same file that
# gets rewritten, and _ctf_persist's line-matching logic doesn't know about
# CTF_REPO_DIR. A dedicated ~/.ctf_env_mode file is simpler and safer: it has
# exactly one job (record the env choice) and is easy to inspect or delete.
#
# To clear the persisted mode and return to auto-detection:
#   rm ~/.ctf_env_mode && source ~/.ctf_env
# =============================================================================

set-env() {
  local mode="${1:l}"   # :l = lowercase in zsh

  # Known modes and their corresponding paths
  local dev_path="$_CTF_HOME/github/CTF_Public"
  local prod_path="/opt/CTF_Public"

  # Guard: require an argument
  if [[ -z "$mode" ]]; then
    _ctf_err "Usage: set-env <dev|prod>"
    _ctf_info "  dev  → ${dev_path}"
    _ctf_info "  prod → ${prod_path}"
    return 1
  fi

  # Guard: only accept dev or prod
  if [[ "$mode" != "dev" && "$mode" != "prod" ]]; then
    _ctf_err "Unknown mode: ${_CTF_BOLD}${mode}${_CTF_RESET}"
    _ctf_info "Valid modes: ${_CTF_BOLD}dev${_CTF_RESET}, ${_CTF_BOLD}prod${_CTF_RESET}"
    return 1
  fi

  # Resolve the target path for the requested mode
  local target_path
  if [[ "$mode" == "dev" ]]; then
    target_path="$dev_path"
  else
    target_path="$prod_path"
  fi

  # Guard: validate the path exists before switching
  # TEACHING NOTE — Improved error message to distinguish install vs sync.
  #
  # The previous message said "Run ctf-sync to create it" for both modes,
  # which is misleading for prod: on a fresh machine, /opt/CTF_Public won't
  # exist until ctf-install --prod has been run. ctf-sync only works once
  # the repo is already cloned. Updated to name the right command per mode.
  if [[ ! -d "$target_path" ]]; then
    _ctf_err "Path does not exist: ${_CTF_BOLD}${target_path}${_CTF_RESET}"
    if [[ "$mode" == "prod" ]]; then
      _ctf_info "Run 'ctf-install --prod' to set up production, or 'ctf-sync --prod' to pull an existing install."
    else
      _ctf_info "Run 'ctf-sync' to clone the repo, or check your install."
    fi
    return 1
  fi

  # State change — show what changed
  local old="$CTF_REPO_DIR"
  export CTF_REPO_DIR="$target_path"

  if [[ -n "$old" && "$old" != "$target_path" ]]; then
    echo "${_CTF_CYAN}[ENV]${_CTF_RESET}      ${_CTF_DIM}${old}${_CTF_RESET} → ${_CTF_BOLD}${target_path}${_CTF_RESET}"
  else
    echo "${_CTF_CYAN}[ENV]${_CTF_RESET}      Set to ${_CTF_BOLD}${target_path}${_CTF_RESET}"
  fi

  # Persist the choice so it survives terminal restarts.
  # TEACHING NOTE — We write a single `export` line to ~/.ctf_env_mode rather
  # than relying on _ctf_persist, for the reasons explained in the function
  # header above. The file is small and human-readable — you can `cat` it to
  # confirm what mode is active, and `rm` it to return to auto-detection.
  echo "export CTF_REPO_DIR=\"${target_path}\"" > "$_CTF_HOME/.ctf_env_mode" \
    || { _ctf_err "Could not write mode file: ~/.ctf_env_mode"; return 1; }

  _ctf_ok "Mode '${mode}' persisted to ~/.ctf_env_mode"

  # Re-source so the change takes effect immediately in the current session.
  # TEACHING NOTE — We source ~/.ctf_env directly rather than "$CTF_REPO_DIR/..."
  # because ~/.ctf_env is the deployed copy that your shell actually uses.
  # CTF_REPO_DIR is the repo — a source for updates, not the live file.
  source "$_CTF_HOME/.ctf_env" && _ctf_ok "Environment reloaded."
}


# =============================================================================
# set-platform <code>
# =============================================================================
# TEACHING NOTE — Soft vs hard validation.
# Known platforms are validated against KNOWN_PLATFORMS, but we don't hard-
# block unknown ones — we warn and ask. This is intentional: CTF platforms
# appear and disappear. You don't want your tooling to block you from working
# just because you haven't added a new platform to the list yet.
#
# "${1:u}" is zsh syntax for "uppercase the value of $1". This means
# `set-platform htb` and `set-platform HTB` both work — case-insensitive UX.
# =============================================================================

set-platform() {
  local new_platform="${1:u}"   # :u = uppercase in zsh

  # Guard: require an argument
  if [[ -z "$new_platform" ]]; then
    _ctf_err "Usage: set-platform <code>"
    local codes=()
    for entry in "${KNOWN_PLATFORMS[@]}"; do codes+=("${entry%%:*}"); done
    _ctf_info "Known platforms: ${_CTF_BOLD}${codes[*]}${_CTF_RESET}"
    return 1
  fi

  # Soft validation: warn if not in known list, but allow it
  local known=false
  for entry in "${KNOWN_PLATFORMS[@]}"; do
    [[ "${entry%%:*}" == "$new_platform" ]] && known=true && break
  done

  if ! $known; then
    _ctf_warn "${_CTF_BOLD}${new_platform}${_CTF_RESET} is not a recognised platform."
    local codes=()
    for entry in "${KNOWN_PLATFORMS[@]}"; do codes+=("${entry%%:*}"); done
    _ctf_info "Known: ${_CTF_BOLD}${codes[*]}${_CTF_RESET}"
    echo -n "  Continue anyway? [y/N]: "
    # TEACHING NOTE — Bug fix #D: added -r flag to both `read confirm` calls.
    #
    # Without -r, the shell treats a backslash in the input as a line-
    # continuation escape: typing `\` then Enter silently consumes the next
    # line rather than registering as a "N" confirmation. With -r, backslash
    # is treated as a literal character — the input is read exactly as typed.
    # The -r flag is already used correctly in _ctf_persist's while loop;
    # these interactive reads are now consistent with that.
    read -r confirm
    [[ "$confirm" != [yY] ]] && echo "${_CTF_DIM}  Aborted.${_CTF_RESET}" && return 1
  fi

  # State change
  local old="$PLATFORM"
  export PLATFORM="$new_platform"

  local full_name
  full_name=$(_ctf_lookup_platform_name "$new_platform")

  if [[ -n "$old" && "$old" != "$new_platform" ]]; then
    local old_name
    old_name=$(_ctf_lookup_platform_name "$old")
    echo "${_CTF_CYAN}[PLATFORM]${_CTF_RESET} ${_CTF_DIM}${old} (${old_name})${_CTF_RESET} → ${_CTF_BOLD}${new_platform} (${full_name})${_CTF_RESET}"
  else
    echo "${_CTF_CYAN}[PLATFORM]${_CTF_RESET} Set to ${_CTF_BOLD}${new_platform}${_CTF_RESET} ${_CTF_DIM}(${full_name})${_CTF_RESET}"
  fi

  # TEACHING NOTE — Conditional sudo for platform directory creation. (Bug fix #3)
  #
  # The previous version used plain `mkdir -p "$pdir"` here, which works on
  # dev machines where CTF_BASE is under $HOME. On a production machine where
  # CTF_BASE is /opt/CTF (owned by root), this mkdir silently fails with a
  # permission denied error and no workspace directory is created.
  #
  # ctf-install.sh correctly uses sudo for /opt/ paths in run_build_directories.
  # This function creates platform directories interactively (e.g. when a user
  # adds a new platform to KNOWN_PLATFORMS and runs set-platform before
  # re-running ctf-install), so it needs the same conditional sudo logic.
  #
  # The pattern mirrors what ctf-install.sh does: check once whether the path
  # is under /opt/, then apply sudo only if needed. This keeps both scripts
  # consistent and means "does this need elevated permissions?" is always
  # answered the same way regardless of which script is running.
  #
  # TEACHING NOTE — Bug fix #E: sudo mkdir failure is now caught and surfaced.
  #
  # The previous version used `sudo mkdir -p "$pdir" && _ctf_ok "..."`. If sudo
  # fails (cancelled password prompt, insufficient permissions), mkdir never
  # runs and _ctf_ok is never echoed — but the function continued silently,
  # calling _ctf_persist and _ctf_write_box_env against a platform directory
  # that didn't actually exist. The user saw no error.
  #
  # The fix uses `|| { _ctf_err ...; return 1; }` to catch the failure and
  # abort immediately. The _ctf_ok call is moved outside the mkdir line so it
  # only fires after a confirmed successful create.
  local pdir="${CTF_BASE}/${new_platform}"
  if [[ ! -d "$pdir" ]]; then
    if [[ "$CTF_BASE" == /opt/* ]]; then
      sudo mkdir -p "$pdir" || { _ctf_err "Failed to create: ${_CTF_BOLD}${pdir}${_CTF_RESET}"; return 1; }
    else
      mkdir -p "$pdir"      || { _ctf_err "Failed to create: ${_CTF_BOLD}${pdir}${_CTF_RESET}"; return 1; }
    fi
    _ctf_ok "Created: ${_CTF_BOLD}${pdir}${_CTF_RESET}"
  fi

  # Update BOX_DIR if a box is already set
  if [[ -n "$BOXNAME" ]]; then
    export BOX_DIR="${CTF_BASE}/${PLATFORM}/${BOXNAME}"
  fi

  _ctf_persist
  _ctf_write_box_env
}


# =============================================================================
# set-box <n>
# =============================================================================
# TEACHING NOTE — Sanitizing user input for filesystem use.
# Box names become directory names. You can't have spaces or special chars in
# directory names safely, so we sanitize with parameter expansion:
#   ${1//[^a-zA-Z0-9_-]/_}
# This replaces any character that is NOT alphanumeric, underscore, or hyphen
# with an underscore. "My Box!" becomes "My_Box_".
#
# This is safer than erroring out — the user still gets a workspace, and the
# name is predictably transformed rather than silently mangled.
# =============================================================================

set-box() {
  # Sanitize: replace anything not alphanumeric/underscore/hyphen with _
  local new_box="${1//[^a-zA-Z0-9_-]/_}"

  # Guard: require an argument
  if [[ -z "$new_box" ]]; then
    _ctf_err "Usage: set-box <box_name>"
    return 1
  fi

  # State change
  local old="$BOXNAME"
  export BOXNAME="$new_box"

  if [[ -n "$old" && "$old" != "$new_box" ]]; then
    echo "${_CTF_CYAN}[BOX]${_CTF_RESET}      ${_CTF_DIM}${old}${_CTF_RESET} → ${_CTF_BOLD}${new_box}${_CTF_RESET}"
  else
    echo "${_CTF_CYAN}[BOX]${_CTF_RESET}      Set to ${_CTF_BOLD}${new_box}${_CTF_RESET}"
  fi

  # Require platform before creating workspace
  if [[ -z "$PLATFORM" ]]; then
    _ctf_warn "\$PLATFORM not set — run ${_CTF_BOLD}set-platform <code>${_CTF_RESET} first."
    _ctf_info "Box name recorded. Workspace will be created after set-platform."
    _ctf_persist
    return 0
  fi

  # Build and create workspace
  export BOX_DIR="${CTF_BASE}/${PLATFORM}/${BOXNAME}"

  if [[ ! -d "$BOX_DIR" ]]; then
    # TEACHING NOTE — Conditional sudo for workspace creation. (Bug fix #6)
    #
    # set-platform was previously fixed to use sudo when creating platform
    # directories under /opt/. The same problem existed here in set-box:
    # the workspace subdirectories (scans, exploits, notes, flags, loot) were
    # always created with plain mkdir, which silently fails with a permission
    # error on a production machine where CTF_BASE is /opt/CTF.
    #
    # The fix mirrors the pattern used in set-platform and ctf-install.sh:
    # check once whether CTF_BASE is under /opt/, then apply sudo to every
    # mkdir call in this block consistently. We check CTF_BASE (the root) not
    # BOX_DIR (the specific path) because the ownership of the parent directory
    # is what determines whether sudo is needed — if /opt/CTF exists and is
    # owned by root, all paths underneath it require elevated permissions too.
    #
    # Using a local flag (use_sudo) rather than repeating the /opt/* check in
    # every mkdir call keeps the decision in one place and makes the logic
    # easy to follow at a glance.
    #
    # TEACHING NOTE — Bug fix #E (continued): mkdir failures in the subdir
    # loop are now caught. If any subdir creation fails, the function aborts
    # immediately rather than continuing to chown a partial workspace.
    local use_sudo=false
    [[ "$CTF_BASE" == /opt/* ]] && use_sudo=true

    # TEACHING NOTE — Driving behavior from config arrays.
    # Adding a new workspace folder is one line in _CTF_BOX_DIRS at the top.
    # The loop here doesn't need to change. Data drives behavior.
    for subdir in "${_CTF_BOX_DIRS[@]}"; do
      if $use_sudo; then
        sudo mkdir -p "${BOX_DIR}/${subdir}" \
          || { _ctf_err "Failed to create: ${_CTF_BOLD}${BOX_DIR}/${subdir}${_CTF_RESET}"; return 1; }
      else
        mkdir -p "${BOX_DIR}/${subdir}" \
          || { _ctf_err "Failed to create: ${_CTF_BOLD}${BOX_DIR}/${subdir}${_CTF_RESET}"; return 1; }
      fi
    done

    # Fix ownership so the normal user can write into the workspace.
    # TEACHING NOTE — sudo mkdir creates dirs owned by root. Even though
    # ctf-install.sh chowns /opt/CTF at install time, new box directories are
    # created here at runtime — after install — so they also need an explicit
    # chown. The recursive flag covers BOX_DIR and all its subdirs in one call,
    # matching the same pattern used in ctf-install.sh's run_build_directories.
    if $use_sudo; then
      sudo chown -R "${USER}:${USER}" "$BOX_DIR"
    fi

    _ctf_ok "Created workspace: ${_CTF_BOLD}${BOX_DIR}${_CTF_RESET}"
    _ctf_info "Folders: ${_CTF_DIM}${_CTF_BOX_DIRS[*]}${_CTF_RESET}"

    # Drop a starter notes file
    # TEACHING NOTE — Seeding files on creation is a nice quality-of-life touch.
    # The box name and date give you a starting point without extra commands.
    cat > "${BOX_DIR}/notes/notes.md" << NOTESEOF
# ${BOXNAME}

**Platform:** ${PLATFORM}
**Started:**  $(date +"%Y-%m-%d")
**Address:**  ${ADDRESS:-TBD}

## Recon

## Foothold

## Privilege Escalation

## Flags

| Flag | Value |
|------|-------|
| User | |
| Root | |

## Notes

NOTESEOF
    _ctf_ok "Created starter notes: ${_CTF_BOLD}${BOX_DIR}/notes/notes.md${_CTF_RESET}"
  else
    _ctf_info "Workspace already exists: ${_CTF_BOLD}${BOX_DIR}${_CTF_RESET}"
  fi

  _ctf_persist
  _ctf_write_box_env
}


# =============================================================================
# ctf-status
# =============================================================================
# TEACHING NOTE — Display functions should be read-only.
# ctf-status never modifies state. It only reads and displays. Keeping
# display logic separate from state-change logic means you can call it
# at any time without side effects.
#
# The box-drawing characters (╔ ║ ╚) are Unicode — they look good in most
# modern terminals. The printf "%-12s" pattern left-aligns values in a
# fixed-width field so the colons line up neatly regardless of label length.
# =============================================================================

ctf-status() {
  local platform_display=""
  if [[ -n "$PLATFORM" ]]; then
    local full_name
    full_name=$(_ctf_lookup_platform_name "$PLATFORM")
    platform_display="${_CTF_BOLD}${PLATFORM}${_CTF_RESET} ${_CTF_DIM}(${full_name})${_CTF_RESET}"
  else
    platform_display="${_CTF_DIM}not set${_CTF_RESET}"
  fi

  local box_display="${BOXNAME:-${_CTF_DIM}not set${_CTF_RESET}}"
  local address_display="${ADDRESS:-${_CTF_DIM}not set${_CTF_RESET}}"
  local dir_display="${BOX_DIR:-${_CTF_DIM}not set${_CTF_RESET}}"

  # TEACHING NOTE — Env detection based on $HOME prefix, not a hardcoded path.
  #
  # Checking "$CTF_REPO_DIR" == "$HOME"* rather than a specific path like
  # "$HOME/github/CTF_Public" means any dev checkout under the user's home
  # directory is correctly labelled "dev", regardless of its exact location.
  local env_label
  if [[ "$CTF_REPO_DIR" == "$_CTF_HOME"* ]]; then
    env_label="${_CTF_YELLOW}dev${_CTF_RESET}  ${_CTF_DIM}(${CTF_REPO_DIR})${_CTF_RESET}"
  else
    env_label="${_CTF_GREEN}prod${_CTF_RESET} ${_CTF_DIM}(${CTF_REPO_DIR})${_CTF_RESET}"
  fi

  # Show whether the mode was set explicitly or via auto-detection
  local mode_source
  if [[ -f "$_CTF_HOME/.ctf_env_mode" ]]; then
    mode_source="${_CTF_DIM}(explicit — ~/.ctf_env_mode)${_CTF_RESET}"
  else
    mode_source="${_CTF_DIM}(auto-detected)${_CTF_RESET}"
  fi

  echo ""
  echo "${_CTF_BOLD}${_CTF_CYAN}╔══ CTF Session Status ══════════════════════╗${_CTF_RESET}"
  echo "${_CTF_BOLD}${_CTF_CYAN}║${_CTF_RESET}  Env        : ${env_label} ${mode_source}"
  echo "${_CTF_BOLD}${_CTF_CYAN}║${_CTF_RESET}  Platform   : ${platform_display}"
  echo "${_CTF_BOLD}${_CTF_CYAN}║${_CTF_RESET}  Box        : ${box_display}"
  echo "${_CTF_BOLD}${_CTF_CYAN}║${_CTF_RESET}  Address    : ${address_display}"
  echo "${_CTF_BOLD}${_CTF_CYAN}║${_CTF_RESET}  Box Dir    : ${dir_display}"
  echo "${_CTF_BOLD}${_CTF_CYAN}╚════════════════════════════════════════════╝${_CTF_RESET}"
  echo ""
}


# =============================================================================
# ctf-clear
# =============================================================================
# TEACHING NOTE — Destructive actions should always confirm.
# Any command that erases state should ask "are you sure?" before doing it.
# The [y/N] convention means N is the default — just hitting Enter aborts.
# Capitalizing N reinforces which choice is the default.
# =============================================================================

ctf-clear() {
  echo -n "${_CTF_YELLOW}[WARN]${_CTF_RESET}  Clear all CTF session variables? [y/N]: "
  # TEACHING NOTE — Bug fix #D (continued): read -r for consistent backslash
  # handling. See the same fix in set-platform for the full explanation.
  read -r confirm
  if [[ "$confirm" == [yY] ]]; then
    export ADDRESS="" PLATFORM="" BOXNAME="" BOX_DIR=""
    _ctf_persist
    _ctf_ok "Session cleared."
  else
    echo "${_CTF_DIM}  Nothing changed.${_CTF_RESET}"
  fi
}


# =============================================================================
# ctf-help
# =============================================================================
# TEACHING NOTE — Every toolkit should have a help command.
# This is the "discoverability" layer. New users (including future you) can
# run ctf-help and immediately understand what's available without reading
# the source. Keep this in sync as you add new commands.
# =============================================================================

ctf-help() {
  echo ""
  echo "${_CTF_BOLD}${_CTF_CYAN}CTF Toolkit — Available Commands${_CTF_RESET}"
  echo ""
  echo "${_CTF_CYAN}Session Setup:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}set-platform <code>${_CTF_RESET}    Set active platform (e.g. HTB, THM)"
  echo "  ${_CTF_BOLD}set-box <n>${_CTF_RESET}            Set active box and create workspace"
  echo "  ${_CTF_BOLD}set-address <ip>${_CTF_RESET}       Set target IP address"
  echo "  ${_CTF_BOLD}set-env <mode>${_CTF_RESET}         Switch environment (dev or prod)"
  echo ""
  echo "${_CTF_CYAN}Session Info:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}ctf-status${_CTF_RESET}             Show current session state"
  echo "  ${_CTF_BOLD}ctf-help${_CTF_RESET}               Show this message"
  echo ""
  echo "${_CTF_CYAN}Session Control:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}ctf-clear${_CTF_RESET}              Clear all session variables"
  echo ""

  # TEACHING NOTE — Added --prod flag entries to Maintenance section. (Refactor #4)
  #
  # The previous version listed ctf-install and ctf-sync but omitted their
  # --prod variants. This meant a user on a dual-install machine who ran
  # ctf-help to find the right command would see no indication that --prod
  # existed. Help output should be the single source of truth for what a
  # tool can do — if a flag exists, it belongs in the help.
  #
  # The rule: every publicly usable flag should appear in ctf-help. If you
  # add a new flag to any script in this toolkit, add it here too.
  echo "${_CTF_CYAN}Maintenance:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}ctf-install${_CTF_RESET}              Re-run machine installer"
  echo "  ${_CTF_BOLD}ctf-install --prod${_CTF_RESET}       Re-run targeting production install"
  echo "  ${_CTF_BOLD}ctf-install --check${_CTF_RESET}      Dependency check only"
  echo "  ${_CTF_BOLD}ctf-sync${_CTF_RESET}                 Pull latest repo changes"
  echo "  ${_CTF_BOLD}ctf-sync --prod${_CTF_RESET}          Pull latest changes for production"
  echo ""

  # Show known platforms inline
  echo "${_CTF_CYAN}Known Platforms:${_CTF_RESET}"
  for entry in "${KNOWN_PLATFORMS[@]}"; do
    local code="${entry%%:*}"
    local name="${entry##*:}"
    printf "  ${_CTF_BOLD}%-6s${_CTF_RESET} ${_CTF_DIM}%s${_CTF_RESET}\n" "$code" "$name"
  done
  echo ""

  # Show workspace folders
  echo "${_CTF_CYAN}Box Workspace Folders:${_CTF_RESET}"
  echo "  ${_CTF_DIM}${_CTF_BOX_DIRS[*]}${_CTF_RESET}"
  echo ""

  # Show active environment
  echo "${_CTF_CYAN}Active Environment:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}CTF_REPO_DIR${_CTF_RESET}  ${_CTF_DIM}${CTF_REPO_DIR}${_CTF_RESET}"
  echo "  ${_CTF_BOLD}CTF_BASE${_CTF_RESET}      ${_CTF_DIM}${CTF_BASE}${_CTF_RESET}"
  if [[ -f "$_CTF_HOME/.ctf_env_mode" ]]; then
    echo "  ${_CTF_BOLD}Mode file${_CTF_RESET}     ${_CTF_DIM}~/.ctf_env_mode (use 'rm ~/.ctf_env_mode' to reset to auto-detect)${_CTF_RESET}"
  fi
  echo ""
}