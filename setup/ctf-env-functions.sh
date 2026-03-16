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
# REPO DIR RESOLUTION
# =============================================================================
# TEACHING NOTE — This block runs every time a terminal session starts (because
# this file is sourced by ~/.zshrc). It resolves and exports CTF_REPO_DIR so
# all other scripts that read it get a consistent value.
#
# The three-pass check mirrors the logic in ctf-sync.sh and ctf-install.sh.
# Keeping the same detection order across all three files means they all agree
# on which directory is authoritative, regardless of which one runs first.
#
# We don't prompt here (unlike ctf-sync.sh) because this file is sourced
# non-interactively on terminal open. Prompting at shell startup would be
# disruptive. Instead we fall back to the production path silently — by the
# time a dev has run ctf-sync.sh once, the repo exists and auto-detection
# finds it without needing a prompt.
# =============================================================================

if [[ -z "$CTF_REPO_DIR" ]]; then
  if [[ -d "$HOME/github/CTF_Public" ]]; then
    export CTF_REPO_DIR="$HOME/github/CTF_Public"
  elif [[ -d "/opt/CTF_Public" ]]; then
    export CTF_REPO_DIR="/opt/CTF_Public"
  else
    export CTF_REPO_DIR="/opt/CTF_Public"   # default before first sync
  fi
fi

# Base directory where all CTF workspaces live
# TEACHING NOTE — CTF_BASE_DIR follows the same override pattern as CTF_REPO_DIR.
# On a dev machine you might want workspaces under ~/CTF rather than /opt/CTF.
# Export CTF_BASE_DIR before sourcing this file (or set it in your .zshrc above
# the source line) to redirect all workspace creation automatically.
CTF_BASE="${CTF_BASE_DIR:-/opt/CTF}"

# Sub-directories created for every new box workspace
# To add a new folder to every box: append to this array
_CTF_BOX_DIRS=(
  "scans"
  "exploits"
  "notes"
  "flags"
  "loot"
)

# Known platforms — format: "CODE:Full Name"
# CODE is what you type (e.g. set-platform HTB)
# Full Name is used in ctf-status and directory creation
# To add a platform: append a new "CODE:Full Name" line
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
# =============================================================================

_ctf_persist() {
  local tmp
  tmp=$(mktemp) || { _ctf_err "Could not create temp file for persist."; return 1; }

  while IFS= read -r line; do
    case "$line" in
      "export ADDRESS="*) echo "export ADDRESS=\"${ADDRESS}\""   ;;
      "export PLATFORM="*) echo "export PLATFORM=\"${PLATFORM}\"" ;;
      "export BOXNAME="*)  echo "export BOXNAME=\"${BOXNAME}\""   ;;
      "export BOX_DIR="*)  echo "export BOX_DIR=\"${BOX_DIR}\""   ;;
      *)                   echo "$line"                            ;;
    esac
  done < "$HOME/.ctf_env" > "$tmp"

  mv "$tmp" "$HOME/.ctf_env"
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
  local IFS='.'
  local octets=("${(@s/./)new_ip}")
  for octet in $octets; do
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
    read confirm
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

  # Create the platform directory if it doesn't exist
  local pdir="${CTF_BASE}/${new_platform}"
  if [[ ! -d "$pdir" ]]; then
    mkdir -p "$pdir" && _ctf_ok "Created: ${_CTF_BOLD}${pdir}${_CTF_RESET}"
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
    # Create each subdirectory defined in _CTF_BOX_DIRS
    # TEACHING NOTE — Driving behavior from config arrays.
    # Adding a new workspace folder is one line in _CTF_BOX_DIRS at the top.
    # The loop here doesn't need to change. Data drives behavior.
    for subdir in "${_CTF_BOX_DIRS[@]}"; do
      mkdir -p "${BOX_DIR}/${subdir}"
    done

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

  # Show which environment is active
  local env_label
  if [[ "$CTF_REPO_DIR" == "$HOME/github/CTF_Public" ]]; then
    env_label="${_CTF_YELLOW}dev${_CTF_RESET}  ${_CTF_DIM}(${CTF_REPO_DIR})${_CTF_RESET}"
  else
    env_label="${_CTF_GREEN}prod${_CTF_RESET} ${_CTF_DIM}(${CTF_REPO_DIR})${_CTF_RESET}"
  fi

  echo ""
  echo "${_CTF_BOLD}${_CTF_CYAN}╔══ CTF Session Status ══════════════════════╗${_CTF_RESET}"
  echo "${_CTF_BOLD}${_CTF_CYAN}║${_CTF_RESET}  Env        : ${env_label}"
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
  read confirm
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
  echo "  ${_CTF_BOLD}set-box <n>${_CTF_RESET}         Set active box and create workspace"
  echo "  ${_CTF_BOLD}set-address <ip>${_CTF_RESET}       Set target IP address"
  echo ""
  echo "${_CTF_CYAN}Session Info:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}ctf-status${_CTF_RESET}             Show current session state"
  echo "  ${_CTF_BOLD}ctf-help${_CTF_RESET}               Show this message"
  echo ""
  echo "${_CTF_CYAN}Session Control:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}ctf-clear${_CTF_RESET}              Clear all session variables"
  echo ""
  echo "${_CTF_CYAN}Maintenance:${_CTF_RESET}"
  echo "  ${_CTF_BOLD}ctf-install${_CTF_RESET}            Re-run machine installer"
  echo "  ${_CTF_BOLD}ctf-install --check${_CTF_RESET}    Dependency check only"
  echo "  ${_CTF_BOLD}ctf-sync${_CTF_RESET}               Pull latest repo changes"
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
  echo ""
}