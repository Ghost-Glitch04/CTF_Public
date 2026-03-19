#!/bin/zsh
# =============================================================================
# ctf-env.sh — CTF Global Environment Manager
# =============================================================================
# ABOUT:
#   Manages global CTF session variables (TARGET, PLATFORM, BOXNAME) and
#   persists them to ~/.ctf_env for use across all terminals and scripts.
#
# INSTALL (fresh machine — run once):
#   chmod +x ctf-env.sh
#   ./ctf-env.sh --install
#
# USAGE (after install, these commands are available everywhere):
#   set-target  10.129.5.56       — Set the target IP
#   set-platform HTB              — Set the platform
#   set-box     Archetype         — Set the box name
#   ctf-status                    — Print current session state
#   ctf-clear                     — Clear all session variables
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================

# --- Paths --------------------------------------------------------------------
CTF_BASE="/opt/CTF"
CTF_ENV_FILE="$HOME/.ctf_env"
ZSHRC="$HOME/.zshrc"

# --- Colors -------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# --- Recognized platforms -----------------------------------------------------
# To add a new platform: append to this array and document the full name below
KNOWN_PLATFORMS=(
  "HTB"   # Hack The Box
  "LD"    # LetsDefend
  "DC"    # DefCon
  "THM"   # TryHackMe
  "GGL"   # Google CTF
)

PLATFORM_NAMES=(
  "HTB:Hack The Box"
  "LD:LetsDefend"
  "DC:DefCon"
  "THM:TryHackMe"
  "GGL:Google CTF"
)

# =============================================================================
# SELF-INSTALL
# =============================================================================
# Run: ./ctf-env.sh --install
# - Creates /opt/CTF/ base directory
# - Creates ~/.ctf_env
# - Adds source line to ~/.zshrc if not already present
# - Symlinks set-target, set-platform, set-box, ctf-status, ctf-clear
# =============================================================================

install_ctf_env() {
  echo ""
  echo "${BOLD}${CYAN}=== CTF Environment Installer ===${RESET}"
  echo ""

  # -- Create /opt/CTF base directory --
  if [[ ! -d "$CTF_BASE" ]]; then
    sudo mkdir -p "$CTF_BASE"
    sudo chown -R "$USER":"$USER" "$CTF_BASE"
    echo "${GREEN}[OK]${RESET}    Created base directory: ${BOLD}${CTF_BASE}${RESET}"
  else
    echo "${DIM}[SKIP]  Base directory already exists: ${CTF_BASE}${RESET}"
  fi

  # -- Create platform subdirectories --
  for platform in "${KNOWN_PLATFORMS[@]}"; do
    PDIR="${CTF_BASE}/${platform}"
    if [[ ! -d "$PDIR" ]]; then
      mkdir -p "$PDIR"
      echo "${GREEN}[OK]${RESET}    Created platform directory: ${BOLD}${PDIR}${RESET}"
    else
      echo "${DIM}[SKIP]  Platform directory exists: ${PDIR}${RESET}"
    fi
  done

  # -- Create ~/.ctf_env if it doesn't exist --
  if [[ ! -f "$CTF_ENV_FILE" ]]; then
    cat > "$CTF_ENV_FILE" << 'EOF'
# =============================================================================
# ~/.ctf_env — CTF Session Environment
# Auto-managed by ctf-env.sh
# Manual edits are fine but will be overwritten by set-* commands
# =============================================================================

# --- Current session variables ------------------------------------------------
export TARGET=""
export PLATFORM=""
export BOXNAME=""
export BOX_DIR=""

# --- Recognized platforms -----------------------------------------------------
KNOWN_PLATFORMS=(HTB LD DC THM GGL)

# --- Colors -------------------------------------------------------------------
_RED='\033[0;31m'
_YELLOW='\033[1;33m'
_GREEN='\033[0;32m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_DIM='\033[2m'
_RESET='\033[0m'

# =============================================================================
# set-target <ip>
# Sets $TARGET, updates .env in current box directory if BOX_DIR is set
# =============================================================================
set-target() {
  local new_ip="$1"

  if [[ -z "$new_ip" ]]; then
    echo "${_RED}[ERROR]${_RESET} Usage: set-target <ip_address>"
    return 1
  fi

  # Validate IP format
  if ! [[ "$new_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "${_RED}[ERROR]${_RESET} Invalid IP address: ${_BOLD}${new_ip}${_RESET}"
    return 1
  fi

  # Check each octet
  local IFS='.'
  local octets=("${(@s/./)new_ip}")
  for octet in $octets; do
    if (( octet > 255 )); then
      echo "${_RED}[ERROR]${_RESET} Invalid IP address: ${_BOLD}${new_ip}${_RESET}"
      return 1
    fi
  done

  local old_ip="$TARGET"
  export TARGET="$new_ip"

  # Show old → new if changing
  if [[ -n "$old_ip" && "$old_ip" != "$new_ip" ]]; then
    echo "${_CYAN}[TARGET]${_RESET} ${_DIM}${old_ip}${_RESET} → ${_BOLD}${new_ip}${_RESET}"
  else
    echo "${_CYAN}[TARGET]${_RESET} Set to ${_BOLD}${new_ip}${_RESET}"
  fi

  _ctf_update_env
  _ctf_update_box_env
}

# =============================================================================
# set-platform <platform>
# Sets $PLATFORM, validates against known list, creates directory if needed
# =============================================================================
set-platform() {
  local new_platform="${1:u}"  # uppercase

  if [[ -z "$new_platform" ]]; then
    echo "${_RED}[ERROR]${_RESET} Usage: set-platform <platform>"
    echo "         Known: ${KNOWN_PLATFORMS[*]}"
    return 1
  fi

  # Validate against known platforms
  local known=false
  for p in "${KNOWN_PLATFORMS[@]}"; do
    if [[ "$p" == "$new_platform" ]]; then
      known=true
      break
    fi
  done

  if ! $known; then
    echo "${_YELLOW}[WARN]${_RESET}  '${_BOLD}${new_platform}${_RESET}' is not a recognized platform."
    echo "         Known platforms: ${_BOLD}${KNOWN_PLATFORMS[*]}${_RESET}"
    echo -n "         Continue anyway? [y/N]: "
    read confirm
    if [[ "$confirm" != [yY] ]]; then
      echo "${_RED}[ABORT]${_RESET} Platform not set."
      return 1
    fi
  fi

  local old_platform="$PLATFORM"
  export PLATFORM="$new_platform"

  # Show old → new if changing
  if [[ -n "$old_platform" && "$old_platform" != "$new_platform" ]]; then
    echo "${_CYAN}[PLATFORM]${_RESET} ${_DIM}${old_platform}${_RESET} → ${_BOLD}${new_platform}${_RESET}"
  else
    echo "${_CYAN}[PLATFORM]${_RESET} Set to ${_BOLD}${new_platform}${_RESET}"
  fi

  # Create platform directory if it doesn't exist
  local pdir="/opt/CTF/${new_platform}"
  if [[ ! -d "$pdir" ]]; then
    mkdir -p "$pdir"
    echo "${_GREEN}[OK]${_RESET}    Created: ${_BOLD}${pdir}${_RESET}"
  fi

  # Update BOX_DIR if BOXNAME is already set
  if [[ -n "$BOXNAME" ]]; then
    export BOX_DIR="/opt/CTF/${PLATFORM}/${BOXNAME}"
  fi

  _ctf_update_env
  _ctf_update_box_env
}

# =============================================================================
# set-box <boxname>
# Sets $BOXNAME, creates box directory structure if it doesn't exist
# =============================================================================
set-box() {
  local new_box="${1//[^a-zA-Z0-9_-]/_}"  # sanitize

  if [[ -z "$new_box" ]]; then
    echo "${_RED}[ERROR]${_RESET} Usage: set-box <box_name>"
    return 1
  fi

  local old_box="$BOXNAME"
  export BOXNAME="$new_box"

  # Show old → new if changing
  if [[ -n "$old_box" && "$old_box" != "$new_box" ]]; then
    echo "${_CYAN}[BOX]${_RESET} ${_DIM}${old_box}${_RESET} → ${_BOLD}${new_box}${_RESET}"
  else
    echo "${_CYAN}[BOX]${_RESET} Set to ${_BOLD}${new_box}${_RESET}"
  fi

  # Update BOX_DIR
  if [[ -n "$PLATFORM" ]]; then
    export BOX_DIR="/opt/CTF/${PLATFORM}/${BOXNAME}"

    # Create directory structure if it doesn't exist
    if [[ ! -d "$BOX_DIR" ]]; then
      mkdir -p "${BOX_DIR}/scans"
      mkdir -p "${BOX_DIR}/scans/nmap"
      mkdir -p "${BOX_DIR}/exploits"
      mkdir -p "${BOX_DIR}/notes"
      mkdir -p "${BOX_DIR}/flags"
      echo "${_GREEN}[OK]${_RESET}    Created workspace: ${_BOLD}${BOX_DIR}${_RESET}"
    fi
  else
    echo "${_YELLOW}[WARN]${_RESET}  \$PLATFORM not set — BOX_DIR not created yet."
    echo "         Run ${_BOLD}set-platform <platform>${_RESET} first."
  fi

  _ctf_update_env
  _ctf_update_box_env
}

# =============================================================================
# ctf-status
# Prints the current session state in a clean summary
# =============================================================================
ctf-status() {
  echo ""
  echo "${_BOLD}${_CYAN}╔══ CTF Session Status ══════════════════════╗${_RESET}"

  # Platform with full name lookup
  if [[ -n "$PLATFORM" ]]; then
    echo "${_BOLD}${_CYAN}║${_RESET}  Platform  : ${_BOLD}${PLATFORM}${_RESET}"
  else
    echo "${_BOLD}${_CYAN}║${_RESET}  Platform  : ${_DIM}not set${_RESET}"
  fi

  if [[ -n "$BOXNAME" ]]; then
    echo "${_BOLD}${_CYAN}║${_RESET}  Box       : ${_BOLD}${BOXNAME}${_RESET}"
  else
    echo "${_BOLD}${_CYAN}║${_RESET}  Box       : ${_DIM}not set${_RESET}"
  fi

  if [[ -n "$TARGET" ]]; then
    echo "${_BOLD}${_CYAN}║${_RESET}  Target IP : ${_BOLD}${TARGET}${_RESET}"
  else
    echo "${_BOLD}${_CYAN}║${_RESET}  Target IP : ${_DIM}not set${_RESET}"
  fi

  if [[ -n "$BOX_DIR" ]]; then
    echo "${_BOLD}${_CYAN}║${_RESET}  Box Dir   : ${_BOLD}${BOX_DIR}${_RESET}"
  else
    echo "${_BOLD}${_CYAN}║${_RESET}  Box Dir   : ${_DIM}not set${_RESET}"
  fi

  echo "${_BOLD}${_CYAN}╚════════════════════════════════════════════╝${_RESET}"
  echo ""
}

# =============================================================================
# ctf-clear
# Clears all session variables
# =============================================================================
ctf-clear() {
  echo -n "${_YELLOW}[WARN]${_RESET}  Clear all CTF session variables? [y/N]: "
  read confirm
  if [[ "$confirm" == [yY] ]]; then
    export TARGET=""
    export PLATFORM=""
    export BOXNAME=""
    export BOX_DIR=""
    _ctf_update_env
    echo "${_GREEN}[OK]${_RESET}    Session cleared."
  else
    echo "${_DIM}[SKIP]  Nothing changed.${_RESET}"
  fi
}

# =============================================================================
# _ctf_update_env (internal)
# Rewrites ~/.ctf_env variable block with current values
# =============================================================================
_ctf_update_env() {
  # Only update the export lines, leave the rest of the file intact
  # Uses a temp file to safely rewrite
  local tmp=$(mktemp)
  while IFS= read -r line; do
    case "$line" in
      "export TARGET="*)    echo "export TARGET=\"${TARGET}\""     ;;
      "export PLATFORM="*)  echo "export PLATFORM=\"${PLATFORM}\"" ;;
      "export BOXNAME="*)   echo "export BOXNAME=\"${BOXNAME}\""   ;;
      "export BOX_DIR="*)   echo "export BOX_DIR=\"${BOX_DIR}\""   ;;
      *)                    echo "$line"                            ;;
    esac
  done < "$HOME/.ctf_env" > "$tmp"
  mv "$tmp" "$HOME/.ctf_env"
}

# =============================================================================
# _ctf_update_box_env (internal)
# Updates the .env file inside the current box directory
# =============================================================================
_ctf_update_box_env() {
  if [[ -n "$BOX_DIR" && -d "$BOX_DIR" ]]; then
    cat > "${BOX_DIR}/.env" << ENVEOF
# Auto-generated by ctf-env.sh — $(date)
# Source this in any terminal: source ${BOX_DIR}/.env
export TARGET="${TARGET}"
export PLATFORM="${PLATFORM}"
export BOXNAME="${BOXNAME}"
export BOX_DIR="${BOX_DIR}"
ENVEOF
  fi
}
EOF
    echo "${GREEN}[OK]${RESET}    Created: ${BOLD}${CTF_ENV_FILE}${RESET}"
  else
    echo "${DIM}[SKIP]  ~/.ctf_env already exists${RESET}"
  fi

  # -- Add source line to ~/.zshrc if not already present --
  if grep -q "source.*\.ctf_env" "$ZSHRC" 2>/dev/null; then
    echo "${DIM}[SKIP]  ~/.zshrc already sources ~/.ctf_env${RESET}"
  else
    echo "" >> "$ZSHRC"
    echo "# CTF Environment — auto-loaded by ctf-env.sh" >> "$ZSHRC"
    echo "source ~/.ctf_env" >> "$ZSHRC"
    echo "${GREEN}[OK]${RESET}    Added source line to: ${BOLD}${ZSHRC}${RESET}"
  fi

  # -- Done --
  echo ""
  echo "${GREEN}${BOLD}[READY]${RESET} Installation complete."
  echo ""
  echo "  Reload your shell now:"
  echo "  ${BOLD}source ~/.zshrc${RESET}"
  echo ""
  echo "  Then start a new CTF session:"
  echo "  ${BOLD}set-platform HTB${RESET}"
  echo "  ${BOLD}set-box      Archetype${RESET}"
  echo "  ${BOLD}set-target   10.129.5.56${RESET}"
  echo "  ${BOLD}ctf-status${RESET}"
  echo ""
}

# =============================================================================
# ENTRY POINT
# =============================================================================
case "$1" in
  --install) install_ctf_env ;;
  --help|-h)
    echo ""
    echo "${BOLD}ctf-env.sh${RESET} — CTF Global Environment Manager"
    echo ""
    echo "  ${BOLD}./ctf-env.sh --install${RESET}   First-time setup on a fresh machine"
    echo "  ${BOLD}./ctf-env.sh --help${RESET}      Show this message"
    echo ""
    echo "  After install, these commands are available in any terminal:"
    echo "  ${CYAN}set-platform${RESET}  HTB|LD|DC|THM|GGL"
    echo "  ${CYAN}set-box${RESET}       <box_name>"
    echo "  ${CYAN}set-target${RESET}    <ip_address>"
    echo "  ${CYAN}ctf-status${RESET}    Print current session state"
    echo "  ${CYAN}ctf-clear${RESET}     Clear all session variables"
    echo ""
    ;;
  *)
    echo "${YELLOW}[INFO]${RESET}  To install, run: ${BOLD}./ctf-env.sh --install${RESET}"
    echo "         To see options:  ${BOLD}./ctf-env.sh --help${RESET}"
    ;;
esac
