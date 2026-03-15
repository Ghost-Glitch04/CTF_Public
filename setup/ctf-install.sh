#!/bin/zsh
# =============================================================================
# ctf-install.sh — CTF Toolkit Machine Installer
# =============================================================================
# ABOUT:
#   One-time setup script for any machine you work from.
#   Run this once after cloning CTF_Public to a new machine.
#   Safe to re-run — backs up existing config before overwriting.
#
# WHAT IT DOES:
#   1. Confirmation prompt  — prevents accidental runs
#   2. Dependency check     — lists missing tools with install commands
#   3. Backup ~/.ctf_env    — saves to ~/.ctf_backups/ with timestamp
#   4. Deploy ~/.ctf_env    — fresh copy of session functions
#   5. Patch ~/.zshrc       — adds source line if not present
#   6. Build /opt/CTF/      — platform directory tree
#   7. Symlink all scripts  — everything in setup/ lands in /usr/local/bin/
#   8. Run ctf-sync         — ensures repo is current
#
# USAGE:
#   First time:   chmod +x ctf-install.sh && ./ctf-install.sh
#   Re-run:       ctf-install   (after first install, symlink is available)
#   Help:         ctf-install --help
#
# ADDING NEW TOOLS TO CHECK:
#   Find the REQUIRED_TOOLS section below and add entries to the array.
#   Format: "command_name:display_name:apt_package"
#   Example: "sqlmap:SQLMap:sqlmap"
#
# ADDING NEW PLATFORMS:
#   Find the KNOWN_PLATFORMS section below and add to the array.
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================

# --- Configuration ------------------------------------------------------------
REPO_DIR="/opt/CTF_Public"
CTF_BASE="/opt/CTF"
CTF_ENV_FILE="$HOME/.ctf_env"
CTF_ENV_SOURCE="$REPO_DIR/setup/ctf-env-functions.sh"
BACKUP_DIR="$HOME/.ctf_backups"
ZSHRC="$HOME/.zshrc"
SYMLINK_DIR="/usr/local/bin"
SETUP_DIR="$REPO_DIR/setup"

# --- Known platforms ----------------------------------------------------------
# To add a platform: append "CODE:Full Name" to this array
KNOWN_PLATFORMS=(
  "HTB:Hack The Box"
  "LD:LetsDefend"
  "DC:DefCon"
  "THM:TryHackMe"
  "GGL:Google CTF"
)

# --- Required tools -----------------------------------------------------------
# FORMAT: "command:display_name:apt_package"
# To add a tool: append a new entry following this exact format
# command     = what's tested with `command -v`
# display_name = shown in output
# apt_package  = used in the install command shown to user
REQUIRED_TOOLS=(
  "curl:cURL:curl"
  "nmap:Nmap:nmap"
  "git:Git:git"
  "wget:Wget:wget"
  "python3:Python3:python3"
)

# --- Colors -------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# --- Helpers ------------------------------------------------------------------
print_ok()   { echo "${GREEN}[OK]${RESET}    $1"; }
print_skip() { echo "${DIM}[SKIP]  $1${RESET}"; }
print_warn() { echo "${YELLOW}[WARN]${RESET}  $1"; }
print_err()  { echo "${RED}[ERROR]${RESET} $1"; }
print_info() { echo "${CYAN}[INFO]${RESET}  $1"; }
print_step() { echo ""; echo "${BOLD}${CYAN}── $1 ──${RESET}"; }

# --- Help ---------------------------------------------------------------------
show_help() {
  echo ""
  echo "${BOLD}ctf-install.sh${RESET} — CTF Toolkit Machine Installer"
  echo ""
  echo "${CYAN}USAGE:${RESET}"
  echo "  ./ctf-install.sh          Run full installation"
  echo "  ./ctf-install.sh --help   Show this message"
  echo "  ./ctf-install.sh --check  Dependency check only, no changes made"
  echo ""
  echo "${CYAN}ADDING TOOLS TO CHECK:${RESET}"
  echo "  Edit REQUIRED_TOOLS array in this script."
  echo "  Format: \"command:display_name:apt_package\""
  echo ""
  echo "${CYAN}ADDING PLATFORMS:${RESET}"
  echo "  Edit KNOWN_PLATFORMS array in this script."
  echo "  Format: \"CODE:Full Name\""
  echo ""
  echo "${CYAN}BACKUP LOCATION:${RESET}"
  echo "  $BACKUP_DIR"
  echo ""
}

# =============================================================================
# STEP 1 — DEPENDENCY CHECK
# =============================================================================
run_dependency_check() {
  print_step "Dependency Check"

  local missing=()
  local present=()

  for entry in "${REQUIRED_TOOLS[@]}"; do
    local cmd="${entry%%:*}"
    local rest="${entry#*:}"
    local name="${rest%%:*}"
    local pkg="${rest##*:}"

    if command -v "$cmd" &>/dev/null; then
      local version
      version=$(${cmd} --version 2>/dev/null | head -1 | awk '{print $NF}')
      print_ok "${name} ${DIM}(${version})${RESET}"
      present+=("$cmd")
    else
      print_warn "${name} ${DIM}— not found${RESET}"
      missing+=("${name}:${pkg}")
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    echo ""
    print_ok "All required tools are installed."
  else
    echo ""
    echo "${YELLOW}${BOLD}Missing tools detected.${RESET}"
    echo "${DIM}Run the following commands to install:${RESET}"
    echo ""
    for entry in "${missing[@]}"; do
      local name="${entry%%:*}"
      local pkg="${entry##*:}"
      echo "  ${CYAN}sudo apt install -y ${pkg}${RESET}   ${DIM}# installs ${name}${RESET}"
    done
    echo ""
    echo "  ${DIM}Or install all at once:${RESET}"
    echo -n "  ${CYAN}sudo apt install -y"
    for entry in "${missing[@]}"; do
      echo -n " ${entry##*:}"
    done
    echo "${RESET}"
    echo ""
    print_info "Installation will continue — missing tools won't break the setup."
    print_info "Install them when ready and re-run ${BOLD}ctf-install${RESET} to verify."
  fi

  # If --check flag, stop here
  if [[ "$1" == "--check-only" ]]; then
    echo ""
    exit 0
  fi
}

# =============================================================================
# STEP 2 — BACKUP ~/.ctf_env
# =============================================================================
run_backup() {
  print_step "Backing Up ~/.ctf_env"

  if [[ ! -f "$CTF_ENV_FILE" ]]; then
    print_skip "No existing ~/.ctf_env found — nothing to back up."
    return 0
  fi

  # Create backup directory if needed
  if [[ ! -d "$BACKUP_DIR" ]]; then
    mkdir -p "$BACKUP_DIR"
    print_ok "Created backup directory: ${BOLD}${BACKUP_DIR}${RESET}"
  fi

  local timestamp
  timestamp=$(date +"%Y%m%d_%H%M%S")
  local backup_file="${BACKUP_DIR}/.ctf_env.${timestamp}"

  cp "$CTF_ENV_FILE" "$backup_file"
  print_ok "Backed up to: ${BOLD}${backup_file}${RESET}"

  # Show how many backups exist and tip on cleanup
  local backup_count
  backup_count=$(ls "$BACKUP_DIR"/.ctf_env.* 2>/dev/null | wc -l | tr -d ' ')
  if (( backup_count > 5 )); then
    print_info "${backup_count} backups in ${BACKUP_DIR}"
    print_info "To clean old backups: ${BOLD}ls ~/.ctf_backups/${RESET} then remove as needed"
  fi
}

# =============================================================================
# STEP 3 — DEPLOY ~/.ctf_env
# =============================================================================
run_deploy_env() {
  print_step "Deploying ~/.ctf_env"

  # Extract current session variable values before overwriting
  local cur_target="" cur_platform="" cur_boxname="" cur_boxdir=""
  if [[ -f "$CTF_ENV_FILE" ]]; then
    cur_target=$(grep   '^export TARGET='   "$CTF_ENV_FILE" | cut -d'"' -f2 | tr -d '\n')
    cur_platform=$(grep '^export PLATFORM=' "$CTF_ENV_FILE" | cut -d'"' -f2 | tr -d '\n')
    cur_boxname=$(grep  '^export BOXNAME='  "$CTF_ENV_FILE" | cut -d'"' -f2 | tr -d '\n')
    cur_boxdir=$(grep   '^export BOX_DIR='  "$CTF_ENV_FILE" | cut -d'"' -f2 | tr -d '\n')
  fi

  # Build the platform arrays dynamically from KNOWN_PLATFORMS
  local platform_codes=()
  local platform_name_entries=()
  for entry in "${KNOWN_PLATFORMS[@]}"; do
    local code="${entry%%:*}"
    platform_codes+=("\"${code}\"")
    platform_name_entries+=("  \"${entry}\"")
  done

  # Write fresh ~/.ctf_env — session variables preserved from old file
  cat > "$CTF_ENV_FILE" << ENVEOF
# =============================================================================
# ~/.ctf_env — CTF Session Functions
# Auto-deployed by ctf-install.sh — do not edit install logic here
# To update: edit ctf-install.sh in your repo and re-run ctf-install
# Last deployed: $(date)
# =============================================================================

# --- Current session variables -----------------------------------------------
export TARGET="${cur_target}"
export PLATFORM="${cur_platform}"
export BOXNAME="${cur_boxname}"
export BOX_DIR="${cur_boxdir}"

# --- Recognised platforms ----------------------------------------------------
# To add a platform: edit KNOWN_PLATFORMS in ctf-install.sh and re-run ctf-install
KNOWN_PLATFORMS=(${platform_codes[*]})

# --- Colors ------------------------------------------------------------------
_RED='\033[0;31m'
_YELLOW='\033[1;33m'
_GREEN='\033[0;32m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_DIM='\033[2m'
_RESET='\033[0m'

# =============================================================================
# set-target <ip>
# =============================================================================
set-target() {
  local new_ip="\$1"
  if [[ -z "\$new_ip" ]]; then
    echo "\${_RED}[ERROR]\${_RESET} Usage: set-target <ip_address>"; return 1
  fi
  if ! [[ "\$new_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\$ ]]; then
    echo "\${_RED}[ERROR]\${_RESET} Invalid IP address: \${_BOLD}\${new_ip}\${_RESET}"; return 1
  fi
  local IFS='.'
  local octets=("\${(@s/./)new_ip}")
  for octet in \$octets; do
    if (( octet > 255 )); then
      echo "\${_RED}[ERROR]\${_RESET} Invalid IP address: \${_BOLD}\${new_ip}\${_RESET}"; return 1
    fi
  done
  local old="\$TARGET"
  export TARGET="\$new_ip"
  if [[ -n "\$old" && "\$old" != "\$new_ip" ]]; then
    echo "\${_CYAN}[TARGET]\${_RESET} \${_DIM}\${old}\${_RESET} → \${_BOLD}\${new_ip}\${_RESET}"
  else
    echo "\${_CYAN}[TARGET]\${_RESET} Set to \${_BOLD}\${new_ip}\${_RESET}"
  fi
  _ctf_update_env
  _ctf_update_box_env
}

# =============================================================================
# set-platform <platform>
# =============================================================================
set-platform() {
  local new_platform="\${1:u}"
  if [[ -z "\$new_platform" ]]; then
    echo "\${_RED}[ERROR]\${_RESET} Usage: set-platform <platform>"
    echo "         Known: \${KNOWN_PLATFORMS[*]}"; return 1
  fi
  local known=false
  for p in "\${KNOWN_PLATFORMS[@]}"; do
    [[ "\$p" == "\$new_platform" ]] && known=true && break
  done
  if ! \$known; then
    echo "\${_YELLOW}[WARN]\${_RESET}  '\${_BOLD}\${new_platform}\${_RESET}' is not a recognised platform."
    echo "         Known: \${_BOLD}\${KNOWN_PLATFORMS[*]}\${_RESET}"
    echo -n "         Continue anyway? [y/N]: "; read confirm
    [[ "\$confirm" != [yY] ]] && echo "\${_RED}[ABORT]\${_RESET} Platform not set." && return 1
  fi
  local old="\$PLATFORM"
  export PLATFORM="\$new_platform"
  if [[ -n "\$old" && "\$old" != "\$new_platform" ]]; then
    echo "\${_CYAN}[PLATFORM]\${_RESET} \${_DIM}\${old}\${_RESET} → \${_BOLD}\${new_platform}\${_RESET}"
  else
    echo "\${_CYAN}[PLATFORM]\${_RESET} Set to \${_BOLD}\${new_platform}\${_RESET}"
  fi
  local pdir="${CTF_BASE}/\${new_platform}"
  if [[ ! -d "\$pdir" ]]; then
    mkdir -p "\$pdir"
    echo "\${_GREEN}[OK]\${_RESET}    Created: \${_BOLD}\${pdir}\${_RESET}"
  fi
  [[ -n "\$BOXNAME" ]] && export BOX_DIR="${CTF_BASE}/\${PLATFORM}/\${BOXNAME}"
  _ctf_update_env
  _ctf_update_box_env
}

# =============================================================================
# set-box <boxname>
# =============================================================================
set-box() {
  local new_box="\${1//[^a-zA-Z0-9_-]/_}"
  if [[ -z "\$new_box" ]]; then
    echo "\${_RED}[ERROR]\${_RESET} Usage: set-box <box_name>"; return 1
  fi
  local old="\$BOXNAME"
  export BOXNAME="\$new_box"
  if [[ -n "\$old" && "\$old" != "\$new_box" ]]; then
    echo "\${_CYAN}[BOX]\${_RESET} \${_DIM}\${old}\${_RESET} → \${_BOLD}\${new_box}\${_RESET}"
  else
    echo "\${_CYAN}[BOX]\${_RESET} Set to \${_BOLD}\${new_box}\${_RESET}"
  fi
  if [[ -n "\$PLATFORM" ]]; then
    export BOX_DIR="${CTF_BASE}/\${PLATFORM}/\${BOXNAME}"
    if [[ ! -d "\$BOX_DIR" ]]; then
      mkdir -p "\${BOX_DIR}/scans" "\${BOX_DIR}/exploits" "\${BOX_DIR}/notes" "\${BOX_DIR}/flags"
      echo "\${_GREEN}[OK]\${_RESET}    Created workspace: \${_BOLD}\${BOX_DIR}\${_RESET}"
    fi
  else
    echo "\${_YELLOW}[WARN]\${_RESET}  \\\$PLATFORM not set — run \${_BOLD}set-platform <platform>\${_RESET} first."
  fi
  _ctf_update_env
  _ctf_update_box_env
}

# =============================================================================
# ctf-status
# =============================================================================
ctf-status() {
  echo ""
  echo "\${_BOLD}\${_CYAN}╔══ CTF Session Status ══════════════════════╗\${_RESET}"
  [[ -n "\$PLATFORM" ]] && echo "\${_BOLD}\${_CYAN}║\${_RESET}  Platform  : \${_BOLD}\${PLATFORM}\${_RESET}" \
                        || echo "\${_BOLD}\${_CYAN}║\${_RESET}  Platform  : \${_DIM}not set\${_RESET}"
  [[ -n "\$BOXNAME"  ]] && echo "\${_BOLD}\${_CYAN}║\${_RESET}  Box       : \${_BOLD}\${BOXNAME}\${_RESET}"  \
                        || echo "\${_BOLD}\${_CYAN}║\${_RESET}  Box       : \${_DIM}not set\${_RESET}"
  [[ -n "\$TARGET"   ]] && echo "\${_BOLD}\${_CYAN}║\${_RESET}  Target IP : \${_BOLD}\${TARGET}\${_RESET}"   \
                        || echo "\${_BOLD}\${_CYAN}║\${_RESET}  Target IP : \${_DIM}not set\${_RESET}"
  [[ -n "\$BOX_DIR"  ]] && echo "\${_BOLD}\${_CYAN}║\${_RESET}  Box Dir   : \${_BOLD}\${BOX_DIR}\${_RESET}"  \
                        || echo "\${_BOLD}\${_CYAN}║\${_RESET}  Box Dir   : \${_DIM}not set\${_RESET}"
  echo "\${_BOLD}\${_CYAN}╚════════════════════════════════════════════╝\${_RESET}"
  echo ""
}

# =============================================================================
# ctf-clear
# =============================================================================
ctf-clear() {
  echo -n "\${_YELLOW}[WARN]\${_RESET}  Clear all CTF session variables? [y/N]: "
  read confirm
  if [[ "\$confirm" == [yY] ]]; then
    export TARGET="" PLATFORM="" BOXNAME="" BOX_DIR=""
    _ctf_update_env
    echo "\${_GREEN}[OK]\${_RESET}    Session cleared."
  else
    echo "\${_DIM}[SKIP]  Nothing changed.\${_RESET}"
  fi
}

# =============================================================================
# _ctf_update_env (internal — rewrites session variable lines in ~/.ctf_env)
# =============================================================================
_ctf_update_env() {
  local tmp=\$(mktemp)
  while IFS= read -r line; do
    case "\$line" in
      "export TARGET="*)   echo "export TARGET=\"\${TARGET}\""     ;;
      "export PLATFORM="*) echo "export PLATFORM=\"\${PLATFORM}\"" ;;
      "export BOXNAME="*)  echo "export BOXNAME=\"\${BOXNAME}\""   ;;
      "export BOX_DIR="*)  echo "export BOX_DIR=\"\${BOX_DIR}\""   ;;
      *)                   echo "\$line"                            ;;
    esac
  done < "\$HOME/.ctf_env" > "\$tmp"
  mv "\$tmp" "\$HOME/.ctf_env"
}

# =============================================================================
# _ctf_update_box_env (internal — writes .env into current box directory)
# =============================================================================
_ctf_update_box_env() {
  if [[ -n "\$BOX_DIR" && -d "\$BOX_DIR" ]]; then
    cat > "\${BOX_DIR}/.env" << BOXENV
# Auto-generated by ctf-install.sh — \$(date)
# Source in any terminal: source \${BOX_DIR}/.env
export TARGET="\${TARGET}"
export PLATFORM="\${PLATFORM}"
export BOXNAME="\${BOXNAME}"
export BOX_DIR="\${BOX_DIR}"
BOXENV
  fi
}
ENVEOF

  print_ok "~/.ctf_env deployed."

  # Show preserved session values if any existed
  if [[ -n "$cur_target" || -n "$cur_platform" || -n "$cur_boxname" ]]; then
    print_info "Session variables preserved from previous install:"
    [[ -n "$cur_platform" ]] && echo "         PLATFORM = ${BOLD}${cur_platform}${RESET}"
    [[ -n "$cur_boxname"  ]] && echo "         BOXNAME  = ${BOLD}${cur_boxname}${RESET}"
    [[ -n "$cur_target"   ]] && echo "         TARGET   = ${BOLD}${cur_target}${RESET}"
  fi
}

# =============================================================================
# STEP 4 — PATCH ~/.zshrc
# =============================================================================
run_patch_zshrc() {
  print_step "Patching ~/.zshrc"

  if grep -q "source.*\.ctf_env" "$ZSHRC" 2>/dev/null; then
    print_skip "~/.zshrc already sources ~/.ctf_env"
  else
    echo "" >> "$ZSHRC"
    echo "# CTF Toolkit — loaded by ctf-install.sh on $(date +%Y-%m-%d)" >> "$ZSHRC"
    echo "source ~/.ctf_env" >> "$ZSHRC"
    print_ok "Added source line to ~/.zshrc"
  fi
}

# =============================================================================
# STEP 5 — BUILD /opt/CTF/ DIRECTORY TREE
# =============================================================================
run_build_directories() {
  print_step "Building /opt/CTF/ Directory Tree"

  if [[ ! -d "$CTF_BASE" ]]; then
    sudo mkdir -p "$CTF_BASE"
    sudo chown -R "$USER":"$USER" "$CTF_BASE"
    print_ok "Created: ${BOLD}${CTF_BASE}${RESET}"
  else
    print_skip "${CTF_BASE} already exists"
  fi

  for entry in "${KNOWN_PLATFORMS[@]}"; do
    local code="${entry%%:*}"
    local name="${entry##*:}"
    local pdir="${CTF_BASE}/${code}"
    if [[ ! -d "$pdir" ]]; then
      mkdir -p "$pdir"
      print_ok "Created: ${BOLD}${pdir}${RESET} ${DIM}(${name})${RESET}"
    else
      print_skip "${pdir} already exists"
    fi
  done
}

# =============================================================================
# STEP 6 — SYMLINK ALL SCRIPTS IN setup/ TO /usr/local/bin/
# =============================================================================
run_symlinks() {
  print_step "Symlinking Tools to /usr/local/bin/"

  if [[ ! -d "$SETUP_DIR" ]]; then
    print_err "Setup directory not found: ${BOLD}${SETUP_DIR}${RESET}"
    print_info "Is the repo cloned to ${BOLD}${REPO_DIR}${RESET}?"
    return 1
  fi

  local count=0
  for script in "$SETUP_DIR"/*.sh; do
    [[ -f "$script" ]] || continue

    # Derive symlink name: strip path and .sh extension
    local filename="${script##*/}"
    local linkname="${filename%.sh}"
    local linkpath="${SYMLINK_DIR}/${linkname}"

    # Make executable first
    chmod +x "$script"

    # Create or update symlink
    if [[ -L "$linkpath" ]]; then
      # Already a symlink — update it
      sudo ln -sf "$script" "$linkpath"
      print_ok "Updated symlink: ${BOLD}${linkname}${RESET} → ${DIM}${script}${RESET}"
    elif [[ -f "$linkpath" ]]; then
      # A real file exists at that name — warn and skip
      print_warn "File already exists at ${BOLD}${linkpath}${RESET} — skipping"
      print_info "Remove it manually to allow symlinking: ${BOLD}sudo rm ${linkpath}${RESET}"
    else
      sudo ln -sf "$script" "$linkpath"
      print_ok "Created symlink:  ${BOLD}${linkname}${RESET} → ${DIM}${script}${RESET}"
    fi

    (( count++ ))
  done

  echo ""
  print_info "${count} script(s) in ${SETUP_DIR} are now available in PATH."
  print_info "Any new .sh file added to setup/ will be symlinked on next ${BOLD}ctf-install${RESET}."
}

# =============================================================================
# STEP 7 — RUN ctf-sync TO ENSURE REPO IS CURRENT
# =============================================================================
run_sync() {
  print_step "Syncing Repo"

  if command -v ctf-sync &>/dev/null; then
    ctf-sync
  elif [[ -f "$SETUP_DIR/smart-sync.sh" ]]; then
    bash "$SETUP_DIR/smart-sync.sh"
  else
    print_warn "ctf-sync not available yet — skipping."
    print_info "It will be available after this install completes."
  fi
}

# =============================================================================
# ENTRY POINT
# =============================================================================
case "$1" in
  --help|-h)
    show_help
    exit 0
    ;;
  --check)
    echo ""
    echo "${BOLD}${CYAN}=== CTF Dependency Check ===${RESET}"
    run_dependency_check "--check-only"
    exit 0
    ;;
esac

# --- Confirmation prompt ------------------------------------------------------
echo ""
echo "${BOLD}${CYAN}=== CTF Toolkit Installer ===${RESET}"
echo ""
echo "  This will configure your machine for CTF work:"
echo "  ${DIM}Repo:    ${REPO_DIR}${RESET}"
echo "  ${DIM}CTF dir: ${CTF_BASE}${RESET}"
echo "  ${DIM}Env:     ${CTF_ENV_FILE}${RESET}"
echo "  ${DIM}Shell:   ${ZSHRC}${RESET}"
echo ""
echo -n "${YELLOW}  Continue? [y/N]:${RESET} "
read confirm
if [[ "$confirm" != [yY] ]]; then
  echo ""
  echo "${DIM}  Aborted. Nothing changed.${RESET}"
  echo ""
  exit 0
fi

# --- Run all steps ------------------------------------------------------------
run_dependency_check
run_backup
run_deploy_env
run_patch_zshrc
run_build_directories
run_symlinks
run_sync

# --- Done ---------------------------------------------------------------------
echo ""
echo "${BOLD}${GREEN}=== Installation Complete ===${RESET}"
echo ""
echo "  ${CYAN}Reload your shell:${RESET}"
echo "  ${BOLD}source ~/.zshrc${RESET}"
echo ""
echo "  ${CYAN}Start a CTF session:${RESET}"
echo "  ${BOLD}set-platform HTB${RESET}"
echo "  ${BOLD}set-box      <boxname>${RESET}"
echo "  ${BOLD}set-target   <ip>${RESET}"
echo "  ${BOLD}ctf-status${RESET}"
echo ""
echo "  ${CYAN}Available commands:${RESET}"
echo "  ${BOLD}ctf-install${RESET}   Re-run this installer"
echo "  ${BOLD}ctf-sync${RESET}      Pull latest repo changes"
echo "  ${BOLD}ctf-install --check${RESET}   Dependency check only"
echo ""
echo "  ${DIM}Backups stored in: ${BACKUP_DIR}${RESET}"
echo ""
