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
#   1. Dependency check     — lists missing tools with install commands
#   2. Backup ~/.ctf_env    — saves to ~/.ctf_backups/ with timestamp
#   3. Deploy ~/.ctf_env    — copies ctf-env-functions.sh into place
#   4. Patch ~/.zshrc       — adds source line if not present
#   5. Build /opt/CTF/      — platform directory tree
#   6. Symlink all scripts  — everything in setup/ lands in /usr/local/bin/
#   7. Run ctf-sync         — ensures repo is current
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
#   Edit KNOWN_PLATFORMS in ctf-env-functions.sh — that file is the authority.
#   Re-run ctf-install after pushing changes to rebuild the directory tree.
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================

# =============================================================================
# TEACHING NOTE — The installer's job has changed
# =============================================================================
# The old version of this file contained all CTF session functions (set-box,
# set-platform, ctf-status, etc.) written inline as a heredoc. That meant:
#   - Editing a session command required editing the installer
#   - Re-running the installer was the only way to deploy a function change
#   - KNOWN_PLATFORMS was duplicated between the installer and the env file
#
# The refactored version separates concerns cleanly:
#   - ctf-install.sh    = machine setup only (runs once)
#   - ctf-env-functions.sh = session commands (sourced every terminal)
#
# Now to update a session command:
#   1. Edit ctf-env-functions.sh
#   2. git push && ctf-sync
#   3. source ~/.ctf_env
#   No reinstall needed.
# =============================================================================


# =============================================================================
# SECTION 1 — CONFIGURATION
# =============================================================================
# TEACHING NOTE — Source the env file FIRST, before anything else.
# This is the key architectural change. By sourcing ctf-env-functions.sh at
# the top, the installer can READ the KNOWN_PLATFORMS array that lives there.
# That array is now the single source of truth — no more duplicate lists.
#
# We check that the file exists before sourcing it. If the repo wasn't cloned
# yet (truly first run, bootstrap scenario), we print a clear error and exit
# rather than proceeding with broken state. Fail loudly and early.
# =============================================================================

REPO_DIR="/opt/CTF_Public"
CTF_BASE="/opt/CTF"
CTF_ENV_FILE="$HOME/.ctf_env"
CTF_ENV_SOURCE="$REPO_DIR/setup/ctf-env-functions.sh"
BACKUP_DIR="$HOME/.ctf_backups"
ZSHRC="$HOME/.zshrc"
SYMLINK_DIR="/usr/local/bin"
SETUP_DIR="$REPO_DIR/setup"

# Load KNOWN_PLATFORMS from the env functions file — it is the authority
if [[ ! -f "$CTF_ENV_SOURCE" ]]; then
  echo "\033[0;31m[ERROR]\033[0m ctf-env-functions.sh not found at: $CTF_ENV_SOURCE"
  echo "        Is the repo cloned to $REPO_DIR?"
  echo "        Run: sudo git clone https://github.com/Ghost-Glitch04/CTF_Public $REPO_DIR"
  exit 1
fi

# Source only to read KNOWN_PLATFORMS — a subshell keeps our namespace clean
# TEACHING NOTE — The ( ) creates a subshell. Variables set inside it don't
# leak into the parent script. We only want KNOWN_PLATFORMS; sourcing the full
# file in the main shell would load all the CTF functions into the installer's
# namespace, which is messy. The subshell isolates the import cleanly.
# Read KNOWN_PLATFORMS safely — IFS loop preserves entries that contain spaces
#---
# TEACHING NOTE — Word splitting is a common shell pitfall. When a command
# substitution like $(...) is unquoted, the shell splits output on whitespace.
# "HTB:Hack The Box" would become three elements: "HTB:Hack", "The", "Box".
# Reading line-by-line with a while/read loop preserves each full entry intact,
# regardless of spaces in the platform full name.
# Note: mapfile is bash-only. This script uses zsh, so we use the portable loop.
KNOWN_PLATFORMS=()
while IFS= read -r entry; do
  [[ -n "$entry" ]] && KNOWN_PLATFORMS+=("$entry")
done < <( source "$CTF_ENV_SOURCE" 2>/dev/null; printf '%s\n' "${KNOWN_PLATFORMS[@]}" )

# --- Required tools -----------------------------------------------------------
# FORMAT: "command:display_name:apt_package"
# To add a tool: append a new entry following this exact format
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
# TEACHING NOTE — The installer has its own print helpers (print_ok, print_err)
# that are separate from the CTF session helpers (_ctf_ok, _ctf_err) in the
# env file. They're intentionally different: the installer runs as a script,
# the session functions run in an interactive shell. Keeping them separate
# avoids the installer accidentally calling functions that haven't been loaded
# yet, and keeps each file's namespace clean and self-contained.
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
  echo "  Edit KNOWN_PLATFORMS in ctf-env-functions.sh — that is the authority."
  echo "  Re-run ctf-install to rebuild the /opt/CTF/ directory tree."
  echo ""
  echo "${CYAN}BACKUP LOCATION:${RESET}"
  echo "  $BACKUP_DIR"
  echo ""
}


# =============================================================================
# STEP 1 — DEPENDENCY CHECK
# =============================================================================
# TEACHING NOTE — Nothing about this step changes from the original.
# It's already doing one job cleanly: checking for required tools and
# reporting what's missing. It doesn't write files, modify state, or depend
# on KNOWN_PLATFORMS. Good code doesn't need to change just because
# other parts of the system were refactored.
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

  if [[ "$1" == "--check-only" ]]; then
    echo ""
    exit 0
  fi
}


# =============================================================================
# STEP 2 — BACKUP ~/.ctf_env
# =============================================================================
# TEACHING NOTE — Also unchanged. It does one thing: back up a file.
# It doesn't care what's in ~/.ctf_env, who wrote it, or what replaces it.
# That independence is why it needs no changes — isolation pays off here.
# =============================================================================
run_backup() {
  print_step "Backing Up ~/.ctf_env"

  if [[ ! -f "$CTF_ENV_FILE" ]]; then
    print_skip "No existing ~/.ctf_env found — nothing to back up."
    return 0
  fi

  if [[ ! -d "$BACKUP_DIR" ]]; then
    mkdir -p "$BACKUP_DIR"
    print_ok "Created backup directory: ${BOLD}${BACKUP_DIR}${RESET}"
  fi

  local timestamp
  timestamp=$(date +"%Y%m%d_%H%M%S")
  local backup_file="${BACKUP_DIR}/.ctf_env.${timestamp}"

  cp "$CTF_ENV_FILE" "$backup_file"
  print_ok "Backed up to: ${BOLD}${backup_file}${RESET}"

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
# TEACHING NOTE — This is the biggest change in the refactor.
# The old version wrote ~300 lines of session functions into ~/.ctf_env using
# a heredoc. That had two problems:
#
#   1. The installer owned the content of session functions — changing
#      set-box() meant editing ctf-install.sh and re-running it.
#
#   2. The heredoc required escaped dollar signs (\$var) and was difficult
#      to read, test, or reason about in isolation.
#
# The new version does one thing: copy ctf-env-functions.sh to ~/.ctf_env.
# That file is a proper, readable zsh script that you can open, test, and
# edit independently. The installer just deploys it.
#
# `cp` vs symlink: we copy rather than symlink because ~/.ctf_env is sourced
# by every terminal session. A symlink would mean the repo must always be
# present and mounted — a copy works even if the repo is temporarily missing.
# =============================================================================
run_deploy_env() {
  print_step "Deploying ~/.ctf_env"

  if [[ ! -f "$CTF_ENV_SOURCE" ]]; then
    print_err "Source file not found: ${BOLD}${CTF_ENV_SOURCE}${RESET}"
    print_info "Ensure ctf-env-functions.sh exists in ${BOLD}${SETUP_DIR}${RESET}"
    return 1
  fi

  cp "$CTF_ENV_SOURCE" "$CTF_ENV_FILE"
  print_ok "Deployed: ${BOLD}${CTF_ENV_SOURCE}${RESET} → ${BOLD}${CTF_ENV_FILE}${RESET}"
  print_info "To update session commands: edit ctf-env-functions.sh, push, run ${BOLD}ctf-sync${RESET}"
  print_info "Then reload with: ${BOLD}source ~/.ctf_env${RESET} — no reinstall needed."
}


# =============================================================================
# STEP 4 — PATCH ~/.zshrc
# =============================================================================
# TEACHING NOTE — Also unchanged. The source line it writes still works
# because ~/.ctf_env still exists at the same path — we just changed what's
# in it. The interface (the path) stayed the same; only the implementation
# (how the file gets its content) changed. Good design insulates callers
# from implementation details.
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
# TEACHING NOTE — This step looks the same but is now driven by a different
# source of truth. Previously, it looped over a KNOWN_PLATFORMS array defined
# right here in ctf-install.sh. Now it loops over the KNOWN_PLATFORMS array
# that was loaded at the top of this script from ctf-env-functions.sh.
#
# The loop body is identical. Only the data source changed — and that's
# exactly what we want. The installer no longer needs to be edited when you
# add a platform. You add it to ctf-env-functions.sh, and the next time
# ctf-install runs, it picks it up automatically.
#
# This pattern — code that is stable, data that changes — is one of the core
# ideas behind scalable scripting. If you find yourself editing a script just
# to change a list, the list should probably live somewhere else.
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
# TEACHING NOTE — Also unchanged. Auto-discovering *.sh in setup/ means you
# never need to edit this function when you add a new script. Drop it in the
# folder, run ctf-install, and it appears in PATH. The data (script files)
# drives the behavior (symlinks created) without code changes.
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

    local filename="${script##*/}"
    local linkname="${filename%.sh}"
    local linkpath="${SYMLINK_DIR}/${linkname}"

    chmod +x "$script"

    if [[ -L "$linkpath" ]]; then
      sudo ln -sf "$script" "$linkpath"
      print_ok "Updated symlink: ${BOLD}${linkname}${RESET} → ${DIM}${script}${RESET}"
    elif [[ -f "$linkpath" ]]; then
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
# TEACHING NOTE — Two small fixes here from the original:
#
#   1. The fallback filename is corrected from smart-sync.sh to ctf-sync.sh,
#      matching the renamed file in your repo.
#
#   2. The ordering note: ctf-sync runs AFTER symlinks are created (Step 6),
#      so by the time we reach this step, ctf-sync is already in PATH from
#      the symlink we just made. The `command -v ctf-sync` check will succeed
#      on a re-run (symlink already existed) but also now succeeds on a first
#      run if Step 6 completed cleanly. The fallback path handles the edge
#      case where Step 6 failed or the symlink wasn't created for some reason.
# =============================================================================
run_sync() {
  print_step "Syncing Repo"

  if command -v ctf-sync &>/dev/null; then
    ctf-sync
  elif [[ -f "$SETUP_DIR/ctf-sync.sh" ]]; then
    bash "$SETUP_DIR/ctf-sync.sh"
  else
    print_warn "ctf-sync not available — skipping."
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
# TEACHING NOTE — The completion summary is the user's first look at what
# the toolkit can do. Update it any time you add a new command. It references
# the new command names (set-address instead of set-target) because it should
# always reflect the current state of ctf-env-functions.sh.
# =============================================================================
echo ""
echo "${BOLD}${GREEN}=== Installation Complete ===${RESET}"
echo ""
echo "  ${CYAN}Reload your shell:${RESET}"
echo "  ${BOLD}source ~/.zshrc${RESET}"
echo ""
echo "  ${CYAN}Start a CTF session:${RESET}"
echo "  ${BOLD}set-platform <platform>${RESET}"
echo "  ${BOLD}set-box      <boxname>${RESET}"
echo "  ${BOLD}set-address  <ip>${RESET}"
echo "  ${BOLD}ctf-status${RESET}"
echo ""
echo "  ${CYAN}Available commands:${RESET}"
echo "  ${BOLD}ctf-install${RESET}              Re-run this installer"
echo "  ${BOLD}ctf-install --check${RESET}      Dependency check only"
echo "  ${BOLD}ctf-sync${RESET}                 Pull latest repo changes"
echo "  ${BOLD}ctf-help${RESET}                 List all session commands"
echo ""
echo "  ${DIM}Backups stored in: ${BACKUP_DIR}${RESET}"
echo ""