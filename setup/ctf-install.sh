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
#   5. Build CTF/           — platform directory tree
#   6. Symlink all scripts  — everything in setup/ lands in /usr/local/bin/
#   7. Run ctf-sync         — ensures repo is current
#
# USAGE:
#   ./ctf-install.sh              # auto-detect install location
#   ./ctf-install.sh --prod       # force production path (/opt/CTF_Public)
#   ./ctf-install.sh --yes        # skip confirmation prompt (for scripting)
#   ./ctf-install.sh --check      # dependency check only, no changes made
#   ./ctf-install.sh --help       # show help
#
# DEV vs PRODUCTION:
#   Production machines expect the repo at /opt/CTF_Public (default).
#   Dev machines are detected automatically if ~/github/CTF_Public exists,
#   or if CTF_REPO_DIR is already exported before the script runs.
#   CTF_BASE_DIR can similarly override where workspaces are created.
#
#   If BOTH a dev and production install exist on the same machine (e.g. a
#   Kali VM used for both purposes), use --prod to explicitly target the
#   production install. Without it, the dev path always takes priority.
#
# ADDING NEW TOOLS TO CHECK:
#   Find the REQUIRED_TOOLS section below and add entries to the array.
#   Format: "command_name:display_name:apt_package:version_field"
#   Example: "sqlmap:SQLMap:sqlmap:2"
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
#   - ctf-install.sh       = machine setup only (runs once)
#   - ctf-env-functions.sh = session commands (sourced every terminal)
#
# Now to update a session command:
#   1. Edit ctf-env-functions.sh
#   2. git push && ctf-sync
#   3. source ~/.ctf_env
#   No reinstall needed.
# =============================================================================


# =============================================================================
# SECTION 1 — ARGUMENT PARSING
# =============================================================================
# TEACHING NOTE — Parse flags before resolving any paths.
#
# Flags must be read first because FORCE_PROD directly controls which path
# gets resolved. Parsing after resolution would mean the flag arrives too
# late to matter.
#
# --prod and --check are not mutually exclusive — `ctf-install --check --prod`
# runs the dependency check while using production path resolution. In
# practice --check exits early so --prod has no visible effect in that
# combination, but accepting both avoids a confusing error.
#
# Unknown arguments exit with a clear error rather than being silently
# ignored. Silent ignoring of unknown flags is a common source of
# "I thought I passed --prod but it didn't do anything" bugs.
# =============================================================================

FORCE_PROD=false
CHECK_ONLY=false
SHOW_HELP=false
SKIP_CONFIRM=false

for arg in "$@"; do
  case "$arg" in
    --prod)    FORCE_PROD=true ;;
    --check)   CHECK_ONLY=true ;;
    --yes|-y)  SKIP_CONFIRM=true ;;
    --help|-h) SHOW_HELP=true ;;
    *)
      # TEACHING NOTE — Fixed typo in error message. (Bug fix #1)
      #
      # The previous version read:
      #   echo "  Run ${arg} ctf-install --help for usage."
      #
      # The ${arg} variable was left in the wrong position after editing —
      # likely a copy-paste artifact. The result was that running
      # `ctf-install --typo` would print:
      #   "Run --typo ctf-install --help for usage."
      #
      # This is a low-severity bug (the user still sees the unknown arg in
      # the line above), but misleading error messages erode trust in a
      # tool. A good error message tells you exactly what went wrong and
      # exactly what to do next — no extra noise.
      echo "\033[0;31m[ERROR]\033[0m Unknown argument: ${arg}"
      echo "  Run ctf-install --help for usage."
      exit 1
      ;;
  esac
done

# =============================================================================
# SECTION 2 — PATH RESOLUTION
# =============================================================================
# TEACHING NOTE — --prod short-circuits auto-detection.
#
# The detection chain is identical to ctf-sync.sh. Keeping the same logic
# in both files means they always agree on which directory is authoritative.
# The --prod flag bypasses all detection and hard-codes the production path,
# with an immediate existence check so a misconfigured --prod fails loudly
# rather than proceeding with a broken REPO_DIR.
# =============================================================================

if $FORCE_PROD; then
  REPO_DIR="/opt/CTF_Public"
  if [[ ! -d "$REPO_DIR" ]]; then
    echo "\033[0;31m[ERROR]\033[0m --prod specified but no production install found at:"
    echo "         ${REPO_DIR}"
    echo ""
    echo "  To set up a production install, run without --prod first, or clone manually:"
    echo "  sudo git clone https://github.com/Ghost-Glitch04/CTF_Public ${REPO_DIR}"
    exit 1
  fi
elif [[ -n "$CTF_REPO_DIR" ]]; then
  REPO_DIR="$CTF_REPO_DIR"
elif [[ -d "$HOME/github/CTF_Public" ]]; then
  REPO_DIR="$HOME/github/CTF_Public"
else
  REPO_DIR="/opt/CTF_Public"
fi

# --- Resolve CTF base (workspace) directory -----------------------------------
# TEACHING NOTE — CTF_BASE_DIR follows the same override pattern as CTF_REPO_DIR.
# When --prod is passed, a dev may still want workspaces under /opt/CTF rather
# than their usual ~/CTF. CTF_BASE_DIR gives explicit control when needed;
# otherwise it falls back to the standard production workspace path.
CTF_BASE="${CTF_BASE_DIR:-/opt/CTF}"

# --- Derived paths (all relative to REPO_DIR — never need editing) ------------
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
  echo "        Run: git clone https://github.com/Ghost-Glitch04/CTF_Public $REPO_DIR"
  exit 1
fi

# Source only to read KNOWN_PLATFORMS — a subshell keeps our namespace clean
# TEACHING NOTE — The ( ) creates a subshell. Variables set inside it don't
# leak into the parent script. We only want KNOWN_PLATFORMS; sourcing the full
# file in the main shell would load all the CTF functions into the installer's
# namespace, which is messy. The subshell isolates the import cleanly.
#
# Word splitting note: reading line-by-line with a while/read loop preserves
# entries that contain spaces (e.g. "HTB:Hack The Box") intact. mapfile is
# bash-only, so we use this portable approach for zsh.
KNOWN_PLATFORMS=()
while IFS= read -r entry; do
  [[ -n "$entry" ]] && KNOWN_PLATFORMS+=("$entry")
done < <( source "$CTF_ENV_SOURCE" 2>/dev/null; printf '%s\n' "${KNOWN_PLATFORMS[@]}" )

# --- Required tools -----------------------------------------------------------
# FORMAT: "command:display_name:apt_package:version_field"
# To add a tool: append a new entry following this exact format.
REQUIRED_TOOLS=(
  "curl:cURL:curl:2"
  "nmap:Nmap:nmap:3"
  "git:Git:git:3"
  "wget:Wget:wget:3"
  "python3:Python3:python3:2"
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
  echo "  ./ctf-install.sh              Run full installation (auto-detect path)"
  echo "  ./ctf-install.sh --prod       Run installation targeting /opt/CTF_Public"
  echo "  ./ctf-install.sh --yes        Skip confirmation prompt (for scripting)"
  echo "  ./ctf-install.sh --check      Dependency check only, no changes made"
  echo "  ./ctf-install.sh --help       Show this message"
  echo ""
  echo "${CYAN}DUAL-INSTALL NOTE:${RESET}"
  echo "  If both ~/github/CTF_Public and /opt/CTF_Public exist, the dev"
  echo "  path is used by default. Pass --prod to explicitly target prod."
  echo ""
  echo "${CYAN}ENVIRONMENT OVERRIDES:${RESET}"
  echo "  CTF_REPO_DIR   Override repo path  (default: /opt/CTF_Public)"
  echo "  CTF_BASE_DIR   Override workspace   (default: /opt/CTF)"
  echo "  Example (dev): export CTF_REPO_DIR=~/github/CTF_Public"
  echo ""
  echo "${CYAN}ACTIVE PATHS:${RESET}"
  echo "  Repo:      $REPO_DIR"
  echo "  Workspace: $CTF_BASE"
  echo ""
  echo "${CYAN}ADDING TOOLS TO CHECK:${RESET}"
  echo "  Edit REQUIRED_TOOLS array in this script."
  echo "  Format: \"command:display_name:apt_package:version_field\""
  echo ""
  echo "${CYAN}ADDING PLATFORMS:${RESET}"
  echo "  Edit KNOWN_PLATFORMS in ctf-env-functions.sh — that is the authority."
  echo "  Re-run ctf-install to rebuild the CTF directory tree."
  echo ""
  echo "${CYAN}BACKUP LOCATION:${RESET}"
  echo "  $BACKUP_DIR"
  echo ""
}

if $SHOW_HELP; then
  show_help
  exit 0
fi


# =============================================================================
# STEP 1 — DEPENDENCY CHECK
# =============================================================================
run_dependency_check() {
  print_step "Dependency Check"

  local missing=()

  for entry in "${REQUIRED_TOOLS[@]}"; do
    local cmd="${entry%%:*}"
    local rest="${entry#*:}"
    local name="${rest%%:*}"
    local rest2="${rest#*:}"
    local pkg="${rest2%%:*}"
    local vfield="${rest2##*:}"

    if command -v "$cmd" &>/dev/null; then
      local vflag="--version"
      [[ "$cmd" == "nmap" ]] && vflag="-V"
      local version=$(${cmd} ${vflag} 2>/dev/null | head -1 | awk -v f="$vfield" '{print $f}' | tr -d '(),')
      print_ok "${name} ${DIM}(${version})${RESET}"
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

  if $CHECK_ONLY; then
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
# STEP 5 — BUILD CTF DIRECTORY TREE
# =============================================================================
# TEACHING NOTE — $use_sudo applied consistently; ownership fixed once at end.
#
# Whether CTF_BASE requires elevated permissions is determined once and stored
# in $use_sudo, then used uniformly throughout the function.
#
# Ownership is set with a single recursive chown AFTER all directories are
# built, rather than chowning each directory individually. This covers three
# cases cleanly:
#   1. Fresh install  — base + all platform subdirs just created by sudo mkdir
#   2. Re-run         — base already exists (chown was previously skipped),
#                       new platforms added since last run
#   3. Partial state  — any mix of existing and new dirs
#
# A per-directory chown inside the loop would miss case 2 entirely: if
# $CTF_BASE already exists, the loop runs but the base itself never gets
# re-chowned. The recursive chown at the end is immune to this because it
# always runs regardless of what was created vs skipped above.
# =============================================================================
run_build_directories() {
  print_step "Building CTF Directory Tree"
  print_info "Workspace root: ${BOLD}${CTF_BASE}${RESET}"

  # TEACHING NOTE — Clear stale session variables before building the workspace.
  #
  # Shell environment variables persist across installs as long as the shell
  # process is alive. If you ran set-box in a previous session and then ran
  # ctf-install without opening a new terminal, PLATFORM/BOXNAME/ADDRESS/BOX_DIR
  # would still be populated from the old session — even though the workspace
  # tree is being rebuilt from scratch. This is invisible and confusing: ctf-status
  # would show a box that was set before the reinstall, giving false confidence
  # that the session is live when it may point at a path that no longer exists.
  #
  # Clearing them here is unconditional and silent — no prompt, no output. The
  # install is a fresh start; session state should reflect that. The user can
  # run set-platform / set-box / set-address again once the install completes.
  #
  # We use `unset` rather than `export VAR=""` because unset removes the
  # variable entirely from the environment. An empty export would still pass
  # an empty string to child processes, which could cause unexpected behavior
  # in scripts that check [[ -n "$PLATFORM" ]] to decide whether a session is
  # active. Unset makes the "not set" state unambiguous.
  unset ADDRESS PLATFORM BOXNAME BOX_DIR

  local use_sudo=false
  [[ "$CTF_BASE" == /opt/* ]] && use_sudo=true

  if [[ ! -d "$CTF_BASE" ]]; then
    if $use_sudo; then
      sudo mkdir -p "$CTF_BASE"
    else
      mkdir -p "$CTF_BASE"
    fi
    print_ok "Created: ${BOLD}${CTF_BASE}${RESET}"
  else
    print_skip "${CTF_BASE} already exists"
  fi

  for entry in "${KNOWN_PLATFORMS[@]}"; do
    local code="${entry%%:*}"
    local name="${entry##*:}"
    local pdir="${CTF_BASE}/${code}"
    if [[ ! -d "$pdir" ]]; then
      if $use_sudo; then
        sudo mkdir -p "$pdir"
      else
        mkdir -p "$pdir"
      fi
      print_ok "Created: ${BOLD}${pdir}${RESET} ${DIM}(${name})${RESET}"
    else
      print_skip "${pdir} already exists"
    fi
  done

  # Fix ownership recursively after all dirs are built.
  # Runs unconditionally so re-runs and partial states are always corrected.
  if $use_sudo; then
    sudo chown -R "$USER":"$USER" "$CTF_BASE"
    print_ok "Ownership set: ${BOLD}${CTF_BASE}${RESET} → ${USER}"
  fi
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
# TEACHING NOTE — Threading --prod through to ctf-sync.
#
# When ctf-install is run with --prod, Step 7 must pass that flag along to
# ctf-sync. If it didn't, ctf-sync would run its own auto-detection and
# potentially target the dev path instead — silently undoing the intent of
# --prod. SYNC_FLAGS is empty when --prod is not set, so the call is
# identical to the previous behaviour in that case.
#
# The fallback uses zsh (not bash) because ctf-sync.sh uses zsh-specific
# syntax and has a #!/bin/zsh shebang.
# =============================================================================
run_sync() {
  print_step "Syncing Repo"

  local SYNC_FLAGS=""
  $FORCE_PROD && SYNC_FLAGS="--prod"

  if command -v ctf-sync &>/dev/null; then
    ctf-sync $SYNC_FLAGS
  elif [[ -f "$SETUP_DIR/ctf-sync.sh" ]]; then
    zsh "$SETUP_DIR/ctf-sync.sh" $SYNC_FLAGS
  else
    print_warn "ctf-sync not available — skipping."
    print_info "It will be available after this install completes."
  fi
}


# =============================================================================
# ENTRY POINT
# =============================================================================
# TEACHING NOTE — Function definition order in zsh scripts. (Note #5)
#
# All the run_* functions (run_dependency_check, run_backup, etc.) are defined
# above this point, and called below it. This ordering is intentional and
# important to understand.
#
# In zsh (and bash), a function must be defined before it is *called*, but not
# before it is *referenced* in another function. This means:
#
#   ✓ run_sync can reference ctf-sync in its body even though ctf-sync is an
#     external command resolved at call time, not at definition time.
#   ✓ All run_* functions can safely call each other because by the time any
#     of them execute (down here at the entry point), all are already defined.
#   ✗ If we put the `run_dependency_check` call ABOVE its function definition,
#     the script would fail with "command not found: run_dependency_check".
#
# The pattern to follow: define all functions first (top of script), call them
# last (bottom of script). This is sometimes called "top-down readability with
# bottom-up execution". The reader sees the high-level flow at the bottom and
# can drill into the details of each function above it.
# =============================================================================

echo ""
echo "${BOLD}${CYAN}=== CTF Toolkit Installer ===${RESET}"
echo ""
echo "  This will configure your machine for CTF work:"
echo "  ${DIM}Repo:    ${REPO_DIR}${RESET}"
echo "  ${DIM}CTF dir: ${CTF_BASE}${RESET}"
echo "  ${DIM}Env:     ${CTF_ENV_FILE}${RESET}"
echo "  ${DIM}Shell:   ${ZSHRC}${RESET}"

# Surface the active mode clearly so the user can confirm the right install
# is targeted before any changes are made.
if $FORCE_PROD; then
  echo "  ${YELLOW}Mode:    production (--prod)${RESET}"
elif [[ "$REPO_DIR" == "$HOME"* ]]; then
  echo "  ${DIM}Mode:    dev (auto-detected)${RESET}"
else
  echo "  ${DIM}Mode:    production (auto-detected)${RESET}"
fi

# TEACHING NOTE — --yes / SKIP_CONFIRM gate.
#
# The confirmation prompt is the only interactive step in the installer.
# Wrapping it in `if ! $SKIP_CONFIRM` means --yes bypasses it entirely
# while leaving every subsequent step (backup, deploy, sync, etc.) unchanged.
#
# This mirrors the identical pattern in full-removal.sh, deliberately.
# Consistent flag names across paired scripts means you can script both
# without needing separate workarounds for each:
#
#   ./ctf-install.sh --yes --prod
#   ./full-removal.sh --yes
#
# SKIP_CONFIRM has no effect on --check (which exits before reaching here)
# and no effect on --dry-run (full-removal.sh only). Every step still runs
# and still prints full output — only the interactive pause is skipped.
if ! $SKIP_CONFIRM; then
  echo ""
  echo -n "${YELLOW}  Continue? [y/N]:${RESET} "
  read confirm
  if [[ "$confirm" != [yY] ]]; then
    echo ""
    echo "${DIM}  Aborted. Nothing changed.${RESET}"
    echo ""
    exit 0
  fi
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
echo "  ${BOLD}set-platform <platform>${RESET}"
echo "  ${BOLD}set-box      <boxname>${RESET}"
echo "  ${BOLD}set-address  <ip>${RESET}"
echo "  ${BOLD}ctf-status${RESET}"
echo ""
echo "  ${CYAN}Available commands:${RESET}"
echo "  ${BOLD}ctf-install${RESET}              Re-run this installer"
echo "  ${BOLD}ctf-install --prod${RESET}       Re-run targeting production install"
echo "  ${BOLD}ctf-install --yes${RESET}        Re-run without confirmation prompt"
echo "  ${BOLD}ctf-install --check${RESET}      Dependency check only"
echo "  ${BOLD}ctf-sync${RESET}                 Pull latest repo changes"
echo "  ${BOLD}ctf-sync --prod${RESET}          Pull latest changes for production"
echo "  ${BOLD}ctf-help${RESET}                 List all session commands"
echo ""
echo "  ${DIM}Repo:    ${REPO_DIR}${RESET}"
echo "  ${DIM}Backups: ${BACKUP_DIR}${RESET}"
echo ""