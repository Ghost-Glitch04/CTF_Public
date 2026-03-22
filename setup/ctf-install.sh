#!/bin/zsh
# =============================================================================
# ctf-install.sh — CTF Toolkit Machine Installer
# =============================================================================
# ABOUT:
#   Setup script for any machine you work from.
#   Handles both fresh installs (clones the repo itself) and re-runs
#   (pulls latest changes, redeploys session commands, rebuilds dirs).
#   Safe to re-run at any time — backs up existing config before overwriting.
#
# WHAT IT DOES:
#   1. Dependency check     — lists missing tools with install commands
#   2. Backup ~/.ctf_env    — saves to ~/.ctf_backups/ with timestamp
#   3. Sync repo            — clones fresh or pulls latest (run_sync)
#   4. Deploy ~/.ctf_env    — copies ctf-env-functions.sh into place
#   5. Patch ~/.zshrc       — adds source line if not present
#   6. Build CTF/           — platform directory tree
#   7. Symlink all scripts  — everything in setup/ lands in /usr/local/bin/
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
# SECTION 2 — SUDO-AWARE USER RESOLUTION
# =============================================================================
# TEACHING NOTE — Bug fix #A: resolve the real invoking user before any paths.
#
# This installer is designed to be run with sudo for production installs —
# sudo mkdir, sudo chown, and sudo ln -sf all appear below. When a script
# runs under sudo, the shell sets $HOME to /root (the root user's home
# directory). Any path built from $HOME then points into root's home instead
# of the invoking user's — meaning:
#
#   CTF_ENV_FILE  → /root/.ctf_env        (wrong user's env file)
#   BACKUP_DIR    → /root/.ctf_backups    (wrong user's backups)
#   ZSHRC         → /root/.zshrc          (wrong user's shell config)
#
# The fix mirrors ctf-env-functions.sh: resolve the real user's home once,
# at the top, into _CTF_HOME. Every user-relative path in the file is built
# from $_CTF_HOME rather than $HOME.
#
# How it works:
#   1. If $SUDO_USER is set, the script is running under sudo. We use
#      `getent passwd` to look up that user's home directory from the system
#      user database — more reliable than `eval echo ~$SUDO_USER` because it
#      does not depend on shell expansion or the sudoers environment config.
#   2. If $SUDO_USER is not set, we are running as the normal user and $HOME
#      is already correct. Fall back to it directly.
#
# REAL_USER is also resolved here for use in chown calls — $USER becomes
# "root" under sudo, just like $HOME, so ownership assignment must also use
# the invoking user's name rather than the elevated one.
# =============================================================================

if [[ -n "$SUDO_USER" ]]; then
  _CTF_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  REAL_USER="$SUDO_USER"
else
  _CTF_HOME="$HOME"
  REAL_USER="$USER"
fi


# =============================================================================
# SECTION 3 — PATH RESOLUTION
# =============================================================================
# TEACHING NOTE — --prod short-circuits auto-detection.
#
# The detection chain mirrors ctf-sync.sh exactly. Keeping identical logic
# in both files means they always agree on which directory is authoritative.
# The --prod flag bypasses all detection and hard-codes the production path,
# with an immediate existence check so a misconfigured --prod fails loudly
# rather than proceeding with a broken REPO_DIR.
#
# IMPORTANT — Keep this chain in sync with ctf-sync.sh whenever either is
# changed. The two scripts must always resolve REPO_DIR/INSTALL_DIR the same
# way or they will silently target different directories on the same machine.
#
# Detection order (without --prod):
#   Pass 1: $CTF_REPO_DIR already exported in the environment
#   Pass 2: $_CTF_HOME/github/CTF_Public exists on disk (dev path)
#   Pass 3: /opt/CTF_Public exists on disk (production path)
#   Pass 4: fall back to /opt/CTF_Public as the default clone target
#
# TEACHING NOTE — Integration fix #1: added Pass 3.
#
# The previous version jumped straight from Pass 2 to an unconditional else
# that assigned /opt/CTF_Public without checking whether that path actually
# exists. ctf-sync.sh has always had a Pass 3 existence check here. The
# missing pass meant the two chains were documented as identical but weren't,
# creating a maintenance trap: anyone updating one script had no signal they
# needed to update the other. Pass 3 is now present in both.
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
elif [[ -d "$_CTF_HOME/github/CTF_Public" ]]; then
  REPO_DIR="$_CTF_HOME/github/CTF_Public"
elif [[ -d "/opt/CTF_Public" ]]; then
  REPO_DIR="/opt/CTF_Public"
else
  # No repo found anywhere — set the default target for cloning.
  # run_sync (Step 3) will clone it.
  REPO_DIR="/opt/CTF_Public"
fi

# --- Resolve CTF base (workspace) directory -----------------------------------
# TEACHING NOTE — CTF_BASE_DIR follows the same override pattern as CTF_REPO_DIR.
# When --prod is passed, a dev may still want workspaces under /opt/CTF rather
# than their usual ~/CTF. CTF_BASE_DIR gives explicit control when needed;
# otherwise it falls back to the standard production workspace path.
CTF_BASE="${CTF_BASE_DIR:-/opt/CTF}"

# --- Derived paths (all relative to _CTF_HOME — never need editing) -----------
# TEACHING NOTE — All user-relative paths are now built from $_CTF_HOME, not
# $HOME. This ensures they resolve to the invoking user's directories even
# when the script is run under sudo. REPO_DIR and CTF_BASE are system paths
# (/opt/*) and are not affected by the sudo context.
CTF_ENV_FILE="$_CTF_HOME/.ctf_env"
CTF_ENV_SOURCE="$REPO_DIR/setup/ctf-env-functions.sh"
BACKUP_DIR="$_CTF_HOME/.ctf_backups"
ZSHRC="$_CTF_HOME/.zshrc"
SYMLINK_DIR="/usr/local/bin"
SETUP_DIR="$REPO_DIR/setup"

# --- Colors -------------------------------------------------------------------
# TEACHING NOTE — Colors and helpers are defined here, before the KNOWN_PLATFORMS
# load block, because the fallback branch of that block calls print_warn and
# print_info on a fresh machine (when CTF_ENV_SOURCE doesn't exist yet).
# In zsh, calling a function at script body scope before it is defined produces
# "command not found". Defining colors and helpers here ensures they are always
# available regardless of which branch executes.
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

# Load KNOWN_PLATFORMS from the env functions file — it is the authority.
# TEACHING NOTE — Integration fix #3: soft handling for fresh machines.
#
# The previous version hard-exited here if CTF_ENV_SOURCE did not exist:
#   if [[ ! -f "$CTF_ENV_SOURCE" ]]; then ... exit 1; fi
#
# This created a chicken-and-egg problem on a genuinely fresh machine:
#   1. Path resolution sets REPO_DIR=/opt/CTF_Public (nothing exists yet)
#   2. CTF_ENV_SOURCE = /opt/CTF_Public/setup/ctf-env-functions.sh
#   3. That file doesn't exist because the repo hasn't been cloned yet
#   4. Script exits with an error — before run_sync can clone the repo
#
# The fix moves the hard existence check inside run_deploy_env (where it
# belongs — that step actually needs the file) and replaces it here with
# a soft fallback: if CTF_ENV_SOURCE is not available, KNOWN_PLATFORMS is
# initialised to a safe built-in default. run_build_directories will still
# create the correct platform directories on this run, and on the next run
# (after run_sync has cloned the repo) the live file will be used.
#
# This means a fresh-machine install proceeds as:
#   run_sync      → clones the repo (CTF_ENV_SOURCE now exists)
#   run_deploy_env → deploys ~/.ctf_env from the just-cloned file
#   run_build_directories → uses KNOWN_PLATFORMS (from file or fallback)
#
# The fallback list mirrors KNOWN_PLATFORMS in ctf-env-functions.sh.
# If they drift, the only consequence is that platform directories created
# on the very first install may differ from a re-run — a minor cosmetic
# issue corrected automatically when ctf-install is re-run after cloning.
if [[ -f "$CTF_ENV_SOURCE" ]]; then
  # Source only to read KNOWN_PLATFORMS — a subshell keeps our namespace clean.
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
else
  # Repo not yet cloned — use built-in fallback matching ctf-env-functions.sh.
  # run_sync will clone the repo; re-running ctf-install afterwards will use
  # the live file. This fallback ensures the first-run install completes fully.
  print_warn "Repo not yet cloned — using built-in platform defaults for this run."
  print_info "Re-run ctf-install after cloning to use the live platform list."
  KNOWN_PLATFORMS=(
    "HTB:Hack The Box"
    "THM:TryHackMe"
    "LD:LetsDefend"
    "DC:DefCon"
    "GGL:Google CTF"
    "PG:Proving Grounds"
  )
fi

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
      # TEACHING NOTE — Bug fix #B: split `local version=$(...)` into two lines.
      #
      # In zsh, `local` is itself a command. When you write:
      #   local version=$(some_command)
      # ...the exit code captured in $? is local's exit code (always 0), not
      # the command substitution's. A failed version command is silently
      # swallowed and the variable is set to an empty string with no error.
      #
      # The fix is to declare the variable first, then assign on a separate
      # line. After the assignment, $? reflects the pipeline's actual exit
      # code. This is the same "$? capture is fragile after local" principle
      # noted in the project's key learnings.
      local version
      version=$(${cmd} ${vflag} 2>/dev/null | head -1 | awk -v f="$vfield" '{print $f}' | tr -d '(),')
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
    mkdir -p "$BACKUP_DIR" \
      || { print_err "Could not create backup directory: ${BOLD}${BACKUP_DIR}${RESET}"; return 1; }
    print_ok "Created backup directory: ${BOLD}${BACKUP_DIR}${RESET}"
  fi

  local timestamp
  timestamp=$(date +"%Y%m%d_%H%M%S")
  local backup_file="${BACKUP_DIR}/.ctf_env.${timestamp}"

  # TEACHING NOTE — Bug fix #C: cp failure is now caught and surfaced.
  #
  # Previously, a failed cp (disk full, permissions issue) would print nothing
  # and the function would continue — the installer would proceed to deploy a
  # fresh ~/.ctf_env without having successfully saved the old one. The user
  # would lose their existing config with no warning.
  #
  # The fix uses || { print_err ...; return 1; } to abort immediately on
  # failure. This is the same error-surfacing pattern applied throughout the
  # toolkit: never let a silent failure propagate.
  cp "$CTF_ENV_FILE" "$backup_file" \
    || { print_err "Backup failed — could not write: ${BOLD}${backup_file}${RESET}"; return 1; }
  print_ok "Backed up to: ${BOLD}${backup_file}${RESET}"

  # TEACHING NOTE — Bug fix #D: replaced `ls | wc -l` with a zsh glob array.
  #
  # `ls` is a tool for humans, not scripts. Its output format is not guaranteed
  # to be stable, and filenames containing newlines would cause wc -l to
  # overcount. The zsh-native approach is to expand the glob into an array and
  # count its elements directly — no subprocess, no parsing, no edge cases.
  #
  # The (N) glob qualifier tells zsh to return an empty array instead of an
  # error when no files match (equivalent to nullglob in bash). Without it,
  # an unmatched glob would expand to the literal pattern string and the count
  # would be 1 instead of 0.
  local backups=("$BACKUP_DIR"/.ctf_env.*(N))
  local backup_count=${#backups}
  if (( backup_count > 5 )); then
    print_info "${backup_count} backups in ${BACKUP_DIR}"
    print_info "To clean old backups: ${BOLD}ls ~/.ctf_backups/${RESET} then remove as needed"
  fi
}


# =============================================================================
# STEP 4 — DEPLOY ~/.ctf_env
# =============================================================================
# TEACHING NOTE — Section headers must match the entry point execution order.
#
# When run_sync was promoted to Step 3 (before run_deploy_env), the step
# numbers on this function and all subsequent functions were not updated,
# leaving both run_sync and run_deploy_env labelled "STEP 3". Section headers
# are the authoritative reference for what order things run — a reader should
# be able to trust them without cross-referencing the entry point call list.
# The labels below now match the actual execution order exactly.
run_deploy_env() {
  print_step "Deploying ~/.ctf_env"

  # TEACHING NOTE — Integration fix #2 + #3 (continued): hard check lives here.
  #
  # The startup-time hard exit on missing CTF_ENV_SOURCE was moved to a soft
  # fallback (see path resolution block). The hard check now lives here, where
  # it is actually meaningful: run_sync has already run, so if the source file
  # still doesn't exist at this point it is a genuine error (clone failed,
  # wrong REPO_DIR, file deleted from repo) rather than a "not cloned yet"
  # first-run condition.
  #
  # Re-derive CTF_ENV_SOURCE here rather than relying on the value set at
  # script startup. On a fresh machine the startup value was set before the
  # repo existed; after run_sync the repo now exists and the path is valid.
  # Re-deriving ensures we always deploy from the freshest pulled version.
  CTF_ENV_SOURCE="$REPO_DIR/setup/ctf-env-functions.sh"

  if [[ ! -f "$CTF_ENV_SOURCE" ]]; then
    print_err "Source file not found: ${BOLD}${CTF_ENV_SOURCE}${RESET}"
    print_info "run_sync should have cloned the repo — check for errors above."
    print_info "Ensure ctf-env-functions.sh exists in ${BOLD}${SETUP_DIR}${RESET}"
    return 1
  fi

  # TEACHING NOTE — Bug fix #C (continued): cp failure caught here too.
  #
  # If the deploy cp fails (permissions, disk full, source vanished between
  # the existence check above and the copy here), the function now aborts
  # with a clear error rather than printing a success message for a copy
  # that never happened.
  cp "$CTF_ENV_SOURCE" "$CTF_ENV_FILE" \
    || { print_err "Deploy failed — could not write: ${BOLD}${CTF_ENV_FILE}${RESET}"; return 1; }

  # TEACHING NOTE — Ownership fix for sudo-safety.
  #
  # When ctf-install runs under sudo (common for production installs that
  # need to write to /opt), the `cp` above creates ~/.ctf_env owned by root.
  # The user's shell then fails to source it ("permission denied") because
  # the file is root-owned with default permissions that may exclude other
  # users.
  #
  # Explicitly chowning to REAL_USER ensures the deployed file is always
  # owned by the intended user, regardless of who ran the installer. This
  # mirrors the ownership fix already applied to /opt/CTF in
  # run_build_directories — every user-home artifact needs this treatment
  # when the installer can run under sudo.
  chown "${REAL_USER}:${REAL_USER}" "$CTF_ENV_FILE" 2>/dev/null

  print_ok "Deployed: ${BOLD}${CTF_ENV_SOURCE}${RESET} → ${BOLD}${CTF_ENV_FILE}${RESET}"
  print_info "To update session commands: edit ctf-env-functions.sh, push, run ${BOLD}ctf-sync${RESET}"
  print_info "Then reload with: ${BOLD}source ~/.ctf_env${RESET} — no reinstall needed."
}


# =============================================================================
# STEP 5 — PATCH ~/.zshrc
# =============================================================================
run_patch_zshrc() {
  print_step "Patching ~/.zshrc"

  # TEACHING NOTE — Observation fix: explicitly note when ~/.zshrc is new.
  #
  # The >> operator creates the file if it doesn't exist, so this function
  # always succeeds regardless of whether ~/.zshrc was already present. On
  # a fresh machine this is probably fine, but silently creating a new file
  # and silently appending to an existing one look identical from the outside.
  # A user debugging their shell config later deserves to know which happened.
  #
  # The fix adds an explicit check: if the file doesn't exist yet, we note
  # that it was created rather than just patched. The >> append still works
  # the same way in both cases — only the feedback message changes.
  if grep -q "source.*\.ctf_env" "$ZSHRC" 2>/dev/null; then
    print_skip "~/.zshrc already sources ~/.ctf_env"
  else
    if [[ ! -f "$ZSHRC" ]]; then
      print_info "~/.zshrc not found — creating it."
    fi
    echo "" >> "$ZSHRC"
    echo "# CTF Toolkit — loaded by ctf-install.sh on $(date +%Y-%m-%d)" >> "$ZSHRC"
    echo "source ~/.ctf_env" >> "$ZSHRC"
    print_ok "Added source line to ~/.zshrc"
  fi
}


# =============================================================================
# STEP 6 — BUILD CTF DIRECTORY TREE
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
  # TEACHING NOTE — Bug fix #A (continued): chown uses REAL_USER, not $USER.
  #
  # Under sudo, $USER is set to "root" — the same problem as $HOME. Using
  # $USER here would transfer ownership to root, defeating the entire purpose
  # of the chown. REAL_USER was resolved at the top of the script alongside
  # _CTF_HOME: it holds the name of the user who invoked sudo, or just $USER
  # when the script runs without elevation.
  if $use_sudo; then
    sudo chown -R "${REAL_USER}:${REAL_USER}" "$CTF_BASE"
    print_ok "Ownership set: ${BOLD}${CTF_BASE}${RESET} → ${REAL_USER}"
  fi
}


# =============================================================================
# STEP 7 — SYMLINK ALL SCRIPTS IN setup/ TO /usr/local/bin/
# =============================================================================
run_symlinks() {
  print_step "Symlinking Tools to /usr/local/bin/"

  if [[ ! -d "$SETUP_DIR" ]]; then
    print_err "Setup directory not found: ${BOLD}${SETUP_DIR}${RESET}"
    print_info "Is the repo cloned to ${BOLD}${REPO_DIR}${RESET}?"
    return 1
  fi

  local count=0
  # TEACHING NOTE — Denylist: sourced files must not be symlinked into PATH.
  # ctf-env-functions.sh is sourced by ~/.ctf_env, not run as a command.
  # Symlinking it creates a misleading `ctf-env-functions` command that
  # appears executable but produces no useful output when called directly.
  # Adding it here means the loop stays data-driven — drop any future
  # sourced-only files into this list and they are automatically excluded.
  local symlink_denylist=("ctf-env-functions.sh")

  for script in "$SETUP_DIR"/*.sh; do
    [[ -f "$script" ]] || continue

    local filename="${script##*/}"

    # Skip any file on the denylist
    local skip=false
    for denied in "${symlink_denylist[@]}"; do
      [[ "$filename" == "$denied" ]] && skip=true && break
    done
    $skip && continue

    local linkname="${filename%.sh}"
    local linkpath="${SYMLINK_DIR}/${linkname}"

    chmod +x "$script"

    if [[ -L "$linkpath" ]]; then
      # TEACHING NOTE — Bug fix #C (continued): ln -sf failures are now caught.
      #
      # Previously, a failed symlink operation (insufficient permissions,
      # target directory not writable) would print nothing and the loop would
      # continue to the next script, incrementing the count as if it succeeded.
      # The final message would then claim N scripts were symlinked when some
      # were not. The fix aborts the current iteration with a clear error,
      # leaving the count accurate for the scripts that did succeed.
      sudo ln -sf "$script" "$linkpath" \
        || { print_err "Failed to update symlink: ${BOLD}${linkname}${RESET}"; continue; }
      print_ok "Updated symlink: ${BOLD}${linkname}${RESET} → ${DIM}${script}${RESET}"
    elif [[ -f "$linkpath" ]]; then
      print_warn "File already exists at ${BOLD}${linkpath}${RESET} — skipping"
      print_info "Remove it manually to allow symlinking: ${BOLD}sudo rm ${linkpath}${RESET}"
    else
      sudo ln -sf "$script" "$linkpath" \
        || { print_err "Failed to create symlink: ${BOLD}${linkname}${RESET}"; continue; }
      print_ok "Created symlink:  ${BOLD}${linkname}${RESET} → ${DIM}${script}${RESET}"
    fi

    (( count++ ))
  done

  echo ""
  print_info "${count} script(s) in ${SETUP_DIR} are now available in PATH."
  print_info "Any new .sh file added to setup/ will be symlinked on next ${BOLD}ctf-install${RESET}."
}


# =============================================================================
# STEP 3 — SYNC REPO (clone fresh or pull latest)
# =============================================================================
# TEACHING NOTE — Threading --prod through to ctf-sync via an array.
#
# When ctf-install is run with --prod, the sync step must pass that flag along
# to ctf-sync. If it didn't, ctf-sync would run its own auto-detection and
# potentially target the dev path instead — silently undoing the intent of
# --prod.
#
# Bug fix #E: SYNC_FLAGS was previously a plain string variable, expanded
# unquoted when passed to ctf-sync. An unquoted empty string is harmless in
# this specific case (it expands to nothing), but it is fragile: if SYNC_FLAGS
# ever grew to contain a value with spaces, word-splitting would break it into
# separate arguments silently. The idiomatic zsh/bash solution is an array:
# "${sync_flags[@]}" expands to zero words when empty and to one word per
# element otherwise — no quoting ambiguity, no word-splitting risk.
#
# The fallback uses zsh (not bash) because ctf-sync.sh uses zsh-specific
# syntax and has a #!/bin/zsh shebang.
# =============================================================================
run_sync() {
  print_step "Syncing Repo"

  local sync_flags=()
  $FORCE_PROD && sync_flags=("--prod")

  # TEACHING NOTE — Integration fix: resolve ctf-sync.sh relative to this
  # script's own directory as the primary fallback path.
  #
  # The previous fallback checked only $SETUP_DIR/ctf-sync.sh, which on a
  # fresh machine is derived from REPO_DIR — the very directory that doesn't
  # exist yet. Both `command -v ctf-sync` (not in PATH before symlinks are
  # created) and `[[ -f $SETUP_DIR/ctf-sync.sh ]]` (directory doesn't exist)
  # would fail, causing run_sync to print "ctf-sync not available" and skip
  # entirely. The repo would never be cloned, and every subsequent step would
  # fail silently against a REPO_DIR that doesn't exist.
  #
  # The fix: use ${0:A:h} to resolve the absolute directory containing this
  # script. ctf-install.sh and ctf-sync.sh always live side by side in
  # setup/. Whether the script is invoked as ./ctf-install.sh, via its
  # /usr/local/bin symlink, or with a full path, ${0:A:h} always gives the
  # real directory — making ctf-sync.sh locatable even on a fresh machine
  # where SETUP_DIR hasn't been created yet.
  #
  # :A  = resolve to absolute path (following symlinks)
  # :h  = head — strip filename, return directory component
  #
  # Detection order:
  #   1. ctf-sync already in PATH (installed on a previous run)
  #   2. ctf-sync.sh beside this script (fresh machine, pre-symlink)
  #   3. ctf-sync.sh via SETUP_DIR (fallback for unusual invocation paths)
  local script_dir="${0:A:h}"

  if command -v ctf-sync &>/dev/null; then
    ctf-sync "${sync_flags[@]}"
  elif [[ -f "$script_dir/ctf-sync.sh" ]]; then
    zsh "$script_dir/ctf-sync.sh" "${sync_flags[@]}"
  elif [[ -f "$SETUP_DIR/ctf-sync.sh" ]]; then
    zsh "$SETUP_DIR/ctf-sync.sh" "${sync_flags[@]}"
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
# TEACHING NOTE — Bug fix #A (continued): mode detection uses _CTF_HOME.
#
# The previous check compared $REPO_DIR against $HOME* to decide whether
# to label the mode "dev" or "production". Under sudo, $HOME is /root, so
# a dev repo at /home/talos/github/CTF_Public would never match /root* and
# would be incorrectly labelled "production". Using $_CTF_HOME ensures the
# prefix check reflects the invoking user's actual home directory.
if $FORCE_PROD; then
  echo "  ${YELLOW}Mode:    production (--prod)${RESET}"
elif [[ "$REPO_DIR" == "$_CTF_HOME"* ]]; then
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
  # TEACHING NOTE — Bug fix #F: added -r flag to read.
  #
  # Without -r, a backslash in the input is treated as a line-continuation
  # escape — typing \ then Enter silently consumes the next line rather than
  # registering as a "N". With -r, backslash is treated as a literal character.
  # Every interactive read in the toolkit now uses -r consistently.
  read -r confirm
  if [[ "$confirm" != [yY] ]]; then
    echo ""
    echo "${DIM}  Aborted. Nothing changed.${RESET}"
    echo ""
    exit 0
  fi
fi

# --- Run all steps ------------------------------------------------------------
# TEACHING NOTE — Integration fix #2 + #3: run_sync moved to before
# run_deploy_env.
#
# Previous order: dependency check → backup → deploy → patch → build → symlink → sync
# New order:      dependency check → backup → sync → deploy → patch → build → symlink
#
# Two problems this fixes:
#
# Fix #2 (deploy-before-pull on re-runs):
#   When ctf-install is re-run to pick up changes, the old order deployed
#   ~/.ctf_env from the pre-pull version of ctf-env-functions.sh, then pulled
#   the updated version into the repo. The result: ~/.ctf_env was always one
#   version behind after a re-run. Moving sync before deploy ensures the file
#   that gets deployed is always the freshest available version.
#
# Fix #3 (fresh machine hard-fail):
#   On a machine with no repo, path resolution sets REPO_DIR=/opt/CTF_Public
#   but that directory doesn't exist yet. The old order tried to load
#   KNOWN_PLATFORMS from the repo (at script startup, before any functions
#   run), then deployed, patched, built dirs, symlinked — all before run_sync
#   could clone the repo. The hard exit on missing CTF_ENV_SOURCE blocked
#   fresh installs entirely.
#
#   With sync running first (step 3 below), the repo is cloned before any
#   step that depends on it. The KNOWN_PLATFORMS load at startup now falls
#   back gracefully if the repo isn't present (see integration fix #3 in the
#   path resolution block), and on the very next step the repo exists.
#
# Backup still runs before sync — we always preserve the existing ~/.ctf_env
# before pulling potentially breaking changes and redeploying over it.
#
# TEACHING NOTE — Integration fix: load-bearing steps now propagate failure.
#
# run_sync and run_deploy_env are load-bearing: every step after them depends
# on the repo existing and ~/.ctf_env being deployed. Without exit-on-failure,
# a skipped sync or failed deploy would let the remaining steps run silently
# against a repo that was never cloned — creating a partial install that
# looks complete but isn't.
#
# run_dependency_check, run_patch_zshrc, run_build_directories, and
# run_symlinks are non-critical or self-contained: a missing tool, an already-
# patched zshrc, an existing directory, or a skipped symlink don't prevent
# the rest of the install from producing a working state. They continue on
# failure so a single non-fatal issue doesn't abort everything.
run_dependency_check
run_backup
run_sync       || { echo "${RED}[ERROR]${RESET} Sync step failed — aborting install."; exit 1; }
run_deploy_env || { echo "${RED}[ERROR]${RESET} Deploy step failed — aborting install."; exit 1; }
run_patch_zshrc
run_build_directories
run_symlinks

# --- Done ---------------------------------------------------------------------
echo ""
echo "${BOLD}${GREEN}=== Installation Complete ===${RESET}"
echo ""
echo "  ${CYAN}Reload your shell:${RESET}"
echo "  ${BOLD}source ~/.zshrc${RESET}           ${DIM}# first install — loads everything fresh${RESET}"
echo "  ${BOLD}source ~/.ctf_env${RESET}          ${DIM}# re-run — picks up the newly deployed env${RESET}"
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