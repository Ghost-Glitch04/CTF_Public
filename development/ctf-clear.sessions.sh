#!/bin/zsh
# =============================================================================
# ctf-clear-session.sh — CTF Session Variable Cleaner
# =============================================================================
# ABOUT:
#   Clears exported CTF session variables (PLATFORM, BOXNAME, ADDRESS,
#   BOX_DIR) from your interactive shell. Safe to run at any time — it
#   only touches those four variables and leaves everything else alone.
#
# USAGE:
#   ~/github/CTF_Public/development/ctf-clear-session.sh
#
#   After running, execute:
#   exec zsh
#
#   The variables will be cleared automatically as part of shell startup.
#
# WHY THIS SCRIPT EXISTS — THE CORE PROBLEM:
#   Shell variables set with `export` are in-memory state of your interactive
#   shell process. When you run any script (even with sudo), the OS gives that
#   script its own *copy* of the environment. Changes made inside the script —
#   including `unset` — only affect that copy. When the script exits, the copy
#   is discarded. Your interactive shell never sees any of it.
#
#   This is a hard Unix rule: child processes cannot modify the environment
#   of their parent. There is no exception, no workaround, no signal that
#   bypasses it cleanly.
#
# THE SOLUTION — ONE-SHOT CLEANUP FILE:
#   Instead of trying to act from inside the script (which can't work), this
#   script schedules work to happen later, in the right place, at the right
#   time. Specifically:
#
#     1. Write a small cleanup file (~/.ctf_cleanup.zsh) that contains
#        the `unset` command and instructions to delete itself afterward.
#
#     2. Register that file with ~/.zshrc by appending a `source` line.
#
#     3. When you run `exec zsh`, the new shell reads ~/.zshrc and sources
#        the cleanup file — running `unset` *inside* the interactive shell
#        that actually owns the variables.
#
#     4. The cleanup file removes its own source line from ~/.zshrc and
#        deletes itself. It fires exactly once and leaves no trace.
#
#   The key insight: the problem was never *what* command to run — `unset`
#   was always correct. The problem was *where* to run it. The one-shot file
#   pattern defers execution to the moment when the command runs natively
#   inside the interactive shell itself.
#
# REPO: https://github.com/Ghost-Glitch04/CTF_Public
# =============================================================================


# =============================================================================
# SECTION 1 — RESOLVE USER CONTEXT
# =============================================================================
# TEACHING NOTE — Always resolve the real user when a script might run as root.
#
# If this script is run with `sudo`, $HOME resolves to /root and $USER is root.
# That would write the cleanup file to the wrong home directory. We use
# $SUDO_USER (set automatically by sudo to the original invoking user) to
# find the real user, then look up their home directory from /etc/passwd via
# `getent` — the most reliable way to resolve a home path regardless of how
# the shell was invoked.
#
# If the script is run without sudo, $SUDO_USER is empty, so we fall back to
# $USER and $HOME — the normal values. This makes the script correct in both
# cases without any extra flags or arguments.
# =============================================================================

TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
TARGET_HOME="${TARGET_HOME:-$HOME}"   # fallback if getent unavailable


# =============================================================================
# SECTION 2 — COLORS
# =============================================================================
# TEACHING NOTE — Define colors once at the top, use them everywhere.
# If you ever want to change how output looks, you change one line here
# rather than hunting through every echo statement in the file.
# =============================================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'


# =============================================================================
# SECTION 3 — REGISTER THE ONE-SHOT CLEANUP FILE
# =============================================================================
# TEACHING NOTE — Why a heredoc with single-quoted delimiter ('CLEANUP').
#
# The heredoc writes the cleanup script verbatim — no variable expansion,
# no command substitution. The single-quoted 'CLEANUP' delimiter is what
# prevents expansion. This is critical: we want the cleanup file to contain
# the literal text `$HOME` so it expands correctly *when the cleanup file
# runs* (inside the user's shell), not right now while we're writing it.
#
# If we used an unquoted CLEANUP delimiter, $HOME would expand to /root
# (because this script may run as root under sudo), and the cleanup file
# would contain hardcoded paths like /root/.zshrc instead of $HOME/.zshrc.
# The user's actual .zshrc would never be touched.
#
# Rule of thumb: use 'QUOTED' heredoc delimiters when writing scripts that
# contain variables meant to expand later — not now.
# =============================================================================

CLEANUP_FILE="$TARGET_HOME/.ctf_cleanup.zsh"
ZSHRC_FILE="$TARGET_HOME/.zshrc"

echo ""
echo "${BOLD}${CYAN}── CTF Session Variable Cleaner ──${RESET}"
echo ""

# Guard: check if a cleanup is already pending from a previous run
# TEACHING NOTE — Idempotency means "safe to run multiple times".
# If the cleanup file already exists, registering it again would add a
# second source line to ~/.zshrc. Running exec zsh would then try to
# source a file that already deleted itself — causing a "no such file"
# error. We check first and skip registration if it's already in place.
if [[ -f "$CLEANUP_FILE" ]]; then
  echo "  ${YELLOW}[NOTE]${RESET}  Cleanup already registered and waiting."
  echo "  ${DIM}Run ${RESET}${BOLD}exec zsh${RESET}${DIM} to clear the variables now.${RESET}"
  echo ""
  exit 0
fi

# Write the one-shot cleanup script
# TEACHING NOTE — This file does three things in sequence:
#   1. unset — removes the four variables from the interactive shell's
#              environment directly. Works because this file is sourced
#              *inside* the interactive shell, not run as a child process.
#   2. sed   — removes its own source line from ~/.zshrc so the file
#              isn't sourced again on the next shell open.
#   3. rm    — deletes itself. After this line, ~/.ctf_cleanup.zsh is gone.
#
# The net result: the cleanup fires exactly once, clears the variables,
# and leaves no trace in ~/.zshrc or on the filesystem.
cat > "$CLEANUP_FILE" << 'CLEANUP'
# CTF one-shot session cleanup
# Auto-generated by ctf-clear-session.sh — runs once, then removes itself.
#
# TEACHING NOTE — This file is sourced by ~/.zshrc on the next shell open.
# Sourcing means the commands run inside the calling shell (exec zsh) rather
# than in a child process. That's what makes `unset` reach the live variables.
unset ADDRESS PLATFORM BOXNAME BOX_DIR
sed -i '/source.*ctf_cleanup/d' "$HOME/.zshrc"
rm -f "$HOME/.ctf_cleanup.zsh"
CLEANUP

# Fix ownership — this script may have run as root under sudo, which means
# the cleanup file was created owned by root. The user's shell can't source
# a root-owned file unless it's world-readable. chown + chmod 644 ensures
# it's both owned by the right user and readable.
# TEACHING NOTE — Always think about who will read a file you create.
# A script that creates files should leave them owned by the person who
# will use them — not by whoever happened to be running the script.
chown "${TARGET_USER}:${TARGET_USER}" "$CLEANUP_FILE"
chmod 644 "$CLEANUP_FILE"

# Register with ~/.zshrc
# TEACHING NOTE — We append rather than insert. Appending is safe and
# predictable — it doesn't shift existing line numbers or interact with
# other config blocks. The source line goes at the end, runs last on
# shell open, and removes itself immediately after firing.
echo "" >> "$ZSHRC_FILE"
echo "# CTF session cleanup — added by ctf-clear-session.sh, runs once" >> "$ZSHRC_FILE"
echo "source ~/.ctf_cleanup.zsh" >> "$ZSHRC_FILE"

echo "  ${GREEN}[OK]${RESET}    Cleanup registered for: ${BOLD}${TARGET_USER}${RESET}"
echo "  ${DIM}Variables queued for removal: ADDRESS PLATFORM BOXNAME BOX_DIR${RESET}"
echo ""
echo "  ${CYAN}Run this now to clear them:${RESET}"
echo "  ${BOLD}exec zsh${RESET}"
echo ""
echo "  ${DIM}The cleanup file will run once and delete itself automatically.${RESET}"
echo ""