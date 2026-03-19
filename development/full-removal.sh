#!/bin/zsh
# =============================================================================
# full-removal.sh - Clean reset of all files and directories in the repo.
# Stored for reference, but will need to be ran externally from another file.
# Usage: Removal of files for testing the installation of ctf-install.sh.
# =============================================================================
# ABOUT:
#   This script will have an array to define the files to be removed.
#   It will then loop through the array and remove each file/directory.
#
## =============================================================================
# Define the files/directories to be removed
## =============================================================================

# Declacre an array of file paths to be removed

echo "Building list of files/directories to remove."

ENTITIES_TO_REMOVE=(
    "~/.ctf_env"
    "/opt/CTF"
    "/opt/CTF_Public"
)

echo "Check the value of ENTITIES_TO_REMOVE:"
echo "${ENTITIES_TO_REMOVE[@]}"


