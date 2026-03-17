# CTF Toolkit

> A personal toolkit for managing Hack The Box, TryHackMe, and other CTF platform sessions from the command line.

---

<!--
README BEST PRACTICE — What a README is for.

A README is the front door of your repository. When someone visits your repo on
GitHub — including future you, six months from now — the README is the first
thing they read. GitHub renders it automatically on the repo's main page as
formatted text, so it doubles as both documentation and a welcome page.

A good README answers four questions in order:
  1. What is this?        (one or two sentences — the "elevator pitch")
  2. How do I install it? (step by step, no assumed knowledge)
  3. How do I use it?     (commands, examples, common workflows)
  4. How does it work?    (structure, architecture, extending it)

Keep it honest and up to date. Outdated documentation is worse than no
documentation — it actively misleads people. Every time you add a command
or change a flag, update this file in the same commit.
-->

## What This Is

This toolkit provides shell commands for managing CTF sessions on Kali Linux. Rather than typing long paths and remembering IP addresses, it gives you short, memorable commands that track your active platform, box name, and target address — and persist that state across terminal windows.

It is designed to run on:
- **Production** — a shared or permanent Kali install at `/opt/CTF_Public`
- **Development** — a personal checkout under `~/github/CTF_Public` for testing changes before pushing

---

## Prerequisites

Before installing, confirm these tools are present on your system. The installer checks for them automatically, but having them ready avoids interruption.

| Tool | Install command |
|------|----------------|
| git | `sudo apt install -y git` |
| curl | `sudo apt install -y curl` |
| wget | `sudo apt install -y wget` |
| nmap | `sudo apt install -y nmap` |
| python3 | `sudo apt install -y python3` |

<!--
README BEST PRACTICE — Prerequisites before installation steps.

Always list what the user needs BEFORE the steps that need it. Nothing is more
frustrating than following installation instructions halfway and then discovering
a missing dependency. A prerequisites table is clear and scannable — readers
can check off what they already have.
-->

---

## Installation

<!--
README BEST PRACTICE — Numbered steps for sequential processes.

Use numbered lists (1. 2. 3.) rather than bullet points for anything where
order matters. Bullets imply the items are independent and interchangeable.
Numbers make clear that step 2 depends on step 1 completing successfully.
-->

### Fresh Production Install

For a new machine that will use the production install path (`/opt/CTF_Public`):

**Step 1 — Clone the repository**

```zsh
sudo git clone https://github.com/Ghost-Glitch04/CTF_Public /opt/CTF_Public
```

**Step 2 — Run the installer**

```zsh
cd /opt/CTF_Public/setup
chmod +x ctf-install.sh
./ctf-install.sh
```

**Step 3 — Reload your shell**

```zsh
source ~/.zshrc
```

That's it. The installer handles everything else: creating workspace directories, symlinking commands to `/usr/local/bin`, and patching `~/.zshrc` so the toolkit loads automatically in every future terminal.

---

### Dev Install (for testing changes)

If you are developing or testing changes to the toolkit itself, clone to your home directory instead:

```zsh
mkdir -p ~/github
git clone https://github.com/Ghost-Glitch04/CTF_Public ~/github/CTF_Public
cd ~/github/CTF_Public/setup
chmod +x ctf-install.sh
./ctf-install.sh
```

The installer automatically detects the `~/github/CTF_Public` path and configures itself as a dev environment. Your terminal prompt will label the session as `dev` so you always know which installation is active.

---

### Dual Install (both prod and dev on the same machine)

If you have both installs on one machine (e.g. a Kali VM used for both purposes), the dev path takes priority by default. Pass `--prod` to any command to explicitly target the production install:

```zsh
ctf-sync --prod      # pull latest into /opt/CTF_Public
ctf-install --prod   # re-run installer targeting /opt/CTF_Public
```

---

## Starting a CTF Session

A typical session follows this order:

```zsh
set-platform HTB          # declare which platform you're working on
set-box    Lame           # name the box — creates a workspace directory
set-address 10.10.10.3    # set the target IP
ctf-status                # confirm everything looks right
```

After `set-box`, a workspace is created at `/opt/CTF/<PLATFORM>/<BOXNAME>/` containing:

```
Lame/
├── scans/
├── exploits/
├── notes/
│   └── notes.md    ← pre-filled with platform, date, and address
├── flags/
└── loot/
```

<!--
README BEST PRACTICE — Show, don't just tell.

Whenever you describe what something does, show an example of it doing it.
The directory tree above is more useful than a paragraph describing the
directory structure. Readers can glance at a tree and immediately understand
the layout — they would have to read and mentally assemble a prose description.

Use code blocks (triple backticks) for anything the user will type or see in
a terminal. GitHub renders these with a monospace font and a copy button.
Specify the language after the opening backticks (zsh, bash, sh) so GitHub
applies syntax highlighting.
-->

---

## Command Reference

<!--
README BEST PRACTICE — A command reference section.

For a toolkit like this, a complete command reference is more useful than
prose descriptions. Use a table for quick scanning, then add expanded
explanations below for anything that has options or nuance.
Readers who just need to check a flag will use the table.
Readers who are learning will read the sections below it.
-->

### Session Setup

| Command | Description |
|---------|-------------|
| `set-platform <code>` | Set the active CTF platform |
| `set-box <name>` | Set the active box and create its workspace |
| `set-address <ip>` | Set the target IP address |

### Session Info

| Command | Description |
|---------|-------------|
| `ctf-status` | Display the current session state |
| `ctf-help` | List all available commands with descriptions |

### Session Control

| Command | Description |
|---------|-------------|
| `ctf-clear` | Clear all session variables (prompts for confirmation) |

### Maintenance

| Command | Description |
|---------|-------------|
| `ctf-install` | Re-run the machine installer |
| `ctf-install --prod` | Re-run installer targeting the production install |
| `ctf-install --check` | Dependency check only — no changes made |
| `ctf-install --help` | Show installer help |
| `ctf-sync` | Pull latest repo changes from GitHub |
| `ctf-sync --prod` | Pull latest changes for the production install |
| `ctf-sync --help` | Show sync help |

---

## Known Platforms

These platforms are built in. The code is what you pass to `set-platform`:

| Code | Platform |
|------|----------|
| `HTB` | Hack The Box |
| `THM` | TryHackMe |
| `LD` | LetsDefend |
| `DC` | DefCon |
| `GGL` | Google CTF |
| `PG` | Proving Grounds |

To add a new platform, open `setup/ctf-env-functions.sh` and append a line to the `KNOWN_PLATFORMS` array:

```zsh
KNOWN_PLATFORMS=(
  "HTB:Hack The Box"
  "THM:TryHackMe"
  "MYPLATFORM:My Custom Platform"   # ← add here
)
```

The toolkit will warn you if you try `set-platform` with an unknown code, but it won't block you — useful when a new platform appears before you've had a chance to add it.

---

## Updating the Toolkit

Pull the latest changes at any time:

```zsh
ctf-sync
```

If `ctf-sync` encounters files that have local modifications (usually permission changes from a previous `chmod +x` run), it will show you the affected files and offer to reset them:

```
[WARN]  Pull blocked — local changes conflict with remote:

  !  setup/ctf-sync.sh
  !  setup/ctf-install.sh

  Overwrite all conflicting local changes with remote? [y/N]:
```

Answer `y` to reset and retry the pull automatically. Answer `N` to abort and resolve manually.

<!--
README BEST PRACTICE — Document known behaviours that might look like errors.

If a user encounters something that looks alarming but is expected and handled,
document it. The conflict recovery prompt above could easily panic a new user
who doesn't know why it's appearing. A brief explanation in the README removes
that anxiety and builds confidence in the tool.
-->

---

## Repo Structure

```
CTF_Public/
├── setup/
│   ├── ctf-env-functions.sh   # Session commands (set-platform, set-box, etc.)
│   ├── ctf-install.sh         # Machine installer — run once per machine
│   └── ctf-sync.sh            # Repo sync — run to pull updates
├── .gitattributes             # Enforces LF line endings across all platforms
└── README.md                  # This file
```

### How the files relate

- **`ctf-install.sh`** is the one-time setup script. It deploys `ctf-env-functions.sh` to `~/.ctf_env`, patches `~/.zshrc` to source it, and symlinks all scripts to `/usr/local/bin` so they are available everywhere.
- **`ctf-env-functions.sh`** is the file sourced into every terminal session. It defines all interactive commands (`set-platform`, `ctf-status`, etc.) and is the single source of truth for known platforms and workspace layout.
- **`ctf-sync.sh`** is the update mechanism. It can be run before `ctf-install` (as a bootstrap on a new machine) or afterwards (as a regular update command).

To update a session command, you only need to edit `ctf-env-functions.sh`, push, and run `ctf-sync && source ~/.ctf_env`. No reinstall required.

---

## Adding New Tools to the Dependency Check

Open `setup/ctf-install.sh` and find the `REQUIRED_TOOLS` array. Add a new entry following the format `"command:display_name:apt_package:version_field"`:

```zsh
REQUIRED_TOOLS=(
  "curl:cURL:curl:2"
  "nmap:Nmap:nmap:3"
  "sqlmap:SQLMap:sqlmap:2"   # ← example addition
)
```

The fourth field is the position of the version number in the tool's `--version` output (counting from 1). Run `sqlmap --version | head -1` and count which word the version number is.

---

## Workspace Folders

Every new box gets these subdirectories automatically:

| Folder | Purpose |
|--------|---------|
| `scans/` | Nmap output, service enumeration |
| `exploits/` | Exploit scripts, payloads |
| `notes/` | Notes markdown file (pre-filled) |
| `flags/` | Captured flags |
| `loot/` | Credentials, hashes, interesting files |

To add a folder to every future workspace, open `setup/ctf-env-functions.sh` and append to `_CTF_BOX_DIRS`:

```zsh
_CTF_BOX_DIRS=(
  "scans"
  "exploits"
  "notes"
  "flags"
  "loot"
  "custom_folder"   # ← add here
)
```

Existing workspaces are not affected — only new ones created after the change.

---

## Environment Variables

These variables can be set in `~/.zshrc` above the `source ~/.ctf_env` line to override defaults:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CTF_REPO_DIR` | `/opt/CTF_Public` | Override the repo path |
| `CTF_BASE_DIR` | `/opt/CTF` | Override where workspaces are created |

Example for a dev machine that wants workspaces in the home directory:

```zsh
# In ~/.zshrc, above the source line:
export CTF_BASE_DIR="$HOME/CTF"
source ~/.ctf_env
```

---

## Session Persistence

Session variables (`PLATFORM`, `BOXNAME`, `ADDRESS`, `BOX_DIR`) persist across terminal windows. When you run `set-address 10.10.10.3` in one terminal, opening a new terminal will have that address already set.

This works by rewriting the export lines in `~/.ctf_env` each time a variable changes. To see the current state from any terminal:

```zsh
ctf-status
```

To start fresh:

```zsh
ctf-clear
```

---

## Troubleshooting

**Commands not found after install**

Run `source ~/.zshrc` and try again. If the issue persists, check that `~/.zshrc` contains the line `source ~/.ctf_env` (the installer adds this automatically).

**`ctf-sync` fails with permission errors**

On a production install, some operations require sudo. Run `ctf-sync --prod` which will use elevated permissions where needed.

**`set-box` fails to create the workspace**

Make sure you have run `set-platform` first. The workspace path is `CTF_BASE/PLATFORM/BOXNAME` — both platform and box name are required to construct it.

**Wrong environment is active**

Run `ctf-status` — the `Env` row shows whether you are in `dev` or `prod` mode and which directory is being used. If the wrong one is active, use `--prod` flags or set `CTF_REPO_DIR` in your environment.

<!--
README BEST PRACTICE — A troubleshooting section.

Every tool has edge cases. Documenting the most common ones here saves users
from having to file issues or dig through source code. Keep this section honest
— only document problems that actually occur and solutions that actually work.
A wrong troubleshooting step is worse than no step at all.
-->

---

## Contributing

1. Fork the repo and clone your fork
2. Make changes in a feature branch: `git checkout -b my-feature`
3. Test on both a dev path (`~/github/CTF_Public`) and a production path (`/opt/CTF_Public`) if possible
4. Ensure files are saved with **LF line endings** (not CRLF) — see `.gitattributes`
5. Push and open a pull request

When editing on Windows, use VS Code and confirm the status bar in the bottom-right shows `LF` before saving. The `.gitattributes` file enforces LF on commit as a safety net.

---

<!--
README BEST PRACTICE — Keep the README in the repo root.

GitHub looks for README.md (case-insensitive) in the repository root and
renders it automatically. Placing it anywhere else means it won't appear on
the repo's main page. The filename must be README.md — not readme.md or
Readme.md, though GitHub is case-insensitive, the convention is all-caps.

Other README best practices to carry forward:
  - Use a single H1 heading (# Title) at the top — only one per file
  - Use H2 (##) for major sections, H3 (###) for subsections
  - Keep lines under ~100 characters where possible for readable diffs
  - Use relative links for anything in the repo: [file](setup/ctf-sync.sh)
  - Use absolute links for anything external: [GitHub](https://github.com)
  - Add a blank line before and after every heading, code block, and table
  - Don't over-explain. If a command is self-evident, a short description is enough.
  - Update the README in the same commit as the code change that requires it.
    A README that lags behind the code is a liability, not an asset.
-->