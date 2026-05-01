![wp-scanner screenshot](https://raw.githubusercontent.com/kimusan/wp-cleaner/master/assets/screenshot.png)

# wp-scanner
_By Kim Schulz <kim@schulz.dk>_

`wp-scanner` is a WordPress malware scanner focused on finding backdoors, crypto miners, suspicious loaders, and obfuscated payloads in WordPress file trees.


## Warning
Use this tool carefully. Quarantine/delete actions can change or remove files. Always take a backup before remediation.

## Features
- Signature-based malware detection (100+ built-in signatures)
- Heuristic detection for suspicious WordPress patterns
- Optional WordPress core verification to skip unchanged official core files
- Interactive Textual TUI with sortable findings, details modal with source view, filtering, export, and remediation actions
- Headless mode with JSON/HTML report output
- Audit logging for remediation actions
- Restore support from quarantine via audit log

## Installation

### pip
Install from PyPI:

```bash
pip install wp-scanner
```

Install from PyPI with TUI dependencies:

```bash
pip install 'wp-scanner[tui]'
```

Install from local repository checkout:

```bash
pip install .
pip install '.[tui]'
```

### pipx
Install from PyPI as an isolated CLI app:

```bash
pipx install wp-scanner
```

Install from PyPI with TUI dependencies:

```bash
pipx install 'wp-scanner[tui]'
```

Install from local repository checkout:

```bash
pipx install .
pipx install --pip-args='.[tui]' .
```

If you run without TUI dependencies, the scanner falls back to headless mode automatically.

## Quick Start
Run TUI scan:

```bash
wp-scanner /path/to/wordpress
```

Run headless scan:

```bash
wp-scanner /path/to/wordpress --no-tui
```

## Common Usage
Headless scan with reports:

```bash
wp-scanner /path/to/wordpress --no-tui --report-json ./ --report-html ./
```

Use custom signatures:

```bash
wp-scanner /path/to/wordpress --no-tui --signatures ./custom-signatures.json
```

Verify against official WordPress core and skip unchanged core files:

```bash
wp-scanner /path/to/wordpress --verify-core
```

Offline core verification (cached core only):

```bash
wp-scanner /path/to/wordpress --verify-core --verify-core-offline
```

## Remote Scanning (SSH)
Scan a remote WordPress tree over SSH (key-based auth):

```bash
wp-scanner /dummy --remote-ssh user@example.com:/var/www/html --remote-key ~/.ssh/id_rsa --verify-core --verify-extensions
```

Headless remote scan:

```bash
wp-scanner /dummy --remote-ssh user@example.com:/var/www/html --no-tui --report-json ./ --report-html ./
```

Inventory-first remote fetch (fetch only scan-relevant files):

```bash
wp-scanner /dummy --remote-ssh user@example.com:/var/www/html --remote-inventory-first --no-tui
```

Use a non-default SSH port and explicit known-hosts file:

```bash
wp-scanner /dummy --remote-ssh user@example.com:/var/www/html --remote-port 2222 --remote-known-hosts ~/.ssh/known_hosts
```

Keep temporary remote snapshot files for debugging:

```bash
wp-scanner /dummy --remote-ssh user@example.com:/var/www/html --remote-keep-temp --no-tui
```

Disable host key verification (not recommended, legacy environments only):

```bash
wp-scanner /dummy --remote-ssh user@example.com:/var/www/html --remote-insecure-host-key --no-tui
```

Notes:
- In TUI mode, if no SSH key is provided, the app prompts for SSH password in a modal.
- In headless mode, if no SSH key is provided, password is prompted in terminal.
- The local path argument is ignored when `--remote-ssh` is set; `/dummy` is a placeholder.

Use a remote profile JSON file:

```bash
wp-scanner /dummy --remote-profile ./remote-profile.json --no-tui
```

Example `remote-profile.json`:

```json
{
  "remote_ssh": "user@example.com:/var/www/html",
  "port": 22,
  "key_file": "/home/user/.ssh/id_rsa",
  "known_hosts": "/home/user/.ssh/known_hosts",
  "inventory_first": true,
  "keep_temp_snapshot": false,
  "password_env": "WP_SCANNER_SSH_PASSWORD"
}
```

Using `password_env` (recommended over plain-text password):

```bash
export WP_SCANNER_SSH_PASSWORD='your-ssh-password'
wp-scanner /dummy --remote-profile ./remote-profile.json --no-tui
```

## Remediation (Headless)
Quarantine infected files:

```bash
wp-scanner /path/to/wordpress --no-tui --quarantine --quarantine-dir ./quarantine --yes
```

Delete infected files:

```bash
wp-scanner /path/to/wordpress --no-tui --delete --yes
```

Restore from quarantine using audit log:

```bash
wp-scanner /path/to/wordpress --no-tui --restore --audit-log ./wp-scan-remediation-audit.jsonl --yes
```

## TUI Controls
Main controls:
- `q`: quit
- `p`: pause/resume scan
- `r`: stop/restart scan
- `j` / `k` or arrows: move selection
- `d` or `enter`: open details modal
- `s`: toggle sort
- `e`: export findings
- `space`: select/unselect current finding
- `a`: select/unselect all visible findings
- `x`: quarantine selected
- `delete`: delete selected
- `u`: open restore modal

## Notes
- Findings can include false positives. Review critical/high findings first.
- Core verification and remediation audit logging are intended to reduce unnecessary scanning and improve operational safety.
