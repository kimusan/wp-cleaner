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
Install from the current directory:

```bash
pip install .
```

Install with TUI dependencies:

```bash
pip install 'wp-scanner[tui]'
```

For local editable/testing installs from this repository, use:

```bash
pip install '.[tui]'
```

### pipx
Install as an isolated CLI app:

```bash
pipx install .
```

Install with TUI dependencies:

```bash
pipx install 'wp-scanner[tui]'
```

For local installs from this repository, use:

```bash
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
