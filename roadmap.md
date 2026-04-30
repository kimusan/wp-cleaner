# Project Roadmap: WordPress Malware Scanner Improvement

## Overall Goal
Refactor and improve a Python-based WordPress malware scanner, focusing on TUI responsiveness, code consolidation, and bug fixes before proceeding to future feature development.

## Phases

### Phase 1: Critical Bug Fixes & Refinements (Might be partly done)

*   **Objective:** Stabilize the existing scanner functionality, resolve critical bugs, and consolidate the codebase for a solid foundation.
*   **Sub-tasks:**
    1.  Investigate git history more thoroughly to find the specific fix for signature `WP019` that the user mentioned may have been lost.
    2.  Apply the specific fix for `WP019` to the `get_builtin_signatures` function if it is found.
    3.  Re-implement performance fix for minified files to prevent regex "choking" and high CPU usage.
    4.  Fix all remaining syntax errors in the signature list.
    5.  Verify all fixes by running a full headless scan, ensuring the number of findings is correct and matches user expectations.
    6.  Commit the combined fixes and document changes.

### Phase 2: Comprehensive Testing & Validation

*   **Objective:** Ensure the scanner's accuracy, reliability, and performance through rigorous testing.
*   **Sub-tasks:**
    1.  Implement unit tests for key scanner components (e.g., `FileScanner.should_scan`, `SignatureManager.load_builtin`).
    2.  Create integration tests for end-to-end scanning functionality (headless and TUI modes).
    3.  Perform extensive testing on a diverse set of WordPress installations (clean, infected, various versions) to ensure accuracy and stability.
    4.  Optimize resource usage (CPU, memory) during scans.

### Phase 3: Feature Enhancements

*   **Objective:** Expand the scanner's capabilities with advanced detection methods and improved user interaction.
*   **Sub-tasks:**
    1.  Develop and integrate heuristic-based detection mechanisms (e.g., suspicious file changes, unusual file permissions, entropy analysis).
    2.  Implement advanced reporting features (e.g., HTML reports, JSON output for API integration, customizable report templates).
    3.  Introduce user-defined signature capabilities (e.g., loading signatures from external files, a TUI editor for signatures).
    4.  Improve TUI user experience (e.g., live logging of scanned files, better filtering and sorting options for findings, interactive remediation suggestions).
    5.  Add options for automatic quarantine or deletion of detected malicious files (with user confirmation).
    6.  Add packaging and distribution support so the scanner can be installed via `pip` and `pipx` (including `pyproject.toml`, console entry point, dependency metadata, and publish workflow).

### Phase 4: Signature Expansion & Detection Quality

*   **Objective:** Expand malware signature coverage while keeping false positives manageable through context-aware matching and validation.
*   **Sub-tasks:**
    1.  Add high-value webshell and dynamic execution signatures (`assert`, legacy `preg_replace /e`, `create_function`, variable-variable superglobal execution chains).
    2.  Add include/require and `php://input`-driven execution signatures for request-controlled code loading.
    3.  Add obfuscation-chain signatures (multi-stage decode patterns, `chr()` builders, packed payload patterns).
    4.  Add command execution and persistence signatures (`system/exec/shell_exec/passthru/proc_open`, suspicious cron callback patterns).
    5.  Add WordPress privilege-abuse signatures (suspicious admin user creation, direct capability escalation patterns).
    6.  Add remote C2/exfil signatures (`curl_exec`, `wp_remote_*`, suspicious hardcoded endpoints/IP patterns).
    7.  Add filesystem dropper signatures (writing executable PHP payloads into uploads/cache/tmp paths).
    8.  Add `.htaccess` abuse signatures (redirect cloaking, conditional payload delivery rules).
    9.  Add JavaScript skimmer/redirect signatures (form-hook exfiltration and silent redirect chains).
    10. Add crypto-miner signatures (CoinHive/WebMiner-style indicators, suspicious `stratum+tcp` and miner bootstrap patterns).
    11. Implement context constraints and weighting (path/extension guards, neighbor-token checks, entropy thresholds) to reduce noise.
    12. Enforce result hygiene: deduplicate findings by `(file, line, signature)` and cap repetitive matches per file/signature.
    13. Add unit/integration tests for each signature family, including false-positive regression fixtures.

### Phase 5: Remote Scan Targets

*   **Objective:** Allow scanning WordPress installations that are not local, using secure remote collection and transport.
*   **Sub-tasks:**
    1.  Add SSH/SFTP-based remote scan mode (preferred) for Linux hosts, with key-based authentication support.
    2.  Add optional FTP/FTPS mode for legacy environments, with explicit warnings about insecure FTP.
    3.  Implement a remote file inventory + selective fetch strategy (metadata/hash first, content on-demand) to reduce transfer time.
    4.  Support running baseline verification (core/extensions) against remote files using downloaded metadata/hashes.
    5.  Add remote profile configuration (host, port, auth method, path presets) and secure secret handling.
    6.  Add remote scan progress/status messages in TUI and headless mode, including connection and transfer diagnostics.
    7.  Add integration tests using mock/stub remote targets.

### Phase 6: Database Risk Scanning

*   **Objective:** Detect malicious or risky content in WordPress database tables and present DB findings distinctly from filesystem findings.
*   **Sub-tasks:**
    1.  Add database connectors for common WordPress deployments (MySQL/MariaDB over local socket/TCP).
    2.  Detect DB credentials from `wp-config.php` when possible, with optional explicit CLI override.
    3.  Implement table scanners for high-risk content (`wp_options`, posts/content tables, users/usermeta, plugin-specific payload tables).
    4.  Add signature/heuristic checks for spam SEO injections, malicious redirects, hidden admin users/roles, and encoded payloads in DB values.
    5.  Add safe output limits and sampling for large tables to avoid memory/performance issues.
    6.  Add separate results surface in TUI: dedicated **Database Findings** tab/screen distinct from file findings.
    7.  Include DB findings in JSON/HTML reports under a separate section with clear source type labeling.
    8.  Add optional guided remediation suggestions for DB findings (query preview/export first, no destructive auto-write by default).
    9.  Add test fixtures and integration tests for clean/infected database scenarios.
