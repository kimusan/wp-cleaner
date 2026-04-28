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
