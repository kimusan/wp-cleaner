#!/usr/bin/env bash
set -euo pipefail

python3 -m unittest -v \
  tests/test_scanner.py \
  tests/test_integration_cli.py \
  tests/test_phase2_performance.py

python3 wp-scanner.py html/wordpress --no-tui --threads 4 >/tmp/wp_phase2_report.txt

echo "Phase 2 validation complete. Report saved to /tmp/wp_phase2_report.txt"
