import subprocess
import tempfile
import unittest
import json
from pathlib import Path


class CliIntegrationTests(unittest.TestCase):
    def _run_cli(self, scan_path: Path):
        return subprocess.run(
            ["python3", "wp-scanner.py", str(scan_path), "--no-tui", "--threads", "2"],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_headless_cli_reports_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "infected.php"
            target.write_text(
                "<?php\n"
                "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n",
                encoding="utf-8",
            )

            proc = self._run_cli(root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("WORDPRESS MALWARE SCAN REPORT", proc.stdout)
            self.assertIn("Base64 Decode Eval", proc.stdout)
            self.assertIn("[CRITICAL]", proc.stdout)
            self.assertIn("Total Findings:", proc.stdout)

    def test_headless_cli_clean_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "clean.php"
            target.write_text("<?php echo 'hello';", encoding="utf-8")

            proc = self._run_cli(root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("WORDPRESS MALWARE SCAN REPORT", proc.stdout)
            self.assertIn("Files Scanned:", proc.stdout)

    def test_headless_cli_writes_json_and_html_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "infected.php"
            target.write_text(
                "<?php\n"
                "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n",
                encoding="utf-8",
            )
            json_report = root / "report.json"
            html_report = root / "report.html"

            proc = subprocess.run(
                [
                    "python3",
                    "wp-scanner.py",
                    str(root),
                    "--no-tui",
                    "--threads",
                    "2",
                    "--report-json",
                    str(json_report),
                    "--report-html",
                    str(html_report),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json_report.exists())
            self.assertTrue(html_report.exists())
            self.assertIn("JSON report written", proc.stdout)
            self.assertIn("HTML report written", proc.stdout)
            self.assertIn("WordPress Malware Scan Report", html_report.read_text(encoding="utf-8"))

    def test_headless_cli_uses_custom_signature_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "custom-hit.php"
            target.write_text("<?php\n// marker\ncustom_needle_456\n", encoding="utf-8")
            custom = root / "custom-signatures.json"
            custom.write_text(
                json.dumps(
                    [
                        {
                            "id": "CUS999",
                            "name": "Custom Needle",
                            "pattern": "custom_needle_456",
                            "description": "Custom signature hit",
                            "threat_level": "high",
                            "category": "custom",
                            "remediation": "Remove custom marker",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    "python3",
                    "wp-scanner.py",
                    str(root),
                    "--no-tui",
                    "--threads",
                    "2",
                    "--signatures",
                    str(custom),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Loaded 1 custom signatures", proc.stdout)
            self.assertIn("Custom Needle", proc.stdout)

    def test_headless_cli_quarantine_moves_infected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "infected.php"
            target.write_text(
                "<?php\n"
                "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n",
                encoding="utf-8",
            )
            qdir = root / "qbox"
            audit = root / "audit.jsonl"

            proc = subprocess.run(
                [
                    "python3",
                    "wp-scanner.py",
                    str(root),
                    "--no-tui",
                    "--threads",
                    "1",
                    "--quarantine",
                    "--quarantine-dir",
                    str(qdir),
                    "--audit-log",
                    str(audit),
                    "--yes",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Quarantine complete:", proc.stdout)
            self.assertFalse(target.exists())
            self.assertTrue((qdir / "infected.php").exists())
            self.assertTrue(audit.exists())
            self.assertIn("\"action\": \"quarantine\"", audit.read_text(encoding="utf-8"))

    def test_headless_cli_delete_removes_infected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "infected.php"
            target.write_text(
                "<?php\n"
                "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n",
                encoding="utf-8",
            )
            audit = root / "audit.jsonl"

            proc = subprocess.run(
                [
                    "python3",
                    "wp-scanner.py",
                    str(root),
                    "--no-tui",
                    "--threads",
                    "1",
                    "--delete",
                    "--audit-log",
                    str(audit),
                    "--yes",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Delete complete:", proc.stdout)
            self.assertFalse(target.exists())
            self.assertTrue(audit.exists())
            self.assertIn("\"action\": \"delete\"", audit.read_text(encoding="utf-8"))

    def test_headless_cli_verify_core_offline_graceful(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "clean.php"
            target.write_text("<?php echo 'ok';", encoding="utf-8")

            proc = subprocess.run(
                [
                    "python3",
                    "wp-scanner.py",
                    str(root),
                    "--no-tui",
                    "--threads",
                    "1",
                    "--verify-core",
                    "--verify-core-offline",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Core baseline skipped:", proc.stdout)


if __name__ == "__main__":
    unittest.main()
