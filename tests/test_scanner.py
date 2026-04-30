import tempfile
import unittest
import os
import json
from pathlib import Path

from wp_scanner import FileScanner, SignatureManager, ScanStatus, WordPressCoreVerifier


class ScannerTests(unittest.TestCase):
    def setUp(self):
        manager = SignatureManager()
        manager.load_builtin()
        self.scanner = FileScanner(manager.get_all())

    def test_signature_manager_loads_builtin(self):
        manager = SignatureManager()
        count = manager.load_builtin()
        self.assertGreaterEqual(count, 100)

    def test_signature_manager_loads_custom_signatures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            custom = root / "custom.json"
            custom.write_text(
                json.dumps(
                    [
                        {
                            "id": "CUS001",
                            "name": "Test Backdoor String",
                            "pattern": "danger_marker_123",
                            "description": "Custom marker",
                            "threat_level": "high",
                            "category": "custom",
                            "remediation": "Remove custom marker",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            manager = SignatureManager(str(custom))
            manager.load_builtin()
            loaded = manager.load_custom()
            self.assertEqual(loaded, 1)
            all_ids = {sig.id for sig in manager.get_all()}
            self.assertIn("CUS001", all_ids)

    def test_should_scan_filters_by_extension_and_minified_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            php_file = root / "ok.php"
            minified_js = root / "app.min.js"
            txt_file = root / "notes.txt"
            bin_file = root / "image.bin"

            php_file.write_text("<?php echo 'ok';", encoding="utf-8")
            minified_js.write_text("console.log('x')", encoding="utf-8")
            txt_file.write_text("text", encoding="utf-8")
            bin_file.write_bytes(b"\x00\x01")

            self.assertTrue(self.scanner.should_scan(php_file))
            self.assertFalse(self.scanner.should_scan(minified_js))
            self.assertTrue(self.scanner.should_scan(txt_file))
            self.assertFalse(self.scanner.should_scan(bin_file))

    def test_scan_file_detects_backdoor_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "mal.php"
            target.write_text(
                "<?php\n"
                "// malware\n"
                "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertGreaterEqual(len(result.findings), 1)
            self.assertTrue(any(f.signature_id == "WP021" for f in result.findings))

    def test_scan_file_detects_include_from_superglobal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "loader.php"
            target.write_text(
                "<?php\n"
                "include($_POST['payload']);\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP102" for f in result.findings))

    def test_scan_file_detects_assert_superglobal_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "exec.php"
            target.write_text(
                "<?php\n"
                "assert($_REQUEST['cmd']);\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP103" for f in result.findings))

    def test_scan_file_deduplicates_and_caps_noisy_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "wallets.js"
            # Repeats bitcoin-like wallet tokens to trigger WP096 many times.
            wallet = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
            target.write_text("\n".join([wallet] * 200), encoding="utf-8")

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            wallet_findings = [f for f in result.findings if f.signature_id == "WP096"]
            self.assertLessEqual(
                len(wallet_findings),
                self.scanner.MAX_MATCHES_PER_SIGNATURE_PER_FILE,
            )

    def test_collect_files_skips_git_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / ".git" / "hidden.php").write_text("<?php eval($x);", encoding="utf-8")
            (root / "ok.php").write_text("<?php echo 'ok';", encoding="utf-8")

            files = self.scanner.collect_files(root)
            self.assertIn(root / "ok.php", files)
            self.assertNotIn(root / ".git" / "hidden.php", files)

    def test_heuristic_php_in_uploads_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uploads = root / "wp-content" / "uploads"
            uploads.mkdir(parents=True, exist_ok=True)
            target = uploads / "dropper.php"
            target.write_text("<?php echo 'x';", encoding="utf-8")

            result = self.scanner.scan_file(target)
            heuristic_ids = {f.signature_id for f in result.findings}
            self.assertIn("H001", heuristic_ids)

    def test_heuristic_world_writable_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "perm.php"
            target.write_text("<?php echo 'x';", encoding="utf-8")
            os.chmod(target, 0o666)

            result = self.scanner.scan_file(target)
            heuristic_ids = {f.signature_id for f in result.findings}
            self.assertIn("H003", heuristic_ids)

    def test_heuristic_high_entropy_token_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 4
            target = root / "obf.php"
            target.write_text(f"<?php\n$blob = '{token}';\n", encoding="utf-8")

            result = self.scanner.scan_file(target)
            heuristic_ids = {f.signature_id for f in result.findings}
            self.assertIn("H004", heuristic_ids)

    def test_verify_core_filters_identical_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan_root = root / "scan"
            ref_root = root / ".wp-scanner-cache" / "wordpress-core" / "6.5.3" / "wordpress"
            (scan_root / "wp-includes").mkdir(parents=True, exist_ok=True)
            (ref_root / "wp-includes").mkdir(parents=True, exist_ok=True)

            version_php = "<?php\n$wp_version = '6.5.3';\n"
            core_php = "<?php echo 'core';\n"
            changed_php = "<?php echo 'changed';\n"
            plugin_php = "<?php echo 'plugin';\n"

            (scan_root / "wp-includes" / "version.php").write_text(version_php, encoding="utf-8")
            (ref_root / "wp-includes" / "version.php").write_text(version_php, encoding="utf-8")
            (scan_root / "wp-includes" / "load.php").write_text(changed_php, encoding="utf-8")
            (ref_root / "wp-includes" / "load.php").write_text(core_php, encoding="utf-8")
            (scan_root / "wp-config.php").write_text("<?php\n", encoding="utf-8")
            (ref_root / "wp-config.php").write_text("<?php\n", encoding="utf-8")
            (scan_root / "wp-content" / "plugins").mkdir(parents=True, exist_ok=True)
            (scan_root / "wp-content" / "plugins" / "x.php").write_text(plugin_php, encoding="utf-8")

            verifier = WordPressCoreVerifier(cache_dir=root / ".wp-scanner-cache", offline=True)
            ok, _msg = verifier.prepare(scan_root)
            self.assertTrue(ok)

            files = self.scanner.collect_files(scan_root)
            filtered, skipped, modified = verifier.filter_identical_core_files(scan_root, files)
            filtered_set = set(filtered)
            self.assertGreaterEqual(skipped, 2)  # version.php and wp-config.php
            self.assertIn(scan_root / "wp-includes" / "load.php", filtered_set)  # changed core file kept
            self.assertIn(scan_root / "wp-content" / "plugins" / "x.php", filtered_set)  # non-core file kept
            self.assertIn(scan_root / "wp-includes" / "load.php", modified)

            self.scanner.modified_core_paths = {str(path.resolve()) for path in modified}
            result = self.scanner.scan_file(scan_root / "wp-includes" / "load.php")
            heuristic_ids = {f.signature_id for f in result.findings}
            self.assertIn("H005", heuristic_ids)


if __name__ == "__main__":
    unittest.main()
