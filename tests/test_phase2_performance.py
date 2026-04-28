import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path

from wp_scanner import FileScanner, SignatureManager


class Phase2PerformanceTests(unittest.TestCase):
    def setUp(self):
        manager = SignatureManager()
        manager.load_builtin()
        self.scanner = FileScanner(manager.get_all())

    def _make_corpus(self, root: Path, file_count: int, lines_per_file: int) -> None:
        benign_line = "<?php echo 'hello world'; // comment\n"
        suspicious_line = "eval(base64_decode('ZWNobyAnaGVsbG8nOw=='));\n"
        for i in range(file_count):
            payload = []
            for j in range(lines_per_file):
                if j % 40 == 0:
                    payload.append(suspicious_line)
                else:
                    payload.append(benign_line)
            (root / f"sample_{i:04d}.php").write_text("".join(payload), encoding="utf-8")

    def test_scan_runtime_small_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_corpus(root, file_count=120, lines_per_file=80)
            files = self.scanner.collect_files(root)

            start = time.perf_counter()
            total_findings = 0
            for file_path in files:
                result = self.scanner.scan_file(file_path)
                total_findings += len(result.findings)
            duration = time.perf_counter() - start

            self.assertGreater(total_findings, 0)
            self.assertLess(duration, 8.0, f"scan too slow: {duration:.2f}s")

    def test_scan_memory_peak_small_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_corpus(root, file_count=80, lines_per_file=120)
            files = self.scanner.collect_files(root)

            tracemalloc.start()
            for file_path in files:
                self.scanner.scan_file(file_path)
            _cur, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            peak_mb = peak / (1024 * 1024)
            self.assertLess(peak_mb, 80.0, f"peak memory too high: {peak_mb:.2f} MB")


if __name__ == "__main__":
    unittest.main()
