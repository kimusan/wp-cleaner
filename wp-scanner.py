#!/usr/bin/env python3
"""
WordPress Malware Scanner
A modern, multi-threaded scanner for detecting malware, backdoors, and crypto miners
in WordPress installations.

Author: Kim Schulz <kim@schulz.dk>
GitHub: github.com/kimusan/wp-cleaner
"""

import os
import sys
import re
import json
import asyncio
import argparse
import logging
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    from textual.widgets import Header, Footer, DataTable, Label, ProgressBar, Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

# Version
__version__ = "1.2.2"

# (The rest of the file remains the same as the previous correct version, so it's omitted for brevity)
# =============================================================================
# DATA CLASSES AND ENUMS
# =============================================================================

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class Signature:
    id: str
    name: str
    pattern: str
    description: str
    threat_level: ThreatLevel
    category: str
    remediation: str
    is_regex: bool = True

@dataclass
class Finding:
    file_path: str
    line_number: int
    signature_id: str
    signature_name: str
    threat_level: str
    category: str
    matched_content: str
    context_before: str
    context_after: str
    description: str
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanResult:
    file_path: str
    status: str
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    scan_time_ms: float = 0.0

@dataclass
class ScanStats:
    total_files: int = 0
    scanned_files: int = 0
    infected_files: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    start_time: str = ""
    end_time: str = ""
    scan_duration_seconds: float = 0.0


# =============================================================================
# SIGNATURE DATABASE
# =============================================================================

def get_builtin_signatures() -> List[Signature]:
    """Return the built-in signature database."""
    return [
        Signature("WP001", "FilesMan Backdoor", r"FilesMan", "FilesMan backdoor", ThreatLevel.CRITICAL, "backdoor", "Remove the infected file."),
        Signature("WP002", "Base64 Decode Return", r'"base64_decode"\s*;\s*return', "Obfuscated code", ThreatLevel.HIGH, "obfuscation", "Decode and analyze payload."),
        Signature("WP003", "GLOBALS Injection", r';\s*\$GLOBALS', "Suspicious GLOBALS access", ThreatLevel.MEDIUM, "injection", "Review for unauthorized variable injection."),
        Signature("WP059", "Uploads PHP File", r'wp-content/uploads/[^/]+\.php', "PHP file in uploads directory", ThreatLevel.HIGH, "backdoor", "Delete - PHP should not be in uploads"),
    ]

# =============================================================================
# SIGNATURE MANAGER
# =============================================================================

class SignatureManager:
    GITHUB_SIGNATURES_URL = "https://raw.githubusercontent.com/kimusan/wp-cleaner/master/signatures.json"

    def __init__(self, custom_signature_file: Optional[str] = None):
        self.signatures_by_id: Dict[str, Signature] = {}
        self.custom_file = custom_signature_file

    def load_builtin(self) -> int:
        for sig in get_builtin_signatures():
            self.signatures_by_id[sig.id] = sig
        return len(self.signatures_by_id)

    def get_all(self) -> List[Signature]:
        return list(self.signatures_by_id.values())

# =============================================================================
# FILE SCANNER
# =============================================================================

class FileScanner:
    SCAN_EXTENSIONS = {'.php', '.js', '.html', '.htm', '.css', '.txt', '.md', '.json', '.xml', '.htaccess', '.ini', '.conf'}
    SKIP_DIRS = {'.git', '.svn', '.hg', 'node_modules', '__pycache__', '.idea', '.vscode', '.DS_Store'}

    def __init__(self, signatures: List[Signature]):
        self.signatures = signatures
        self.compiled_patterns: List[Tuple[Signature, re.Pattern]] = []
        for sig in signatures:
            try:
                flags = re.MULTILINE | re.IGNORECASE if sig.is_regex else 0
                pattern = re.compile(sig.pattern, flags)
                self.compiled_patterns.append((sig, pattern))
            except re.error as e:
                logging.warning(f"Invalid regex pattern {sig.id}: {e}")

    def should_scan(self, filepath: Path) -> bool:
        if filepath.suffix.lower() not in self.SCAN_EXTENSIONS:
            return False
        if '.min.' in filepath.name:
            return False
        try:
            if filepath.stat().st_size > 5 * 1024 * 1024: return False # 5MB limit
        except OSError:
            return False
        return True

    def scan_file(self, filepath: Path) -> ScanResult:
        start_time = time.monotonic()
        findings: List[Finding] = []
        try:
            if not self.should_scan(filepath):
                return ScanResult(file_path=str(filepath), status=ScanStatus.COMPLETED.value, findings=[])
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for sig, pattern in self.compiled_patterns:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(Finding(file_path=str(filepath), line_number=line_num, signature_id=sig.id, signature_name=sig.name, threat_level=sig.threat_level.value, category=sig.category, matched_content=match.group(0)[:200], context_before="", context_after="", description=sig.description, remediation=sig.remediation))
            
            scan_time = (time.monotonic() - start_time) * 1000
            return ScanResult(file_path=str(filepath), status=ScanStatus.COMPLETED.value, findings=findings, scan_time_ms=scan_time)
        except Exception as e:
            return ScanResult(file_path=str(filepath), status=ScanStatus.ERROR.value, error=str(e))

    def collect_files(self, root_path: Path) -> List[Path]:
        files: List[Path] = []
        for root, dirs, filenames in os.walk(root_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for filename in filenames:
                files.append(Path(root) / filename)
        return files

# =============================================================================
# REPORT GENERATOR
# =============================================================================
class ReportGenerator:
    @staticmethod
    def generate_text_report(results: List[ScanResult], stats: ScanStats) -> str:
        """Generate a text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("WORDPRESS MALWARE SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Duration: {stats.scan_duration_seconds:.2f} seconds")
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 70)
        lines.append(f"Files Scanned: {stats.scanned_files}")
        lines.append(f"Infected Files: {stats.infected_files}")
        lines.append(f"Total Findings: {stats.total_findings}")
        lines.append(f"  Critical: {stats.critical} | High: {stats.high} | Medium: {stats.medium} | Low: {stats.low}")
        lines.append("")
        
        all_findings = [f for r in results for f in r.findings]
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_findings.sort(key=lambda f: (severity_order.get(f.threat_level, 4), f.file_path))
        
        if all_findings:
            lines.append("FINDINGS")
            lines.append("-" * 70)
            
            for finding in all_findings:
                lines.append(f"[{finding.threat_level.upper()}] in {finding.file_path}:{finding.line_number}")
                lines.append(f"  -> {finding.signature_name}: {finding.description}")
                lines.append("")
        else:
            lines.append("No threats detected! ✓")
        
        lines.append("=" * 70)
        return '\n'.join(lines)

# =============================================================================
# TUI IMPLEMENTATION
# =============================================================================
if TEXTUAL_AVAILABLE:
    class FindingDetailScreen(ModalScreen):
        BINDINGS = [Binding("escape", "dismiss", "Close")]
        def __init__(self, finding: Finding):
            super().__init__()
            self.finding = finding
        def compose(self) -> ComposeResult:
            with Container(id="detail-container", classes="popup"):
                yield Label(f"[{self.finding.threat_level}]{self.finding.threat_level.upper()}[/] Details")
                yield Label(f"[b]File:[/b] {self.finding.file_path}:{self.finding.line_number}")
                yield Label(f"[b]Signature:[/b] {self.finding.signature_name}")
                yield Label(f"[b]Description:[/b] {self.finding.description}")
                yield Label(f"[b]Remediation:[/b] {self.finding.remediation}")
                yield Label("[b]Matched:[/]")
                yield Static(self.finding.matched_content, classes="code-view")

    class ScannerTUI(App):
        CSS = """
        #main-container {
            padding: 0 1;
        }
        #stats-grid {
            grid-size: 4;
            grid-gutter: 1;
            height: 3;
            margin: 1 0;
        }
        #stats-grid > .stat-box {
            background: #1a1b26;
            border: round #414868;
        }
        #stats-grid > .stat-box > Label {
            text-align: center;
            width: 100%;
        }
        .stat-value {
            text-style: bold;
            color: #7aa2f7;
        }
        #current-file {
            color: #7aa2f7;
        }
        #progress-bar {
            margin-top: 1;
        }
        #findings-table {
            height: 1fr;
            margin-top: 1;
        }
        .critical { color: #f7768e; }
        .high { color: #ff9e64; }
        .medium { color: #e0af68; }
        .low { color: #9ece6a; }
        """
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("d", "show_detail", "Details"),
            Binding("p", "toggle_pause", "Pause"),
            Binding("s", "toggle_sort", "Sort"),
        ]

        total_files = reactive(0)
        files_scanned = reactive(0)
        critical_count = reactive(0)
        high_count = reactive(0)
        medium_count = reactive(0)
        low_count = reactive(0)
        
        def __init__(self, scanner: FileScanner, scan_path: str, threads: int):
            super().__init__()
            self.scanner = scanner
            self.scan_path = scan_path
            self.threads = threads
            self.findings_map: Dict[str, Finding] = {}
            self.scan_complete = False
            self.executor = ThreadPoolExecutor(max_workers=self.threads)
            self._paused = False
            self._sort_column = 'severity'

        def compose(self) -> ComposeResult:
            yield Header()
            with Container(id="main-container"):
                with Horizontal(id="stats-grid"):
                    yield Label("Files: 0/0", id="files-stat")
                    yield Label("[critical]C: 0[/]", id="critical-stat")
                    yield Label("[high]H: 0[/]", id="high-stat")
                    yield Label("[medium]M: 0[/]", id="medium-stat")
                yield Static("Starting...", id="current-file")
                yield ProgressBar(total=100, id="progress-bar")
                yield DataTable(id="findings-table")
            yield Footer()

        def on_mount(self) -> None:
            self.query_one(DataTable).add_columns("Level", "File", "Threat", "Line", "Category")
            self.run_worker(self._run_scan)

        async def _run_scan(self) -> None:
            loop = asyncio.get_running_loop()
            self.sub_title = "Collecting files..."
            files = await loop.run_in_executor(self.executor, self.scanner.collect_files, Path(self.scan_path))
            self.total_files = len(files)
            if not files:
                self.sub_title = "✓ No files to scan."
                return

            self.sub_title = "Scanning..."
            tasks = [loop.run_in_executor(self.executor, self.scanner.scan_file, f) for f in files]
            for future in asyncio.as_completed(tasks):
                while self._paused:
                    self.sub_title = "⏸ PAUSED"
                    await asyncio.sleep(0.1)
                self.sub_title = "Scanning..."
                
                result: ScanResult = await future
                self.files_scanned += 1
                self.query_one("#current-file", Static).update(f"Scanning: {result.file_path}")
                
                if result.findings:
                    table = self.query_one(DataTable)
                    for finding in result.findings:
                        key = f"f_{len(self.findings_map)}"
                        self.findings_map[key] = finding
                        table.add_row(
                            f"[{finding.threat_level}]{finding.threat_level.upper()}[/]", 
                            Path(finding.file_path).name, 
                            finding.signature_name, 
                            str(finding.line_number), 
                            finding.category,
                            key=key
                        )
                        if finding.threat_level == 'critical': self.critical_count += 1
                        elif finding.threat_level == 'high': self.high_count += 1
                        elif finding.threat_level == 'medium': self.medium_count += 1
                        else: self.low_count += 1
            self.scan_complete = True
            self.sub_title = "✓ Scan Complete"
        
        def watch_files_scanned(self, val:int): 
            self.query_one("#files-stat").update(f"Files: {val}/{self.total_files}")
            if self.total_files > 0:
                self.query_one(ProgressBar).update(progress=val / self.total_files * 100)
        def watch_critical_count(self, val:int): self.query_one("#critical-stat").update(f"[critical]C: {val}[/]")
        def watch_high_count(self, val:int): self.query_one("#high-stat").update(f"[high]H: {val}[/]")
        def watch_medium_count(self, val:int): self.query_one("#medium-stat").update(f"[medium]M: {val}[/]")

        def action_quit(self) -> None:
            self.executor.shutdown(wait=False, cancel_futures=True)
            self.exit()
        def action_toggle_pause(self) -> None: self._paused = not self._paused
        
        def action_toggle_sort(self) -> None:
            """Cycle through sort options."""
            table = self.query_one(DataTable)
            if table.row_count == 0:
                return
            
            sort_options = ['severity', 'filename', 'line', 'category']
            current_idx = sort_options.index(self._sort_column)
            next_idx = (current_idx + 1) % len(sort_options)
            self._sort_column = sort_options[next_idx]

            severity_map = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

            def get_sort_key(row):
                key, cells = row
                level_text = cells[0].plain
                
                if self._sort_column == 'severity':
                    return severity_map.get(level_text, 99)
                elif self._sort_column == 'filename':
                    return cells[1].plain
                elif self._sort_column == 'line':
                    return int(cells[3].plain)
                elif self._sort_column == 'category':
                    return cells[4].plain
                return 0

            rows = list(table.rows.items())
            rows.sort(key=get_sort_key)
            
            table.clear()
            for key, row in rows:
                table.add_row(*[cell.renderable for cell in row.cells], key=key)
            
            self.sub_title = f"Sorted by {self._sort_column}"

        def action_show_detail(self) -> None:
            table = self.query_one(DataTable)
            if table.cursor_row >= 0:
                try:
                    row_key = table.get_row_key(table.cursor_row)
                    self.push_screen(FindingDetailScreen(self.findings_map[row_key]))
                except Exception:
                    self.bell()

# =============================================================================
# MAIN
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="WordPress Malware Scanner")
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--no-tui', action='store_true', help='Disable TUI')
    parser.add_argument('--threads', type=int, default=os.cpu_count(), help='Number of threads')
    args = parser.parse_args()

    sig_manager = SignatureManager()
    sig_manager.load_builtin()
    scanner = FileScanner(sig_manager.get_all())

    if args.no_tui or not TEXTUAL_AVAILABLE:
        if not TEXTUAL_AVAILABLE and not args.no_tui:
            print("Textual not found, falling back to headless mode.")
        
        print(f"Scanning {args.path}...")
        start_time = time.time()
        stats = ScanStats()
        results = []
        
        files = scanner.collect_files(Path(args.path))
        stats.total_files = len(files)
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scanner.scan_file, f): f for f in files}
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                results.append(result)
                stats.scanned_files += 1
                if result.findings:
                    stats.infected_files += 1
                    for finding in result.findings:
                        if finding.threat_level == 'critical': stats.critical += 1
                        elif finding.threat_level == 'high': stats.high += 1
                        elif finding.threat_level == 'medium': stats.medium += 1
                        else: stats.low += 1
                
                progress = (i + 1) / stats.total_files * 100
                sys.stdout.write(f"\rScanning... {progress:.2f}% ({i+1}/{stats.total_files})")
                sys.stdout.flush()
        
        end_time = time.time()
        stats.scan_duration_seconds = end_time - start_time
        stats.total_findings = stats.critical + stats.high + stats.medium + stats.low
        print("\nScan complete.")
        
        report = ReportGenerator.generate_text_report(results, stats)
        print(report)

    else:
        app = ScannerTUI(scanner=scanner, scan_path=args.path, threads=args.threads)
        app.run()

if __name__ == '__main__':
    main()
