#!/usr/bin/env python3
"""
WordPress Malware Scanner - TUI Module
Textual-based terminal user interface for real-time scanning visualization.
"""

from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import signal

try:
    from textual.app import App, ComposeResult
    from textual.widgets import (
        Header, Footer, DataTable, Static, ProgressBar,
    )
    from textual.containers import Container
    from textual.binding import Binding
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


class SummaryScreen(ModalScreen):
    """Modal screen showing scan summary."""
    
    BINDINGS = [Binding("escape", "dismiss", "Close")]
    
    def __init__(self, stats):
        super().__init__()
        self.stats = stats
    
    def compose(self) -> ComposeResult:
        yield Static(f"""
╔══════════════════════════════════════════════════════════╗
║                    SCAN COMPLETE                          ║
╠══════════════════════════════════════════════════════════╣
║  Files Scanned:     {self.stats.scanned_files:>6}                          ║
║  Infected Files:    {self.stats.infected_files:>6}                          ║
║  Total Findings:    {self.stats.total_findings:>6}                          ║
║                                                           ║
║  Critical: {self.stats.critical:>3}  |  High: {self.stats.high:>3}  |  Medium: {self.stats.medium:>3}  |  Low: {self.stats.low:>3}         ║
║                                                           ║
║  Duration: {self.stats.scan_duration_seconds:>6.2f} seconds                        ║
╚══════════════════════════════════════════════════════════╝

Press ESC to close
""", id="summary-box")
    
    def action_dismiss(self) -> None:
        self.dismiss()


class SummaryScreenMock(ModalScreen):
    """Modal screen showing scan progress (when scan not complete)."""
    
    BINDINGS = [Binding("escape", "dismiss", "Close")]
    
    def __init__(self, text: str):
        super().__init__()
        self.text = text
    
    def compose(self) -> ComposeResult:
        yield Static(self.text, id="summary-box")
    
    def action_dismiss(self) -> None:
        self.dismiss()


class ScannerTUI(App):
    """Textual TUI for the WordPress Malware Scanner."""
    
    TITLE = "WordPress Malware Scanner"
    SUB_TITLE = "Real-time malware detection"
    
    CSS = """
    Screen {
        background: #0b0c15;
    }
    
    #header-container {
        height: 5;
        margin: 1 2;
    }
    
    #stats-bar {
        height: 4;
        margin: 1 2;
        background: #1a1b26;
        border: solid #414868;
    }
    
    #progress-container {
        height: 3;
        margin: 1 2;
    }
    
    #current-file {
        height: 3;
        margin: 1 2;
        background: #1a1b26;
        color: #7aa2f7;
        padding: 1 2;
    }
    
    #main-content {
        height: 1fr;
        margin: 1 2;
    }
    
    .critical { color: #f7768e; text-style: bold; }
    .high { color: #ff9e64; text-style: bold; }
    .medium { color: #e0af68; }
    .low { color: #9ece6a; }
    
    .stat-label { color: #565f89; }
    .stat-value { color: #7aa2f7; text-style: bold; }
    
    DataTable {
        height: 1fr;
        background: #1a1b26;
    }
    
    DataTable > .datatable--header {
        background: #24283b;
        color: #7aa2f7;
    }
    
    #summary-box {
        background: #1a1b26;
        border: solid #7aa2f7;
        padding: 1 2;
        width: 60;
        height: 20;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit_app", "Quit", priority=True),
        Binding("s", "show_summary", "Summary"),
        Binding("c", "clear_findings", "Clear"),
        Binding("p", "toggle_pause", "Pause"),
        Binding("escape", "quit_app", "Quit", show=False),
    ]
    
    files_scanned = reactive(0)
    total_files = reactive(0)
    current_file_path = reactive("Scanning...")
    status_text = reactive("Scanning...")
    critical_count = reactive(0)
    high_count = reactive(0)
    medium_count = reactive(0)
    low_count = reactive(0)
    
    def __init__(self, scanner, scan_path: str, threads: int = 4):
        super().__init__()
        self.scanner = scanner
        self.scan_path = scan_path
        self.threads = threads
        self.findings: List = []
        self.results: List = []
        self.scan_complete = False
        self._stats = None
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused by default
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="header-container"):
            yield Static(f"""[bold cyan]WordPress Malware Scanner[/bold cyan]
[cyan]Path: {self.scan_path} | Threads: {self.threads}[/cyan]""", id="title-bar")
        
        with Container(id="stats-bar"):
            yield Static(f"""
[stat-label]Files:[/stat-label] [stat-value]{self.files_scanned}[/stat-value] / [stat-value]{self.total_files}[/stat-value]
[stat-label]Findings:[/stat-label] [critical]{self.critical_count}[/critical] [high]{self.high_count}[/high] [medium]{self.medium_count}[/medium] [low]{self.low_count}[/low]
[stat-label]Status:[/stat-label] [cyan]{self.status_text}[/cyan]
            """, id="stats-display")
        
        with Container(id="progress-container"):
            yield ProgressBar(total=100, show_eta=True, show_percentage=True, id="main-progress")
        
        yield Static(f"[cyan]📁 {self.current_file_path}[/cyan]", id="current-file")
        
        with Container(id="main-content"):
            yield DataTable(id="findings-table")
        
        yield Footer()
    
    def on_mount(self) -> None:
        if not TEXTUAL_AVAILABLE:
            return
        
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Level", "File", "Threat", "Line", "Category")
        table.zebra_stripes = True
        table.cursor_type = "row"
        
        self._scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self._scan_thread.start()
    
    def _run_scan(self) -> None:
        try:
            files = self.scanner.collect_files(Path(self.scan_path))
            total = len(files)
            self.call_from_thread(self._set_total_files, total)
            
            if total == 0:
                self.call_from_thread(self._scan_done)
                return
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_file = {executor.submit(self.scanner.scan_file, f): f for f in files}
                for future in as_completed(future_to_file):
                    # Check if stop requested
                    if self._stop_event.is_set():
                        break
                    
                    # Check if paused
                    self._pause_event.wait()
                    if self._stop_event.is_set():
                        break
                    
                    result = future.result()
                    self.results.append(result)
                    self.call_from_thread(self._process_result, result)
            
            if not self._stop_event.is_set():
                self.call_from_thread(self._scan_done)
            else:
                self.call_from_thread(self._scan_cancelled)
        except Exception as e:
            self.call_from_thread(self._scan_error, str(e))
    
    def _set_total_files(self, total: int) -> None:
        self.total_files = total
    
    def _process_result(self, result) -> None:
        self.files_scanned += 1
        self.current_file_path = result.file_path
        
        try:
            progress_bar = self.query_one("#main-progress", ProgressBar)
            progress = (self.files_scanned / self.total_files * 100) if self.total_files > 0 else 0
            progress_bar.update(progress=progress)
        except Exception:
            pass
        
        if result.findings:
            try:
                table = self.query_one("#findings-table", DataTable)
                for finding in result.findings:
                    self.findings.append(finding)
                    if finding.threat_level == 'critical':
                        self.critical_count += 1
                    elif finding.threat_level == 'high':
                        self.high_count += 1
                    elif finding.threat_level == 'medium':
                        self.medium_count += 1
                    else:
                        self.low_count += 1
                    
                    level_class = finding.threat_level
                    # Add background color based on severity
                    bg_colors = {
                        'critical': '#3a1a1a',
                        'high': '#3a2a1a',
                        'medium': '#3a3a1a',
                        'low': '#1a3a1a'
                    }
                    bg = bg_colors.get(level_class, '#1a1a1a')
                    
                    table.add_row(
                        f"[{level_class} on {bg}]{finding.threat_level.upper()}[/]",
                        f"[on {bg}]{Path(finding.file_path).name[:25]}[/]",
                        f"[on {bg}]{finding.signature_name[:20]}[/]",
                        f"[on {bg}]{finding.line_number}[/]",
                        f"[on {bg}]{finding.category[:15]}[/]",
                        key=f"{finding.file_path}:{finding.line_number}"
                    )
            except Exception:
                pass
        
        if self.files_scanned % 10 == 0 or self.files_scanned == self.total_files:
            self.status_text = f"Scanning... {self.files_scanned}/{self.total_files}"
    
    def _scan_done(self):
        self.scan_complete = True
        self.status_text = "✓ Scan complete"
        self._calculate_stats()
    
    def _scan_cancelled(self):
        self.scan_complete = True
        self.status_text = "✗ Scan cancelled"
    
    def _scan_error(self, error: str):
        self.scan_complete = True
        self.status_text = f"✗ Error: {error}"
    
    def _calculate_stats(self):
        from wp_scanner import ScanStats, calculate_stats
        if self.results:
            start_time = time.time() - max(1, self.files_scanned * 0.01)
            self._stats = calculate_stats(self.results, start_time, time.time())
    
    def action_quit_app(self) -> None:
        """Quit immediately, stopping scan if in progress."""
        self._stop_event.set()
        self._pause_event.set()  # Unblock if paused
        self.exit()
    
    def action_toggle_pause(self) -> None:
        """Pause or resume the scan."""
        if self.scan_complete:
            return
        
        self._paused = not self._paused
        if self._paused:
            self._pause_event.clear()
            self.status_text = "⏸ Paused - press 'p' to resume"
        else:
            self._pause_event.set()
            self.status_text = f"Scanning... {self.files_scanned}/{self.total_files}"
    
    def action_show_summary(self) -> None:
        """Show summary or progress info."""
        if self._stats:
            self.push_screen(SummaryScreen(self._stats))
        else:
            # Show progress during scan
            progress_text = f"""
╔══════════════════════════════════════════════════════════╗
║                    SCAN IN PROGRESS                       ║
╠══════════════════════════════════════════════════════════╣
║  Files Scanned:     {self.files_scanned:>6} / {self.total_files:<6}                     ║
║  Findings So Far:   {self.critical_count + self.high_count + self.medium_count + self.low_count:>6}                          ║
║                                                           ║
║  Critical: {self.critical_count:>3}  |  High: {self.high_count:>3}  |  Medium: {self.medium_count:>3}  |  Low: {self.low_count:>3}         ║
║                                                           ║
║  Press 'p' to pause, 'q' to quit                          ║
╚══════════════════════════════════════════════════════════╝

Press ESC to close
"""
            self.push_screen(SummaryScreenMock(progress_text))
    
    def action_clear_findings(self) -> None:
        try:
            table = self.query_one("#findings-table", DataTable)
            table.clear()
        except Exception:
            pass
        self.findings.clear()
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0


def run_tui_app(scanner, path: str, threads: int = 4) -> int:
    if not TEXTUAL_AVAILABLE:
        print("Textual TUI not installed. Install with: pip install textual")
        print("Or use --no-tui for headless mode.")
        return 1
    
    app = ScannerTUI(scanner, path, threads)
    try:
        app.run()
        return 0
    except KeyboardInterrupt:
        return 1
    except Exception as e:
        print(f"TUI error: {e}")
        return 1


if __name__ == "__main__":
    print("This module is meant to be imported by wp-scanner.py")
    print("Run: python3 wp-scanner.py /path/to/scan")
