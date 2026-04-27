#!/usr/bin/env python3
"""
WordPress Malware Scanner - TUI Module
Textual-based terminal user interface for real-time scanning visualization.
"""

from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

try:
    from textual.app import App, ComposeResult
    from textual.widgets import (
        Header, Footer, DataTable, Label, Static, ProgressBar,
        TabbedContent, TabPane
    )
    from textual.containers import Container, Vertical, Horizontal
    from textual.binding import Binding
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


class SummaryScreen(ModalScreen):
    """Modal screen showing scan summary."""
    
    BINDINGS = [Binding("escape", "dismiss", "Close")]
    
    def __init__(self, stats, findings):
        super().__init__()
        self.stats = stats
        self.findings = findings
    
    def compose(self) -> ComposeResult:
        yield Static(f"""
╔══════════════════════════════════════════════════════════╗
║                    SCAN COMPLETE                          ║
╠══════════════════════════════════════════════════════════╣
║  Files Scanned:     {self.stats.scanned_files:>6}                          
║  Infected Files:    {self.stats.infected_files:>6}                          
║  Total Findings:    {self.stats.total_findings:>6}                          
║                                                           ║
║  Critical: {self.stats.critical:>3}  |  High: {self.stats.high:>3}  |  Medium: {self.stats.medium:>3}  |  Low: {self.stats.low:>3}         ║
║                                                           ║
║  Duration: {self.stats.scan_duration_seconds:>6.2f} seconds                        
╚══════════════════════════════════════════════════════════╝
""", id="summary-box")
    
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
    
    .stat-label {
        color: #565f89;
    }
    
    .stat-value {
        color: #7aa2f7;
        text-style: bold;
    }
    
    DataTable {
        height: 1fr;
        background: #1a1b26;
    }
    
    DataTable > .datatable--header {
        background: #24283b;
        color: #7aa2f7;
    }
    
    DataTable > .datatable--cursor {
        background: #24283b;
        color: #c0caf5;
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
        Binding("q", "quit", "Quit", priority=True),
        Binding("s", "show_summary", "Summary"),
        Binding("d", "toggle_dark", "Theme"),
        Binding("c", "clear_findings", "Clear"),
    ]
    
    # Reactive state
    files_scanned = reactive(0)
    total_files = reactive(0)
    findings_count = reactive(0)
    current_file_path = reactive("Waiting to start...")
    status_text = reactive("Initializing")
    
    # Counters
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
            yield ProgressBar(
                total=100, 
                show_eta=True,
                show_percentage=True,
                id="main-progress"
            )
        
        yield Static(f"[cyan]📁 {self.current_file_path}[/cyan]", id="current-file")
        
        with Container(id="main-content"):
            yield DataTable(id="findings-table")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the DataTable when app mounts."""
        if not TEXTUAL_AVAILABLE:
            return
        
        table = self.query_one("#findings-table", DataTable)
        table.add_columns(
            "Level",
            "File", 
            "Threat",
            "Line",
            "Category"
        )
        table.zebra_stripes = True
        table.cursor_type = "row"
        
        # Start the scan in background
        self.run_scan()
    
    def run_scan(self) -> None:
        """Run the malware scan in background."""
        def scan_worker():
            files = self.scanner.collect_files(Path(self.scan_path))
            self.total_files = len(files)
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_file = {
                    executor.submit(self.scanner.scan_file, f): f 
                    for f in files
                }
                
                for future in as_completed(future_to_file):
                    result = future.result()
                    self.results.append(result)
                    self._process_result(result)
            
            self.scan_complete = True
            self.status_text = "Scan complete"
            self._calculate_stats()
        
        # Run in thread to not block UI
        import threading
        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()
    
    def _process_result(self, result) -> None:
        """Process a scan result and update UI."""
        self.files_scanned += 1
        self.current_file_path = result.file_path
        
        # Update progress bar directly
        progress_bar = self.query_one("#main-progress", ProgressBar)
        progress = (self.files_scanned / self.total_files * 100) if self.total_files > 0 else 0
        progress_bar.update(progress=progress)
        
        if result.findings:
            table = self.query_one("#findings-table", DataTable)
            
            for finding in result.findings:
                self.findings.append(finding)
                self.findings_count += 1
                
                # Update severity counters
                if finding.threat_level == 'critical':
                    self.critical_count += 1
                elif finding.threat_level == 'high':
                    self.high_count += 1
                elif finding.threat_level == 'medium':
                    self.medium_count += 1
                else:
                    self.low_count += 1
                
                # Add row to table
                level_class = finding.threat_level
                table.add_row(
                    f"[{level_class}]{finding.threat_level.upper()}[/{level_class}]",
                    Path(finding.file_path).name[:25],
                    finding.signature_name[:20],
                    str(finding.line_number),
                    finding.category[:15],
                    key=f"{finding.file_path}:{finding.line_number}"
                )
        
        # Update status text
        if self.files_scanned % 10 == 0:
            self.status_text = f"Scanning... {self.files_scanned}/{self.total_files}"
    
    def _calculate_stats(self):
        """Calculate final statistics."""
        from wp_scanner import ScanStats, calculate_stats
        
        if self.results:
            start_time = time.time() - 1  # Approximate
            self._stats = calculate_stats(self.results, start_time, time.time())
    
    def action_quit(self) -> None:
        """Quit the application."""
        if self.scan_complete:
            self.exit()
        else:
            # Show confirmation
            self.exit(return_code=1)
    
    def action_show_summary(self) -> None:
        """Show scan summary modal."""
        if self._stats:
            self.push_screen(SummaryScreen(self._stats, self.findings))
    
    def action_toggle_dark(self) -> None:
        """Toggle dark/light theme."""
        # For now, just flash the screen
        self.bell()
    
    def action_clear_findings(self) -> None:
        """Clear the findings table."""
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        self.findings.clear()
        self.findings_count = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0


def run_tui_app(scanner, path: str, threads: int = 4) -> int:
    """Run the TUI application and return exit code."""
    if not TEXTUAL_AVAILABLE:
        print("Textual TUI not installed.")
        print("Install with: pip install textual")
        print("Or use --no-tui for headless mode.")
        return 1
    
    app = ScannerTUI(scanner, path, threads)
    return app.run()


if __name__ == "__main__":
    # Test run
    print("This module is meant to be imported by wp-scanner.py")
    print("Run: python3 wp-scanner.py /path/to/scan")
