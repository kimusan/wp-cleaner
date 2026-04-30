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
import csv
import json
import bisect
import math
import html
import shutil
import getpass
import hashlib
import zipfile
import tarfile
import tempfile
import urllib.request
import urllib.error
import asyncio
import argparse
import logging
import time
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable, Set
from enum import Enum
from urllib.parse import urlparse

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, VerticalScroll
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    from textual.widgets import Header, Footer, DataTable, Label, ProgressBar, Static, Button, Input
    try:
        from textual.widgets import TextArea
    except Exception:
        TextArea = None
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False
    TEXTUAL_IMPORT_ERROR = "textual is not installed"
else:
    TEXTUAL_IMPORT_ERROR = ""

try:
    from rich.syntax import Syntax
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
    RICH_IMPORT_ERROR = ""
except ImportError:
    Syntax = None
    Panel = None
    Text = None
    RICH_AVAILABLE = False
    RICH_IMPORT_ERROR = "rich is not installed"

if TEXTUAL_AVAILABLE and not RICH_AVAILABLE:
    TEXTUAL_AVAILABLE = False
    TEXTUAL_IMPORT_ERROR = f"{TEXTUAL_IMPORT_ERROR}; {RICH_IMPORT_ERROR}".strip("; ").strip()
try:
    from pygments.lexers import guess_lexer_for_filename, get_lexer_by_name, find_lexer_class
except Exception:
    guess_lexer_for_filename = None
    get_lexer_by_name = None
    find_lexer_class = None

# Version
__version__ = "1.3.0"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_STYLES = {
    "critical": "#ff4d4f",
    "high": "#ff9f1a",
    "medium": "#ffd166",
    "low": "#66d9ef",
}

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
    target_type: str = "all"

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
    location: str = "unknown"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


def classify_path_location(path: Path, unverified_prefixes: Optional[Set[str]] = None) -> str:
    p = str(path).replace("\\", "/").lower()
    if unverified_prefixes:
        for prefix in unverified_prefixes:
            prefix = prefix.strip("/").lower()
            if not prefix:
                continue
            if f"/{prefix}/" in p or p.endswith(f"/{prefix}"):
                if prefix.startswith("wp-content/themes/"):
                    return "unverified theme"
                if prefix.startswith("wp-content/plugins/"):
                    return "unverified plugin"
                if prefix.startswith("wp-content/mu-plugins/"):
                    return "unverified mu-plugin"
                return "unverified extension"
    if "/wp-content/plugins/" in p:
        return "plugin"
    if "/wp-content/mu-plugins/" in p:
        return "mu-plugin"
    if "/wp-content/themes/" in p:
        return "theme"
    if "/wp-content/uploads/" in p:
        return "upload"
    if "/wp-content/languages/" in p:
        return "language-pack"
    if "/wp-content/cache/" in p:
        return "cache"
    if "/wp-admin/" in p or "/wp-includes/" in p:
        return "core"
    if re.search(r"/wp-[^/]+\.php$", p):
        return "core"
    return "unknown"

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
    """Return the full built-in signature database."""
    signatures = [
        Signature("WP001", "FilesMan Backdoor", r"FilesMan", "FilesMan backdoor - common WordPress backdoor", ThreatLevel.CRITICAL, "backdoor", "Remove the infected file or clean the malicious code"),
        Signature("WP002", "Base64 Decode Return", r'"base64_decode"\s*;\s*return', "Obfuscated code using base64_decode with return", ThreatLevel.HIGH, "obfuscation", "Decode and analyze the payload, then remove malicious code"),
        Signature("WP003", "GLOBALS Injection", r';\s*\$GLOBALS', "Suspicious GLOBALS variable access", ThreatLevel.MEDIUM, "injection", "Review code for unauthorized variable injection"),
        Signature("WP004", "Variable Variable", r'<?php\s*\${', "Variable variable syntax - often used in backdoors", ThreatLevel.HIGH, "backdoor", "Remove the malicious code block"),
        Signature("WP005", "Array Assignment Backdoor", r'<?php\s*\$array\s*=\s*array\s*\(', "Suspicious array assignment pattern", ThreatLevel.MEDIUM, "backdoor", "Verify if this is legitimate code or backdoor"),
        Signature("WP006", "Mail Stripslashes", r'mail\s*\(\s*stripslashes\s*\(', "Mail function with stripslashes - spam indicator", ThreatLevel.HIGH, "spam", "Remove spam-sending code"),
        Signature("WP007", "Array Diff Ukey", r'<?php\s*@array_diff_ukey\s*\(', "array_diff_ukey backdoor pattern", ThreatLevel.CRITICAL, "backdoor", "Remove the infected file"),
        Signature("WP008", "Request Chr Injection", r'\$_REQUEST\s*\[\s*chr\s*\(', "REQUEST with chr() - command injection", ThreatLevel.CRITICAL, "injection", "Remove the malicious code"),
        Signature("WP009", "Eval Variable", r'eval\s*\(\s*\${', "Eval with variable - code execution", ThreatLevel.CRITICAL, "backdoor", "Remove the eval statement and analyze payload"),
        Signature("WP010", "Isset Variable Variable", r'isset\s*\(\s*\${', "Isset with variable variable", ThreatLevel.MEDIUM, "suspicious", "Review for malicious intent"),
        Signature("WP011", "PhpReverseProxy", r'PhpReverseProxy', "PHP Reverse Proxy backdoor", ThreatLevel.CRITICAL, "backdoor", "Remove the entire file"),
        Signature("WP012", "Str Rot13", r'str_rot13\s*\(', "ROT13 encoding - often used to hide code", ThreatLevel.MEDIUM, "obfuscation", "Decode and verify content"),
        Signature("WP013", "Set Time Limit Zero", r'@set_time_limit\s*\(\s*0\s*\)', "Removing time limit - common in long-running malware", ThreatLevel.MEDIUM, "suspicious", "Review if legitimate or crypto miner"),
        Signature("WP014", "Sha1 Strripos", r'strripos\s*\(\s*@sha1\s*\(', "SHA1 comparison pattern", ThreatLevel.HIGH, "backdoor", "Remove the authentication bypass code"),
        Signature("WP015", "Assert Function", r'@assert\s*\(', "Assert function - can execute arbitrary code", ThreatLevel.HIGH, "backdoor", "Remove the assert statement"),
        Signature("WP016", "Made in China Link", r'made-in-china\.com', "Suspicious external link", ThreatLevel.LOW, "seo_spam", "Remove the spam link"),
        Signature("WP017", "Curl Exec Trim", r'trim\s*\(\s*curl_exec\s*\(', "Curl execution with trim", ThreatLevel.MEDIUM, "suspicious", "Verify the curl usage is legitimate"),
        Signature("WP018", "Rot13 Obfuscated", r'onfr64_qrpbqr', "ROT13 encoded string (base64_qrpbqr)", ThreatLevel.HIGH, "obfuscation", "Decode and remove malicious code"),
        Signature("WP019", "Obfuscated Function Chain", r"function.?for.?strlen.*?isset", "Obfuscated function pattern - potential malware", ThreatLevel.HIGH, "obfuscation", "Analyze and remove the obfuscated code"),
        Signature("WP020", "Eval Hex Function", r'eval\s*\(\s*function\s*_0x', "Hex-encoded eval function", ThreatLevel.CRITICAL, "backdoor", "Remove the entire malicious block"),
        Signature("WP021", "Base64 Decode Eval", r'eval\s*\(\s*base64_decode\s*\(', "Eval with base64_decode - very common backdoor", ThreatLevel.CRITICAL, "backdoor", "Remove the eval statement and decode payload for analysis"),
        Signature("WP022", "Gzip Uncompress", r'gzuncompress\s*\(\s*base64_decode', "Compressed and encoded payload", ThreatLevel.HIGH, "obfuscation", "Decode and decompress to analyze"),
        Signature("WP023", "Preg Replace Eval", r'preg_replace\s*\([^)]*\/e[^)]*\)', "Preg_replace with /e modifier - code execution", ThreatLevel.HIGH, "injection", "Remove or replace with preg_replace_callback"),
        Signature("WP024", "Create Function", r'create_function\s*\(', "create_function - arbitrary code execution", ThreatLevel.HIGH, "backdoor", "Replace with anonymous function or remove"),
        Signature("WP025", "Shell Exec", r'shell_exec\s*\(', "Shell execution function", ThreatLevel.CRITICAL, "backdoor", "Remove unless legitimately needed"),
        Signature("WP026", "System Call", r'\bsystem\s*\(\s*[^)]{0,500}\)\s*;', "System call - command execution", ThreatLevel.CRITICAL, "backdoor", "Remove unless legitimately needed"),
        Signature("WP027", "Passthru", r'passthru\s*\(', "Passthru - command execution", ThreatLevel.CRITICAL, "backdoor", "Remove unless legitimately needed"),
        Signature("WP028", "Proc Open", r'proc_open\s*\(', "Process opening - command execution", ThreatLevel.CRITICAL, "backdoor", "Remove unless legitimately needed"),
        Signature("WP029", "Pcntl Exec", r'pcntl_exec\s*\(', "Process control execution", ThreatLevel.CRITICAL, "backdoor", "Remove unless legitimately needed"),
        Signature("WP030", "Socket Connect", r'socket_connect\s*\(', "Socket connection - potential C2", ThreatLevel.HIGH, "backdoor", "Verify if legitimate or command & control"),
        Signature("WP031", "Fsockopen", r'fsockopen\s*\(', "File socket open - potential C2", ThreatLevel.MEDIUM, "suspicious", "Verify the destination is legitimate"),
        Signature("WP032", "Curl Init", r'curl_init\s*\(', "Curl initialization", ThreatLevel.LOW, "suspicious", "Verify curl usage is legitimate"),
        Signature("WP033", "Wp Config Get", r'get_currentuserinfo|wp_get_current_user', "WordPress user info access", ThreatLevel.LOW, "suspicious", "Verify in context - could be credential harvester"),
        Signature("WP034", "Admin Email Grabber", r'get_option\s*\(\s*[\'"]admin_email', "Admin email retrieval", ThreatLevel.MEDIUM, "data_theft", "Verify if used for spam or legitimate purpose"),
        Signature("WP035", "Wp Users Query", r'WP_User_Query|get_users', "User query - potential data harvesting", ThreatLevel.MEDIUM, "data_theft", "Verify the purpose of user enumeration"),
        Signature("WP036", "Crypto Miner Pool", r'(\bstratum\+tcp\b|\bcryptonight\b|\brandomx\b|\bethash\b|\bmonero(?:-miner)?\b)', "Cryptocurrency mining pool connection", ThreatLevel.CRITICAL, "crypto_miner", "Remove the miner and check for persistence"),
        Signature("WP037", "Coinhive", r'coinhive|cnv1\.js', "Coinhive crypto miner", ThreatLevel.CRITICAL, "crypto_miner", "Remove Coinhive integration"),
        Signature("WP038", "Jquery Load Suspicious", r'\$\.getScript\s*\([^)]*\.js', "Dynamic script loading", ThreatLevel.MEDIUM, "suspicious", "Verify the script source is legitimate"),
        Signature("WP039", "Document Write", r'document\.write\s*\(', "Document write - potential XSS", ThreatLevel.MEDIUM, "injection", "Review for malicious content injection"),
        Signature("WP040", "FromCharCode", r'fromCharCode\s*\(', "Character code conversion - often obfuscated", ThreatLevel.MEDIUM, "obfuscation", "Decode and verify the actual content"),
        Signature("WP041", "Iframe Inject", r'<iframe[^>]*style\s*=\s*[\'"][^\'"]*display:\s*none', "Hidden iframe - potential malware delivery", ThreatLevel.HIGH, "injection", "Remove the hidden iframe"),
        Signature("WP042", "Script Src External", r'<script[^>]*src\s*=\s*[\'"][^\'"]*(?:pastebin|raw.github|bit.ly)', "External script from suspicious source", ThreatLevel.HIGH, "injection", "Remove the external script reference"),
        Signature("WP043", "Eval Gzip", r'eval\s*\(\s*gzinflate\s*\(\s*base64_decode', "Eval with gzinflate and base64", ThreatLevel.CRITICAL, "backdoor", "Remove and decode payload for analysis"),
        Signature("WP044", "Strtr Base64", r'strtr\s*\(\s*base64_decode', "String translation with base64", ThreatLevel.HIGH, "obfuscation", "Decode and analyze the payload"),
        Signature("WP045", "Pack Base64", r'pack\s*\(\s*[\'"]H[\'"]\s*,\s*base64_decode', "Pack with base64 - heavy obfuscation", ThreatLevel.HIGH, "obfuscation", "Decode and analyze"),
        Signature("WP046", "Call User Func", r'call_user_func\s*\(\s*[\'"]assert', "Call user func with assert", ThreatLevel.CRITICAL, "backdoor", "Remove the malicious call"),
        Signature("WP047", "Array Map Assert", r'array_map\s*\(\s*[\'"]assert', "Array map with assert", ThreatLevel.CRITICAL, "backdoor", "Remove the malicious code"),
        Signature("WP048", "Wp Option Add", r'add_option|update_option.*siteurl', "Site URL modification", ThreatLevel.HIGH, "defacement", "Verify and restore correct URL"),
        Signature("WP049", "Htaccess Modify", r'RewriteRule.*\$', "Suspicious htaccess rewrite rule", ThreatLevel.MEDIUM, "defacement", "Review and clean htaccess"),
        Signature("WP050", "Phar Stream", r'phar://', "Phar stream wrapper - potential RCE", ThreatLevel.HIGH, "injection", "Remove unless legitimately needed"),
        Signature("WP051", "Viagra Cialis", r'(viagra|cialis|pharmacy|pills)', "Pharmaceutical spam keywords", ThreatLevel.LOW, "seo_spam", "Remove spam content"),
        Signature("WP052", "Casino Gambling", r'(casino|poker|blackjack|gambling)', "Gambling spam keywords", ThreatLevel.LOW, "seo_spam", "Remove spam content"),
        Signature("WP053", "Replica Watch", r'(replica|rolex|omega|watches)', "Replica product spam", ThreatLevel.LOW, "seo_spam", "Remove spam content"),
        Signature("WP054", "Cheap Meds", r'(cheap.*meds|prescription.*online)', "Online pharmacy spam", ThreatLevel.LOW, "seo_spam", "Remove spam content"),
        Signature("WP055", "Adult Content", r'(xxx|porn|sex|adult.*content)', "Adult content spam", ThreatLevel.LOW, "seo_spam", "Remove spam content"),
        Signature("WP056", "Backdoor File Name", r'(c9|r57|ws0|b374k|wso)\.php', "Known backdoor filename pattern", ThreatLevel.CRITICAL, "backdoor", "Delete the entire file"),
        Signature("WP057", "Shell File Name", r'(shell|hack|exploit|inject)\.php', "Suspicious filename pattern", ThreatLevel.HIGH, "backdoor", "Review and likely delete"),
        Signature("WP058", "Temp PHP File", r'tmp_[a-z0-9]+\.php', "Temporary PHP file - potential dropped payload", ThreatLevel.MEDIUM, "suspicious", "Review content and delete if malicious"),
        Signature("WP059", "Uploads PHP File", r'wp-content/uploads/[^/]+\.php', "PHP file in uploads directory", ThreatLevel.HIGH, "backdoor", "Delete - PHP should not be in uploads"),
        Signature("WP060", "Cache PHP File", r'wp-content/cache/[^/]+\.php', "PHP file in cache directory", ThreatLevel.MEDIUM, "suspicious", "Review and delete if not legitimate"),
        Signature("WP061", "Hex String", r'0x[0-9a-fA-F]{20,}', "Long hex string - potential obfuscated code", ThreatLevel.MEDIUM, "obfuscation", "Decode and verify content"),
        Signature("WP062", "Chr Concat", r'(chr\s*\(\s*\d+\s*\)\s*\.\s*)+', "Chr() concatenation - string obfuscation", ThreatLevel.HIGH, "obfuscation", "Decode the concatenated string"),
        Signature("WP063", "Ord Chr Mix", r'ord\s*\(\s*chr\s*\(', "Ord/chr manipulation - obfuscation", ThreatLevel.MEDIUM, "obfuscation", "Analyze the actual output"),
        Signature("WP064", "Xor Encryption", r'\^\s*[\'"]', "XOR encryption pattern", ThreatLevel.HIGH, "obfuscation", "Decrypt and analyze payload"),
        Signature("WP065", "Base64 String", r'(?<![A-Za-z0-9+/=])(?=[A-Za-z0-9+/=]*[A-Za-z])(?=[A-Za-z0-9+/=]*\d)(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])', "Long base64 string", ThreatLevel.LOW, "obfuscation", "Decode and verify content"),
        Signature("WP066", "Wp Cron Exploit", r'wp-cron\.php.*\?', "Potential wp-cron exploitation", ThreatLevel.MEDIUM, "suspicious", "Verify cron usage is legitimate"),
        Signature("WP067", "Xmlrpc Exploit", r'xmlrpc\.php.*system\.', "XML-RPC exploitation attempt", ThreatLevel.HIGH, "injection", "Disable xmlrpc.php or block access"),
        Signature("WP068", "Rest Api Abuse", r'wp-json\s*/\s*users', "REST API user enumeration", ThreatLevel.MEDIUM, "data_theft", "Restrict REST API access"),
        Signature("WP069", "Wp Config Backup", r'wp-config\.php\.(bak|old|save|orig)', "WordPress config backup file", ThreatLevel.HIGH, "data_theft", "Delete backup files immediately"),
        Signature("WP070", "Debug Log Enabled", r'WP_DEBUG.*true', "Debug mode enabled in production", ThreatLevel.MEDIUM, "info_leak", "Disable WP_DEBUG in production"),
        Signature("WP071", "Header Location", r'header\s*\(\s*[\'"]Location:', "HTTP redirect header", ThreatLevel.MEDIUM, "redirect", "Verify redirect is legitimate"),
        Signature("WP072", "Js Window Location", r'window\.location\s*=\s*[\'"]', "JavaScript redirect", ThreatLevel.MEDIUM, "redirect", "Verify redirect destination"),
        Signature("WP073", "Meta Refresh", r'<meta[^>]*http-equiv\s*=\s*[\'"]refresh', "Meta refresh redirect", ThreatLevel.MEDIUM, "redirect", "Remove if malicious redirect"),
        Signature("WP074", "Base64 In Cookie", r'\butter_cookie.*base64', "Base64 encoded cookie handling", ThreatLevel.MEDIUM, "suspicious", "Verify cookie handling is safe"),
        Signature("WP075", "Unserialize User Input", r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', "Unserialize with user input - RCE risk", ThreatLevel.CRITICAL, "injection", "Replace with json_decode or validate input"),
        Signature("WP076", "File Get Contents Remote", r'file_get_contents\s*\(\s*http', "Remote file fetching", ThreatLevel.MEDIUM, "suspicious", "Verify the remote source is trusted"),
        Signature("WP077", "Fopen Remote", r'fopen\s*\(\s*http', "Remote file opening", ThreatLevel.MEDIUM, "suspicious", "Verify the remote source is trusted"),
        Signature("WP078", "File Put Contents", r'file_put_contents\s*\([^,]*\$_', "File write with user input", ThreatLevel.HIGH, "injection", "Sanitize input or remove"),
        Signature("WP079", "Unlink Call", r'unlink\s*\(', "File deletion function", ThreatLevel.MEDIUM, "suspicious", "Verify deletion is legitimate"),
        Signature("WP080", "Chmod Call", r'chmod\s*\(', "Permission change function", ThreatLevel.MEDIUM, "suspicious", "Verify permission change is needed"),
        Signature("WP081", "Mysql Connect", r'mysql_connect|mysqli_connect', "Database connection", ThreatLevel.LOW, "suspicious", "Verify database connection is legitimate"),
        Signature("WP082", "Query Execution", r'mysql_query|mysqli_query.*\$_', "Query with user input", ThreatLevel.HIGH, "injection", "Use prepared statements"),
        Signature("WP083", "Wpdb Prepare Missing", r'\$wpdb->query\s*\([^)]*\$_', "WPDB query without prepare", ThreatLevel.HIGH, "injection", "Use $wpdb->prepare()") ,
        Signature("WP084", "Error Suppression", r'@\s*(include|require|eval)', "Error suppression on dangerous functions", ThreatLevel.MEDIUM, "evasion", "Review for malicious intent"),
        Signature("WP085", "Conditional Include", r'if\s*\(\s*!\s*defined\s*\(', "Conditional include pattern", ThreatLevel.LOW, "evasion", "Verify the condition is legitimate"),
        Signature("WP086", "Time Based Execution", r'time\s*\(\s*\)\s*[<>=]', "Time-based condition - potential time bomb", ThreatLevel.MEDIUM, "evasion", "Check for time-based malware"),
        Signature("WP087", "Domain Check", r'\$_SERVER\s*\[\s*[\'"]HTTP_HOST', "Domain checking - potential cloaking", ThreatLevel.MEDIUM, "evasion", "Verify for SEO cloaking"),
        Signature("WP088", "User Agent Check", r'\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT', "User agent checking - potential cloaking", ThreatLevel.MEDIUM, "evasion", "Verify for search engine cloaking"),
        Signature("WP089", "Referrer Check", r'\$_SERVER\s*\[\s*[\'"]HTTP_REFERER', "Referrer checking - potential cloaking", ThreatLevel.LOW, "evasion", "Verify for traffic filtering"),
        Signature("WP090", "IP Address Check", r'\$_SERVER\s*\[\s*[\'"]REMOTE_ADDR', "IP address checking", ThreatLevel.MEDIUM, "evasion", "Verify for access control or cloaking"),
        Signature("WP091", "Lambda Function", r'create_function|lambda\s*function', "Anonymous function creation - code execution", ThreatLevel.HIGH, "backdoor", "Review and remove if malicious"),
        Signature("WP092", "Callback Injection", r'call_user_func_array', "Callback injection potential", ThreatLevel.MEDIUM, "injection", "Verify callbacks are safe"),
        Signature("WP093", "Variable Function", r'\$\{?\w+\}?\s*\(', "Variable function call", ThreatLevel.MEDIUM, "backdoor", "Verify function call is safe"),
        Signature("WP094", "Dynamic Property", r'\$\$\w+|\$\{\$', "Dynamic property access", ThreatLevel.MEDIUM, "injection", "Review for property injection"),
        Signature("WP095", "Include From Variable", r'(include|require)\s*\(\s*\$', "Include from variable", ThreatLevel.HIGH, "backdoor", "Ensure variable is sanitized"),
        Signature("WP096", "Bitcoin Wallet", r'(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}', "Bitcoin wallet address pattern", ThreatLevel.LOW, "crypto_spam", "Remove if spam content"),
        Signature("WP097", "Ethereum Wallet", r'0x[a-fA-F0-9]{40}', "Ethereum wallet address", ThreatLevel.LOW, "crypto_spam", "Remove if spam content"),
        Signature("WP098", "Mining Script", r'(cryptonight|randomx|monero-miner)', "Cryptocurrency mining script", ThreatLevel.CRITICAL, "crypto_miner", "Remove the miner immediately"),
        Signature("WP099", "Suspicious Domain", r'(pastebin\.com|raw.githubusercontent.com|bit.ly|tinyurl)', "Reference to suspicious domain", ThreatLevel.MEDIUM, "suspicious", "Verify external resource is safe"),
        Signature("WP100", "Data URI", r'data:text/html|data:application/javascript', "Data URI - potential XSS vector", ThreatLevel.MEDIUM, "injection", "Review data URI content"),
        Signature("WP101", "Assert Function Generic", r'(?<!@)\bassert\s*\(', "Assert function invocation - potential dynamic code execution", ThreatLevel.HIGH, "backdoor", "Remove or harden assert usage and review caller-controlled input paths"),
        Signature("WP102", "Include From Superglobal", r'(include|require)(?:_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[', "Dynamic include/require from request data", ThreatLevel.CRITICAL, "backdoor", "Remove dynamic include from user input and restore trusted code"),
        Signature("WP103", "Eval Superglobal Input", r'(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[', "Direct execution of user-controlled input", ThreatLevel.CRITICAL, "injection", "Remove runtime execution of request data and patch entry point"),
        Signature("WP104", "Php Input Execution Chain", r'php://input.*\b(eval|assert|create_function)\s*\(', "Raw request body tied to runtime code execution", ThreatLevel.CRITICAL, "backdoor", "Remove request-body execution logic and inspect for follow-on payloads"),
        Signature("WP105", "Decoded Include Require", r'(include|require)(?:_once)?\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(', "Include/require on decoded or inflated payload", ThreatLevel.HIGH, "obfuscation", "Decode payload, verify intent, and remove malicious loader logic"),
        Signature("WP106", "Preg Replace Eval Modifier", r'preg_replace\s*\(\s*[\'"][^\'"]*\/e[^\'"]*[\'"]', "Legacy preg_replace /e modifier - execution primitive", ThreatLevel.HIGH, "injection", "Replace with safe callback and remove executable regex modifiers"),
        Signature("WP107", "Multi Decode Chain", r'(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(', "Layered decode/decompress chain often used for payload obfuscation", ThreatLevel.HIGH, "obfuscation", "Unpack decode chain and review plaintext before execution paths"),
        Signature("WP108", "Chr Array Builder", r'array_map\s*\(\s*[\'"]chr[\'"]\s*,\s*array\s*\(', "Character array builder used to reconstruct hidden payload strings", ThreatLevel.HIGH, "obfuscation", "Reconstruct output string and inspect downstream execution usage"),
        Signature("WP109", "Eval Unescape", r'eval\s*\(\s*unescape\s*\(', "Eval + unescape chain in script content", ThreatLevel.HIGH, "obfuscation", "Decode escaped payload and remove unsafe runtime evaluation"),
        Signature("WP110", "Function Atob Constructor", r'new\s+Function\s*\(\s*atob\s*\(', "Dynamic Function constructor with base64 decoding", ThreatLevel.HIGH, "obfuscation", "Decode function body and remove dynamic code construction"),
        Signature("WP111", "Cron Callback Execution", r'wp_schedule_event\s*\([\s\S]{0,400}?(?:eval|assert|base64_decode|gzinflate)', "Suspicious cron registration with execution/obfuscation callbacks", ThreatLevel.HIGH, "persistence", "Review cron callback implementation and remove unauthorized scheduled payloads"),
        Signature("WP112", "Disable Functions Tampering", r'ini_set\s*\(\s*[\x27\"]disable_functions[\x27\"]\s*,', "Runtime tampering of disabled_functions", ThreatLevel.HIGH, "evasion", "Remove runtime security-control tampering and audit surrounding code paths"),
        Signature("WP113", "Admin User Creation Flow", r'(wp_create_user|wp_insert_user)\s*\([\s\S]{0,220}?(administrator|role\s*=>\s*[\'"]administrator)', "Suspicious WordPress user creation with administrator role assignment", ThreatLevel.HIGH, "privilege_abuse", "Review user-creation logic and remove unauthorized admin account provisioning"),
        Signature("WP114", "Direct Capabilities Escalation", r'(update_user_meta|add_user_meta|update_metadata)\s*\([\s\S]{0,260}?[\'"]wp_capabilities[\'"][\s\S]{0,220}?administrator', "Direct capability metadata write granting administrator privileges", ThreatLevel.CRITICAL, "privilege_abuse", "Revert unauthorized capability writes and audit account/role changes"),
        Signature("WP115", "Usermeta SQL Capabilities Write", r'(INSERT|UPDATE)\s+[\s\S]{0,120}?usermeta[\s\S]{0,220}?wp_capabilities[\s\S]{0,220}?administrator', "Direct SQL write to usermeta capabilities with administrator role", ThreatLevel.CRITICAL, "privilege_abuse", "Remove unauthorized SQL capability updates and rotate compromised credentials"),
        Signature("WP116", "Remote C2 Insecure Endpoint", r'(curl_exec|wp_remote_get|wp_remote_post|file_get_contents)\s*\([\s\S]{0,260}?(?:http://\d{1,3}(?:\.\d{1,3}){3}|https?://[^\'\"\\s]*(?:pastebin|raw\.githubusercontent|transfer\.sh|anonfiles|ngrok|duckdns)\.)', "Network fetch/post to suspicious endpoint or raw IP host", ThreatLevel.HIGH, "c2_exfil", "Verify remote destination ownership and remove unauthorized beacon/exfiltration logic"),
        Signature("WP117", "Encoded Exfil Beacon", r'(base64_encode|json_encode)[\s\S]{0,180}?(wp_remote_post|curl_exec|file_get_contents)\s*\(', "Possible encoded data exfiltration over HTTP request flow", ThreatLevel.HIGH, "c2_exfil", "Inspect payload fields and destination; remove unauthorized outbound data transfer"),
        Signature("WP118", "Cookie Exfiltration Request", r'(\$_COOKIE|\$_SERVER\s*\[\s*[\'"]HTTP_COOKIE[\'"]\s*\])[\s\S]{0,220}?(wp_remote_post|curl_setopt\s*\([\s\S]{0,120}?CURLOPT_POSTFIELDS)', "Cookie/session data tied to outbound HTTP payload", ThreatLevel.CRITICAL, "data_theft", "Remove credential/session exfiltration logic and rotate affected secrets"),
        Signature("WP119", "Dropper Write Uploads PHP", r'file_put_contents\s*\(\s*[^\n]{0,220}?wp-content/(?:uploads|cache|upgrade|tmp)/[^\n]{0,180}?\.php', "Direct write of PHP payload into writable WordPress content paths", ThreatLevel.CRITICAL, "dropper", "Remove dropped payload and block PHP execution in writable content directories"),
        Signature("WP120", "Suspicious Upload Move PHP", r'move_uploaded_file\s*\([\s\S]{0,220}?wp-content/(?:uploads|cache|upgrade|tmp)/[^\n]{0,180}?\.php', "Uploaded file moved as PHP into writable content paths", ThreatLevel.CRITICAL, "dropper", "Remove uploaded PHP payload and enforce extension/MIME validation"),
        Signature("WP121", "Runtime Tmp PHP Writer", r'(tempnam|tmpfile)\s*\([\s\S]{0,180}?file_put_contents\s*\([\s\S]{0,180}?\.php', "Temporary-file workflow writing executable PHP content", ThreatLevel.HIGH, "dropper", "Inspect temp-file write flow and remove unauthorized runtime payload generation"),
        Signature("WP122", "Htaccess Cloaked Redirect", r'RewriteCond\s+%\{HTTP_USER_AGENT\}\s+!?\^?\(\?i:\.\*googlebot\.\*|\.\*bingbot\.\*|\.\*yandex\.\*\)', "User-agent based cloaking in rewrite rules", ThreatLevel.HIGH, "redirect_cloaking", "Remove cloaking rewrite conditions and restore legitimate routing rules"),
        Signature("WP123", "Htaccess Remote Redirect Rule", r'RewriteRule\s+\^.*\$\s+https?://[^\s]+', "RewriteRule issuing full remote redirect", ThreatLevel.HIGH, "redirect", "Review rewrite destination and remove unauthorized external redirects"),
        Signature("WP124", "Conditional Referrer Redirect", r"(HTTP_REFERER|REMOTE_ADDR)[\s\S]{0,200}?(header\s*\(\s*['\"]Location:|window\.location\s*=)", "Referrer/IP-gated redirect logic", ThreatLevel.MEDIUM, "redirect_cloaking", "Review conditional redirect logic and remove traffic-cloaking behavior"),
        Signature("WP125", "JS Payment Form Exfiltration", r'addEventListener\s*\(\s*[\'"]submit[\'"]\s*,[\s\S]{0,260}?(fetch|XMLHttpRequest|navigator\.sendBeacon)[\s\S]{0,260}?(card|cc|cvv|expiry|exp_month|exp_year|payment)', "Potential payment form exfiltration hook in JavaScript", ThreatLevel.CRITICAL, "skimmer", "Remove malicious form hook and review all checkout/payment scripts"),
        Signature("WP126", "JS Keylogger Exfiltration", r'addEventListener\s*\(\s*[\'"](?:keyup|keydown|input)[\'"]\s*,[\s\S]{0,260}?(fetch|XMLHttpRequest|navigator\.sendBeacon)', "Potential key/input capture with outbound exfiltration", ThreatLevel.HIGH, "skimmer", "Remove key capture logic and validate trusted analytics scripts only"),
        Signature("WP127", "Stealth Location Redirect", r'(setTimeout|setInterval)\s*\([\s\S]{0,160}?(window\.location|document\.location)\s*=', "Delayed client-side redirect often used for stealth traffic hijacking", ThreatLevel.MEDIUM, "redirect", "Review delayed redirect logic and remove unauthorized traffic forwarding"),
    ]
    php_signature_ids = {
        "WP004", "WP007", "WP008", "WP009", "WP010", "WP011", "WP014", "WP015",
        "WP020", "WP021", "WP022", "WP023", "WP024", "WP025", "WP026", "WP027",
        "WP028", "WP029", "WP043", "WP046", "WP047", "WP050", "WP058", "WP059",
        "WP060", "WP062", "WP063", "WP075", "WP076", "WP077", "WP078", "WP079",
        "WP080", "WP083", "WP084", "WP091", "WP095", "WP101", "WP102", "WP103",
        "WP104", "WP105", "WP106", "WP107", "WP108", "WP111", "WP112", "WP113",
        "WP114", "WP115", "WP116", "WP117", "WP118", "WP119", "WP120", "WP121",
        "WP124",
    }
    for sig in signatures:
        if sig.id in php_signature_ids:
            sig.target_type = "php"
        elif sig.id in {"WP122", "WP123"}:
            sig.target_type = "htaccess"
        elif sig.id in {"WP125", "WP126", "WP127"}:
            sig.target_type = "js"
    return signatures

# =============================================================================
# SIGNATURE MANAGER
# =============================================================================

class SignatureManager:
    VALID_TARGET_TYPES = {"all", "php", "js", "htaccess"}

    def __init__(self, custom_signature_file: Optional[str] = None):
        self.signatures_by_id: Dict[str, Signature] = {}
        self.custom_file = custom_signature_file

    def load_builtin(self) -> int:
        for sig in get_builtin_signatures():
            self.signatures_by_id[sig.id] = sig
        return len(self.signatures_by_id)

    @staticmethod
    def _parse_threat_level(value: str) -> ThreatLevel:
        normalized = (value or "").strip().lower()
        for level in ThreatLevel:
            if level.value == normalized:
                return level
        raise ValueError(f"invalid threat_level '{value}'")

    @staticmethod
    def _normalize_custom_payload(payload) -> List[dict]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            signatures = payload.get("signatures")
            if isinstance(signatures, list):
                return signatures
        raise ValueError("custom signature file must be a JSON list or {\"signatures\": [...]} object")

    @classmethod
    def _parse_target_type(cls, value: str) -> str:
        normalized = (value or "all").strip().lower()
        if normalized not in cls.VALID_TARGET_TYPES:
            raise ValueError(f"invalid target_type '{value}'")
        return normalized

    def load_custom(self, signature_file: Optional[str] = None) -> int:
        source = signature_file or self.custom_file
        if not source:
            return 0
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"custom signature file not found: {path}")

        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = self._normalize_custom_payload(raw)
        loaded = 0
        skipped = 0
        for idx, entry in enumerate(entries, start=1):
            try:
                if not isinstance(entry, dict):
                    raise ValueError("entry must be an object")
                sig_id = str(entry["id"]).strip()
                name = str(entry["name"]).strip()
                pattern = str(entry["pattern"])
                description = str(entry.get("description", "Custom signature match")).strip()
                category = str(entry.get("category", "custom")).strip()
                remediation = str(entry.get("remediation", "Review and remediate matched code.")).strip()
                threat_level = self._parse_threat_level(str(entry.get("threat_level", "medium")))
                is_regex = bool(entry.get("is_regex", True))
                target_type = self._parse_target_type(str(entry.get("target_type", "all")))
                sig = Signature(
                    id=sig_id,
                    name=name,
                    pattern=pattern,
                    description=description,
                    threat_level=threat_level,
                    category=category,
                    remediation=remediation,
                    is_regex=is_regex,
                    target_type=target_type,
                )
                self.signatures_by_id[sig.id] = sig
                loaded += 1
            except Exception as exc:
                skipped += 1
                logging.warning(f"Skipping custom signature entry #{idx}: {exc}")
        if skipped:
            logging.warning(f"Skipped {skipped} invalid custom signatures from {path}")
        return loaded

    def get_all(self) -> List[Signature]:
        return list(self.signatures_by_id.values())

    def export_to_file(self, output_file: str) -> int:
        path = Path(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for sig in sorted(self.get_all(), key=lambda s: s.id):
            rows.append(
                {
                    "id": sig.id,
                    "name": sig.name,
                    "pattern": sig.pattern,
                    "description": sig.description,
                    "threat_level": sig.threat_level.value,
                    "category": sig.category,
                    "remediation": sig.remediation,
                    "is_regex": sig.is_regex,
                    "target_type": (sig.target_type or "all"),
                }
            )
        path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return len(rows)

# =============================================================================
# FILE SCANNER
# =============================================================================

class FileScanner:
    SCAN_EXTENSIONS = {'.php', '.js', '.html', '.htm', '.css', '.txt', '.md', '.json', '.xml', '.htaccess', '.ini', '.conf'}
    SKIP_DIRS = {'.git', '.svn', '.hg', 'node_modules', '__pycache__', '.idea', '.vscode', '.DS_Store'}
    MAX_MATCHES_PER_SIGNATURE_PER_FILE = 25
    HEURISTIC_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{180,}")
    TARGET_TYPE_RULES: Dict[str, Dict[str, Set[str]]] = {
        "all": {},
        "php": {"suffixes": {".php", ".phtml", ".php5", ".php7", ".inc"}},
        "js": {"suffixes": {".js"}},
        "htaccess": {"names": {".htaccess"}},
    }

    def __init__(self, signatures: List[Signature]):
        self.signatures = signatures
        self.unverified_extension_prefixes: Set[str] = set()
        self.compiled_patterns: List[Tuple[Signature, re.Pattern]] = []
        for sig in signatures:
            try:
                flags = re.MULTILINE | re.IGNORECASE if sig.is_regex else 0
                pattern = re.compile(sig.pattern, flags)
                self.compiled_patterns.append((sig, pattern))
            except re.error as e:
                logging.warning(f"Invalid regex pattern {sig.id}: {e}")

    def should_scan(self, filepath: Path) -> bool:
        """Check if file should be scanned."""
        suffix = filepath.suffix.lower()
        if suffix not in self.SCAN_EXTENSIONS and filepath.name.lower() not in self.SCAN_EXTENSIONS:
            return False
        if '.min.' in filepath.name:
            return False
        skip_patterns = ['wp-tinymce.js', 'tiny_mce.js', 'jquery.js', 'vendor.js']
        if any(pattern in filepath.name.lower() for pattern in skip_patterns):
            return False
        try:
            if filepath.stat().st_size > 2 * 1024 * 1024:  # 2MB limit
                return False
        except OSError:
            return False
        return True

    def _signature_allowed_for_file(self, sig: Signature, filepath: Path) -> bool:
        target_type = (sig.target_type or "all").strip().lower()
        guard = self.TARGET_TYPE_RULES.get(target_type, self.TARGET_TYPE_RULES["all"])
        if not guard:
            return True
        suffixes = guard.get("suffixes", set())
        names = guard.get("names", set())
        if suffixes and filepath.suffix.lower() not in suffixes:
            return False
        if names and filepath.name.lower() not in names:
            return False
        return True

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: Dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return entropy

    @staticmethod
    def _context_for_line(lines: List[str], line_num: int) -> Tuple[str, str]:
        start = max(0, line_num - 4)
        end = min(len(lines), line_num + 3)
        context_before = "\n".join(lines[start:line_num - 1])
        context_after = "\n".join(lines[line_num:end])
        return context_before, context_after

    def _heuristic_findings(self, filepath: Path, content: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        location = classify_path_location(filepath, self.unverified_extension_prefixes)
        lower_path = str(filepath).replace("\\", "/").lower()
        filename = filepath.name.lower()
        # H001: Unexpected PHP in web-accessible uploads/cache paths.
        if filepath.suffix.lower() == ".php" and (
            "/wp-content/uploads/" in lower_path or "/wp-content/cache/" in lower_path
        ):
            findings.append(
                Finding(
                    file_path=str(filepath),
                    line_number=1,
                    signature_id="H001",
                    signature_name="Heuristic: PHP In Uploads/Cache",
                    threat_level=ThreatLevel.HIGH.value,
                    category="heuristic_path",
                    matched_content=str(filepath),
                    context_before="",
                    context_after=lines[0] if lines else "",
                    description="PHP file located in uploads/cache path; this is a common malware drop location.",
                    remediation="Move/inspect the file immediately and block PHP execution in uploads/cache directories.",
                    location=location,
                )
            )

        # H002: Suspicious filename pattern (double extension or hidden dot-php style).
        if re.search(r"\.(php\d?|phtml)\.(jpg|jpeg|png|gif|ico|txt|log)$", filename) or filename.startswith(".") and ".php" in filename:
            findings.append(
                Finding(
                    file_path=str(filepath),
                    line_number=1,
                    signature_id="H002",
                    signature_name="Heuristic: Suspicious PHP Filename",
                    threat_level=ThreatLevel.HIGH.value,
                    category="heuristic_path",
                    matched_content=filename,
                    context_before="",
                    context_after=lines[0] if lines else "",
                    description="Suspicious filename camouflage (double extension or hidden php filename).",
                    remediation="Verify file origin and purpose; quarantine if not part of known application code.",
                    location=location,
                )
            )

        # H003: Dangerous filesystem permissions.
        try:
            mode = filepath.stat().st_mode & 0o777
            if mode & 0o002:
                findings.append(
                    Finding(
                        file_path=str(filepath),
                        line_number=1,
                        signature_id="H003",
                        signature_name="Heuristic: World-Writable File",
                        threat_level=ThreatLevel.MEDIUM.value,
                        category="heuristic_permissions",
                        matched_content=oct(mode),
                        context_before="",
                        context_after=lines[0] if lines else "",
                        description="File is world-writable, which is often abused by webshells and droppers.",
                        remediation="Restrict file permissions (e.g., 0644 for files) and audit recent changes.",
                        location=location,
                    )
                )
        except OSError:
            pass

        # H004: High-entropy long token (possible packed/obfuscated payload).
        for match in self.HEURISTIC_LONG_TOKEN_RE.finditer(content):
            token = match.group(0)
            entropy = self._shannon_entropy(token)
            if entropy < 4.6:
                continue
            line_num = content[:match.start()].count("\n") + 1
            context_before, context_after = self._context_for_line(lines, line_num)
            findings.append(
                Finding(
                    file_path=str(filepath),
                    line_number=line_num,
                    signature_id="H004",
                    signature_name="Heuristic: High-Entropy Token",
                    threat_level=ThreatLevel.MEDIUM.value,
                    category="heuristic_obfuscation",
                    matched_content=token[:200],
                    context_before=context_before,
                    context_after=context_after,
                    description=f"Long high-entropy token detected (entropy {entropy:.2f}), often used in encoded payloads.",
                    remediation="Decode/review token origin and execution path; remove if unrelated to trusted application logic.",
                    location=location,
                )
            )
            break

        return findings

    def scan_file(self, filepath: Path) -> ScanResult:
        start_time = time.monotonic()
        findings: List[Finding] = []
        location = classify_path_location(filepath, self.unverified_extension_prefixes)
        seen_finding_keys: set[tuple[str, int, str]] = set()
        signature_match_counts: Dict[str, int] = {}
        try:
            if not self.should_scan(filepath):
                return ScanResult(file_path=str(filepath), status=ScanStatus.COMPLETED.value, findings=[])
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            lines = content.splitlines()
            line_starts = [0]
            for idx, char in enumerate(content):
                if char == "\n":
                    line_starts.append(idx + 1)
            
            for sig, pattern in self.compiled_patterns:
                if not self._signature_allowed_for_file(sig, filepath):
                    continue
                signature_match_counts.setdefault(sig.id, 0)
                for match in pattern.finditer(content):
                    if signature_match_counts[sig.id] >= self.MAX_MATCHES_PER_SIGNATURE_PER_FILE:
                        break
                    line_num = bisect.bisect_right(line_starts, match.start())
                    matched_text = match.group(0)[:200]
                    dedupe_key = (sig.id, line_num, matched_text)
                    if dedupe_key in seen_finding_keys:
                        continue
                    start = max(0, line_num - 4)
                    end = min(len(lines), line_num + 3)
                    context_before = "\n".join(lines[start:line_num - 1])
                    context_after = "\n".join(lines[line_num:end])
                    findings.append(Finding(file_path=str(filepath), line_number=line_num, signature_id=sig.id, signature_name=sig.name, threat_level=sig.threat_level.value, category=sig.category, matched_content=matched_text, context_before=context_before, context_after=context_after, description=sig.description, remediation=sig.remediation, location=location))
                    seen_finding_keys.add(dedupe_key)
                    signature_match_counts[sig.id] += 1

            findings.extend(self._heuristic_findings(filepath, content, lines))
            
            scan_time = (time.monotonic() - start_time) * 1000
            return ScanResult(file_path=str(filepath), status=ScanStatus.COMPLETED.value, findings=findings, scan_time_ms=scan_time)
        except Exception as e:
            return ScanResult(file_path=str(filepath), status=ScanStatus.ERROR.value, error=str(e))

    def collect_files(self, root_path: Path) -> List[Path]:
        files: List[Path] = []
        for root, dirs, filenames in os.walk(root_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for filename in filenames:
                filepath = Path(root) / filename
                if self.should_scan(filepath):
                    files.append(filepath)
        return files

# =============================================================================
# REPORT GENERATOR
# =============================================================================
class ReportGenerator:
    @staticmethod
    def findings_sorted(results: List[ScanResult]) -> List[Finding]:
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_findings = [f for r in results for f in r.findings]
        all_findings.sort(key=lambda f: (severity_order.get(f.threat_level, 4), f.file_path, f.line_number))
        return all_findings

    @staticmethod
    def generate_json_report(
        results: List[ScanResult],
        stats: ScanStats,
        remediation_audit: Optional[Dict] = None,
    ) -> Dict:
        payload = {
            "generated_at": datetime.now().isoformat(),
            "scan_stats": {
                "total_files": stats.total_files,
                "scanned_files": stats.scanned_files,
                "infected_files": stats.infected_files,
                "total_findings": stats.total_findings,
                "critical": stats.critical,
                "high": stats.high,
                "medium": stats.medium,
                "low": stats.low,
                "scan_duration_seconds": stats.scan_duration_seconds,
            },
            "findings": [
                {
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "signature_id": f.signature_id,
                    "signature_name": f.signature_name,
                    "threat_level": f.threat_level,
                    "category": f.category,
                    "location": f.location,
                    "matched_content": f.matched_content,
                    "description": f.description,
                    "remediation": f.remediation,
                    "timestamp": f.timestamp,
                }
                for f in ReportGenerator.findings_sorted(results)
            ],
        }
        if remediation_audit is not None:
            payload["remediation_audit"] = remediation_audit
        return payload

    @staticmethod
    def generate_html_report(
        results: List[ScanResult],
        stats: ScanStats,
        remediation_audit: Optional[Dict] = None,
    ) -> str:
        findings = ReportGenerator.findings_sorted(results)
        rows = []
        for finding in findings:
            severity_class = f"sev-{finding.threat_level}"
            rows.append(
                "<tr>"
                f"<td class='{severity_class}'>{html.escape(finding.threat_level.upper())}</td>"
                f"<td>{html.escape(finding.file_path)}</td>"
                f"<td>{finding.line_number}</td>"
                f"<td>{html.escape(finding.signature_id)}</td>"
                f"<td>{html.escape(finding.signature_name)}</td>"
                f"<td>{html.escape(finding.category)}</td>"
                f"<td>{html.escape(finding.location)}</td>"
                f"<td>{html.escape(finding.description)}</td>"
                f"<td>{html.escape(finding.remediation)}</td>"
                "</tr>"
            )

        findings_table = "\n".join(rows) if rows else "<tr><td colspan='9'>No threats detected.</td></tr>"
        remediation_html = ""
        if remediation_audit:
            summary = remediation_audit.get("summary", {})
            recent_rows = []
            for row in remediation_audit.get("recent_actions", []):
                recent_rows.append(
                    "<tr>"
                    f"<td>{html.escape(str(row.get('timestamp', '')))}</td>"
                    f"<td>{html.escape(str(row.get('mode', '')))}</td>"
                    f"<td>{html.escape(str(row.get('action', '')))}</td>"
                    f"<td>{html.escape(str(row.get('result', '')))}</td>"
                    f"<td>{html.escape(str(row.get('target', '')))}</td>"
                    "</tr>"
                )
            recent_table = "\n".join(recent_rows) if recent_rows else "<tr><td colspan='5'>No remediation actions recorded.</td></tr>"
            remediation_html = f"""
  <div class="summary">
    <h2>Remediation Audit</h2>
    <div>Total Actions: {summary.get('total_actions', 0)}</div>
    <div>Success: {summary.get('success', 0)} | Failed: {summary.get('failed', 0)} | Cancelled: {summary.get('cancelled', 0)} | No-op: {summary.get('noop', 0)} | Partial: {summary.get('partial', 0)}</div>
  </div>
  <h2>Recent Remediation Actions</h2>
  <table>
    <thead>
      <tr><th>Timestamp</th><th>Mode</th><th>Action</th><th>Result</th><th>Target</th></tr>
    </thead>
    <tbody>
      {recent_table}
    </tbody>
  </table>
"""
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WordPress Malware Scan Report</title>
  <style>
    body {{ font-family: ui-monospace, Menlo, Consolas, monospace; background:#111; color:#eee; margin:0; padding:20px; }}
    h1, h2 {{ margin: 0 0 12px 0; }}
    .meta, .summary {{ margin-bottom: 20px; padding: 12px; border:1px solid #333; background:#181818; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border: 1px solid #333; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background:#222; }}
    .sev-critical {{ color:#ff4d4f; font-weight:700; }}
    .sev-high {{ color:#ff9f1a; font-weight:700; }}
    .sev-medium {{ color:#ffd166; font-weight:700; }}
    .sev-low {{ color:#66d9ef; font-weight:700; }}
  </style>
</head>
<body>
  <h1>WordPress Malware Scan Report</h1>
  <div class="meta">
    <div><strong>Generated:</strong> {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
    <div><strong>Duration:</strong> {stats.scan_duration_seconds:.2f} seconds</div>
  </div>
  <div class="summary">
    <h2>Summary</h2>
    <div>Files Scanned: {stats.scanned_files}</div>
    <div>Infected Files: {stats.infected_files}</div>
    <div>Total Findings: {stats.total_findings}</div>
    <div>Critical: {stats.critical} | High: {stats.high} | Medium: {stats.medium} | Low: {stats.low}</div>
  </div>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>File</th><th>Line</th><th>Signature ID</th>
        <th>Threat</th><th>Category</th><th>Location</th><th>Description</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {findings_table}
    </tbody>
  </table>
{remediation_html}
</body>
</html>"""

    @staticmethod
    def generate_text_report(results: List[ScanResult], stats: ScanStats) -> str:
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
        
        all_findings = ReportGenerator.findings_sorted(results)
        
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


def _resolve_report_output_path(raw_path: str, extension: str, stem_prefix: str) -> Path:
    target = Path(raw_path)
    if target.is_dir() or raw_path.endswith(("/", "\\")):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return target / f"{stem_prefix}-{timestamp}.{extension}"
    return target


def _collect_infected_paths(results: List[ScanResult]) -> List[Path]:
    infected = sorted({Path(r.file_path) for r in results if r.findings})
    return infected


def _confirm_remediation(action: str, count: int, non_interactive_yes: bool) -> bool:
    if non_interactive_yes:
        return True
    if count > 0:
        prompt = f"{action} {count} infected files? Type 'yes' to continue: "
    else:
        prompt = f"{action}? Type 'yes' to continue: "
    reply = input(prompt).strip().lower()
    return reply == "yes"


def _quarantine_path(src: Path, quarantine_dir: Path) -> Tuple[bool, Optional[Path], str]:
    try:
        dst = quarantine_dir / src.name
        if dst.exists():
            stamp = datetime.now().strftime("%Y%m%d%H%M%S")
            dst = quarantine_dir / f"{src.stem}-{stamp}{src.suffix}"
        shutil.move(str(src), str(dst))
        return True, dst, ""
    except Exception as exc:
        return False, None, str(exc)


def _apply_quarantine(paths: List[Path], quarantine_dir: Path) -> Tuple[int, int, List[Dict[str, str]]]:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    moved = 0
    failed = 0
    records: List[Dict[str, str]] = []
    for src in paths:
        ok, dst, error = _quarantine_path(src, quarantine_dir)
        if ok and dst is not None:
            moved += 1
            records.append({"target": str(src), "quarantine_path": str(dst), "result": "success"})
        else:
            failed += 1
            records.append({"target": str(src), "quarantine_path": "", "result": "failed", "error": error})
    return moved, failed, records


def _apply_delete(paths: List[Path]) -> Tuple[int, int]:
    deleted = 0
    failed = 0
    for src in paths:
        try:
            src.unlink(missing_ok=False)
            deleted += 1
        except Exception:
            failed += 1
    return deleted, failed


def _append_audit_log(
    log_path: Path,
    *,
    mode: str,
    action: str,
    target: str,
    result: str,
    details: Optional[Dict] = None,
) -> None:
    record = {
        "timestamp": datetime.now().isoformat(),
        "user": getpass.getuser(),
        "mode": mode,
        "action": action,
        "target": target,
        "result": result,
        "details": details or {},
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _load_audit_summary(log_path: Path, tail: int = 20) -> Dict:
    if not log_path.exists():
        return {
            "summary": {
                "total_actions": 0,
                "success": 0,
                "failed": 0,
                "cancelled": 0,
                "noop": 0,
                "partial": 0,
            },
            "recent_actions": [],
        }
    actions: List[Dict] = []
    try:
        for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                actions.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        pass

    summary = {
        "total_actions": len(actions),
        "success": 0,
        "failed": 0,
        "cancelled": 0,
        "noop": 0,
        "partial": 0,
    }
    for row in actions:
        result = str(row.get("result", "")).lower()
        if result in summary:
            summary[result] += 1
    recent = actions[-tail:]
    return {"summary": summary, "recent_actions": recent}


def _restore_from_audit(
    log_path: Path,
    *,
    target_filter: Optional[Set[str]] = None,
) -> Dict[str, int]:
    if not log_path.exists():
        return {"restored": 0, "failed": 0, "skipped": 0}
    restored = 0
    failed = 0
    skipped = 0
    seen: Set[Tuple[str, str]] = set()
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {"restored": 0, "failed": 0, "skipped": 0}

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(row.get("action", "")).lower() != "quarantine":
            continue
        if str(row.get("result", "")).lower() != "success":
            continue
        target = str(row.get("target", "")).strip()
        quarantine_path = str(row.get("details", {}).get("quarantine_path", "")).strip()
        if not target or not quarantine_path:
            continue
        if target_filter and target not in target_filter:
            continue
        token = (target, quarantine_path)
        if token in seen:
            continue
        seen.add(token)
        src = Path(quarantine_path)
        dst = Path(target)
        if not src.exists():
            skipped += 1
            continue
        if dst.exists():
            skipped += 1
            continue
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            restored += 1
        except Exception:
            failed += 1
    return {"restored": restored, "failed": failed, "skipped": skipped}


def _list_restorable_quarantine_entries(log_path: Path) -> List[Dict[str, str]]:
    if not log_path.exists():
        return []
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    entries: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(row.get("action", "")).lower() != "quarantine":
            continue
        if str(row.get("result", "")).lower() != "success":
            continue
        target = str(row.get("target", "")).strip()
        quarantine_path = str(row.get("details", {}).get("quarantine_path", "")).strip()
        timestamp = str(row.get("timestamp", "")).strip()
        if not target or not quarantine_path:
            continue
        token = (target, quarantine_path)
        if token in seen:
            continue
        seen.add(token)
        qpath = Path(quarantine_path)
        if not qpath.exists():
            continue
        status = "available"
        entries.append(
            {
                "target": target,
                "quarantine_path": quarantine_path,
                "timestamp": timestamp,
                "status": status,
            }
        )
    entries.reverse()
    return entries


def _restore_single_entry(target: str, quarantine_path: str) -> Tuple[bool, str]:
    src = Path(quarantine_path)
    dst = Path(target)
    if not src.exists():
        return False, "quarantine file missing"
    if dst.exists():
        return False, "target already exists"
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return True, ""
    except Exception as exc:
        return False, str(exc)


class WordPressCoreVerifier:
    """Verify local WordPress core files against official release files."""

    def __init__(self, cache_dir: Path, offline: bool = False):
        self.cache_dir = cache_dir
        self.offline = offline
        self.version: Optional[str] = None
        self.reference_root: Optional[Path] = None
        self.core_hashes: Dict[str, str] = {}
        self.modified_core_details: Dict[str, Dict[str, str | int]] = {}

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 128), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def detect_version(scan_root: Path) -> Optional[str]:
        version_file = scan_root / "wp-includes" / "version.php"
        if not version_file.exists():
            return None
        try:
            content = version_file.read_text(encoding="utf-8", errors="ignore")
            match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", content)
            return match.group(1).strip() if match else None
        except OSError:
            return None

    def _reference_dir_for_version(self, version: str) -> Path:
        return self.cache_dir / "wordpress-core" / version / "wordpress"

    def _zip_path_for_version(self, version: str) -> Path:
        return self.cache_dir / "downloads" / f"wordpress-{version}.zip"

    def _ensure_reference_downloaded(self, version: str) -> Path:
        ref_dir = self._reference_dir_for_version(version)
        if ref_dir.exists():
            return ref_dir
        if self.offline:
            raise FileNotFoundError(f"offline mode enabled and no cached WordPress core for version {version}")

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        zip_path = self._zip_path_for_version(version)
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://wordpress.org/wordpress-{version}.zip"
        urllib.request.urlretrieve(url, zip_path)  # nosec: official wordpress release URL

        extract_root = ref_dir.parent
        extract_root.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_root)
        if not ref_dir.exists():
            raise FileNotFoundError(f"downloaded archive for {version} did not contain expected wordpress/ folder")
        return ref_dir

    def prepare(self, scan_root: Path, progress_cb: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        if progress_cb:
            progress_cb("Detecting local WordPress version...")
        version = self.detect_version(scan_root)
        if not version:
            return False, "could not detect local WordPress version"
        self.version = version
        try:
            if progress_cb:
                progress_cb(f"Fetching WordPress core v{version} reference...")
            self.reference_root = self._ensure_reference_downloaded(version)
        except (OSError, urllib.error.URLError, zipfile.BadZipFile) as exc:
            return False, f"failed to prepare official core reference: {exc}"

        if progress_cb:
            progress_cb(f"Hashing official WordPress core v{version}...")
        self.core_hashes.clear()
        for root, _dirs, filenames in os.walk(self.reference_root):
            for filename in filenames:
                ref_path = Path(root) / filename
                rel = str(ref_path.relative_to(self.reference_root)).replace("\\", "/")
                try:
                    self.core_hashes[rel] = self._sha256_file(ref_path)
                except OSError:
                    continue
        return True, f"prepared WordPress core reference for version {version}"

    def filter_identical_core_files(
        self,
        scan_root: Path,
        files: List[Path],
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> Tuple[List[Path], int, Set[Path]]:
        if not self.core_hashes:
            return files, 0, set()
        if progress_cb:
            progress_cb("Checking local files against official WordPress core...")
        kept: List[Path] = []
        skipped = 0
        modified_core: Set[Path] = set()
        self.modified_core_details.clear()
        for path in files:
            try:
                rel = str(path.relative_to(scan_root)).replace("\\", "/")
            except ValueError:
                kept.append(path)
                continue
            expected_hash = self.core_hashes.get(rel)
            if not expected_hash:
                kept.append(path)
                continue
            try:
                local_hash = self._sha256_file(path)
            except OSError:
                kept.append(path)
                continue
            if local_hash == expected_hash:
                skipped += 1
            else:
                kept.append(path)
                modified_core.add(path)
                try:
                    rel = str(path.relative_to(scan_root)).replace("\\", "/")
                    ref_path = self.reference_root / rel if self.reference_root else None
                    if ref_path and ref_path.exists():
                        line_num, local_line, ref_line = self._first_diff_line(path, ref_path)
                        self.modified_core_details[str(path.resolve())] = {
                            "line_number": line_num,
                            "local_line": local_line,
                            "reference_line": ref_line,
                        }
                except Exception:
                    pass
        return kept, skipped, modified_core

    @staticmethod
    def _first_diff_line(local_path: Path, ref_path: Path) -> Tuple[int, str, str]:
        local_lines = local_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        ref_lines = ref_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        max_len = max(len(local_lines), len(ref_lines))
        for idx in range(max_len):
            local_line = local_lines[idx] if idx < len(local_lines) else ""
            ref_line = ref_lines[idx] if idx < len(ref_lines) else ""
            if local_line != ref_line:
                return idx + 1, local_line, ref_line
        return 1, local_lines[0] if local_lines else "", ref_lines[0] if ref_lines else ""


class WordPressExtensionVerifier:
    """Verify plugin/theme files against official package baselines when possible."""

    def __init__(self, cache_dir: Path, offline: bool = False):
        self.cache_dir = cache_dir
        self.offline = offline
        self.reference_hashes: Dict[str, str] = {}
        self.unverifiable_extensions: List[str] = []
        self.unverifiable_prefixes: Set[str] = set()

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 128), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _plugin_version(plugin_root: Path) -> Optional[str]:
        php_candidates: List[Path] = []
        if plugin_root.is_dir():
            for child in plugin_root.iterdir():
                if child.is_file() and child.suffix.lower() == ".php":
                    php_candidates.append(child)
        elif plugin_root.is_file() and plugin_root.suffix.lower() == ".php":
            php_candidates.append(plugin_root)
        for php_file in php_candidates:
            try:
                text = php_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "Plugin Name:" not in text:
                continue
            match = re.search(r"^\s*\*?\s*Version:\s*([^\r\n]+)$", text, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def _theme_version(theme_root: Path) -> Optional[str]:
        style_css = theme_root / "style.css"
        if not style_css.exists():
            return None
        try:
            text = style_css.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        match = re.search(r"^\s*\*?\s*Version:\s*([^\r\n]+)$", text, re.MULTILINE | re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _download_and_extract(self, kind: str, slug: str, version: str) -> Optional[Path]:
        cache_root = self.cache_dir / "extensions" / kind / slug / version
        marker = cache_root / ".ready"
        if marker.exists():
            return cache_root
        if self.offline:
            return None
        url = f"https://downloads.wordpress.org/{kind}/{slug}.{version}.zip"
        zip_path = self.cache_dir / "downloads" / kind / f"{slug}-{version}.zip"
        try:
            zip_path.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(url, zip_path)  # nosec: official wordpress downloads URL
            cache_root.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(cache_root)
            marker.write_text("ok", encoding="utf-8")
            return cache_root
        except Exception:
            return None

    @staticmethod
    def _first_real_subdir(path: Path) -> Optional[Path]:
        dirs = [p for p in path.iterdir() if p.is_dir()]
        if len(dirs) == 1:
            return dirs[0]
        return path if dirs else None

    def _build_reference_for_plugin(self, scan_root: Path, plugin_path: Path) -> None:
        slug = plugin_path.name if plugin_path.is_dir() else plugin_path.stem
        version = self._plugin_version(plugin_path)
        rel_base = f"wp-content/plugins/{slug}"
        if not version:
            self.unverifiable_extensions.append(f"plugin:{slug}")
            self.unverifiable_prefixes.add(rel_base)
            return
        extracted = self._download_and_extract("plugin", slug, version)
        if not extracted:
            self.unverifiable_extensions.append(f"plugin:{slug}@{version}")
            self.unverifiable_prefixes.add(rel_base)
            return
        root = self._first_real_subdir(extracted)
        if root is None:
            self.unverifiable_extensions.append(f"plugin:{slug}@{version}")
            self.unverifiable_prefixes.add(rel_base)
            return
        for walk_root, _dirs, files in os.walk(root):
            for name in files:
                ref_path = Path(walk_root) / name
                rel = ref_path.relative_to(root).as_posix()
                try:
                    self.reference_hashes[f"{rel_base}/{rel}"] = self._sha256_file(ref_path)
                except OSError:
                    continue

    def _build_reference_for_theme(self, theme_path: Path) -> None:
        slug = theme_path.name
        version = self._theme_version(theme_path)
        rel_base = f"wp-content/themes/{slug}"
        if not version:
            self.unverifiable_extensions.append(f"theme:{slug}")
            self.unverifiable_prefixes.add(rel_base)
            return
        extracted = self._download_and_extract("theme", slug, version)
        if not extracted:
            self.unverifiable_extensions.append(f"theme:{slug}@{version}")
            self.unverifiable_prefixes.add(rel_base)
            return
        root = self._first_real_subdir(extracted)
        if root is None:
            self.unverifiable_extensions.append(f"theme:{slug}@{version}")
            self.unverifiable_prefixes.add(rel_base)
            return
        for walk_root, _dirs, files in os.walk(root):
            for name in files:
                ref_path = Path(walk_root) / name
                rel = ref_path.relative_to(root).as_posix()
                try:
                    self.reference_hashes[f"{rel_base}/{rel}"] = self._sha256_file(ref_path)
                except OSError:
                    continue

    def prepare(
        self,
        scan_root: Path,
        core_hashes: Optional[Dict[str, str]] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        self.reference_hashes.clear()
        self.unverifiable_extensions.clear()
        self.unverifiable_prefixes.clear()
        core_hashes = core_hashes or {}
        plugins_dir = scan_root / "wp-content" / "plugins"
        themes_dir = scan_root / "wp-content" / "themes"

        if progress_cb:
            progress_cb("Collecting plugin/theme extensions for baseline verification...")

        plugin_entries: List[Path] = []
        if plugins_dir.exists():
            for entry in plugins_dir.iterdir():
                if entry.name.startswith("."):
                    continue
                rel = entry.relative_to(scan_root).as_posix()
                if entry.is_dir():
                    if any((entry / f).exists() and f"{rel}/{f}" in core_hashes for f in ("hello.php", "akismet.php")):
                        continue
                    plugin_entries.append(entry)
                elif entry.is_file() and entry.suffix.lower() == ".php":
                    if rel in core_hashes:
                        continue
                    plugin_entries.append(entry)

        theme_entries: List[Path] = []
        if themes_dir.exists():
            for entry in themes_dir.iterdir():
                if not entry.is_dir() or entry.name.startswith("."):
                    continue
                style_rel = f"wp-content/themes/{entry.name}/style.css"
                if style_rel in core_hashes:
                    continue
                theme_entries.append(entry)

        for plugin_path in plugin_entries:
            if progress_cb:
                progress_cb(f"Preparing plugin baseline: {plugin_path.name}")
            self._build_reference_for_plugin(scan_root, plugin_path)
        for theme_path in theme_entries:
            if progress_cb:
                progress_cb(f"Preparing theme baseline: {theme_path.name}")
            self._build_reference_for_theme(theme_path)

        return True, (
            f"prepared extension baselines: {len(self.reference_hashes)} files, "
            f"unverifiable extensions: {len(self.unverifiable_extensions)}"
        )

    def filter_identical_extension_files(
        self,
        scan_root: Path,
        files: List[Path],
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> Tuple[List[Path], int]:
        if not self.reference_hashes:
            return files, 0
        if progress_cb:
            progress_cb("Checking local plugin/theme files against extension baselines...")
        kept: List[Path] = []
        skipped = 0
        for path in files:
            try:
                rel = path.relative_to(scan_root).as_posix()
            except ValueError:
                kept.append(path)
                continue
            expected = self.reference_hashes.get(rel)
            if not expected:
                kept.append(path)
                continue
            try:
                local_hash = self._sha256_file(path)
            except OSError:
                kept.append(path)
                continue
            if local_hash == expected:
                skipped += 1
            else:
                kept.append(path)
        return kept, skipped


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"{hours:02d}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"
        
# =============================================================================
# TUI IMPLEMENTATION
# =============================================================================
if TEXTUAL_AVAILABLE:
    class ConfirmActionScreen(ModalScreen):
        BINDINGS = [Binding("escape", "cancel", "Cancel")]

        def __init__(self, action_label: str, target_path: str):
            super().__init__()
            self.action_label = action_label
            self.target_path = target_path

        def compose(self) -> ComposeResult:
            with Container(classes="popup-host"):
                with Container(id="confirm-container", classes="popup"):
                    yield Label(f"[b]{self.action_label}[/b]")
                    yield Label(f"Target file:\n{self.target_path}", classes="wrap")
                    with Horizontal():
                        yield Button("Confirm", id="confirm-action", variant="error")
                        yield Button("Cancel", id="cancel-action")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "confirm-action":
                self.dismiss(True)
            else:
                self.dismiss(False)

        def action_cancel(self) -> None:
            self.dismiss(False)

    class FindingDetailScreen(ModalScreen):
        BINDINGS = [Binding("escape", "dismiss", "Close")]
        def __init__(self, finding: Finding):
            super().__init__()
            self.finding = finding

        def _render_context(self) -> str:
            blocks: List[str] = []
            try:
                lines = Path(self.finding.file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
                if lines:
                    start = max(1, self.finding.line_number - 3)
                    end = min(len(lines), self.finding.line_number + 3)
                    for line_no in range(start, end + 1):
                        marker = ">>" if line_no == self.finding.line_number else "  "
                        source = lines[line_no - 1].replace("\x00", "")
                        blocks.append(f"{marker} {line_no:>6} | {source}")
            except Exception:
                blocks = []

            if not blocks:
                before_lines = self.finding.context_before.splitlines() if self.finding.context_before else []
                after_lines = self.finding.context_after.splitlines() if self.finding.context_after else []
                start_line = max(1, self.finding.line_number - len(before_lines))
                for idx, line in enumerate(before_lines):
                    line_no = start_line + idx
                    blocks.append(f"   {line_no:>6} | {line.replace(chr(0), '')}")
                blocks.append(f">> {self.finding.line_number:>6} | {self.finding.matched_content.strip()[:220].replace(chr(0), '')}")
                for idx, line in enumerate(after_lines, start=1):
                    blocks.append(f"   {self.finding.line_number + idx:>6} | {line.replace(chr(0), '')}")

            if not blocks:
                blocks.append(f">> {self.finding.line_number:>6} | {self.finding.matched_content.strip()[:220]}")
            return "\n".join(blocks)

        def _raw_context_source(self) -> tuple[str, int, int]:
            """Return raw source context, local highlight line, and file start line."""
            try:
                lines = Path(self.finding.file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
                if lines:
                    if self._show_full_source():
                        return "\n".join(lines).replace("\x00", ""), max(1, self.finding.line_number), 1
                    start = max(1, self.finding.line_number - 3)
                    end = min(len(lines), self.finding.line_number + 3)
                    snippet = "\n".join(lines[start - 1:end]).replace("\x00", "")
                    highlight_line = self.finding.line_number - start + 1
                    return snippet, max(1, highlight_line), start
            except Exception:
                pass
            return self.finding.matched_content.strip()[:220], 1, self.finding.line_number

        def _show_full_source(self) -> bool:
            if self.finding.category == "backdoor":
                return True
            if self.finding.signature_id in {"H001", "H002"}:
                return True
            return False

        def compose(self) -> ComposeResult:
            with Container(classes="popup-host"):
                with Container(id="detail-container", classes="popup"):
                    sev_style = SEVERITY_STYLES.get(self.finding.threat_level, "white")
                    yield Label(f"[{sev_style}]● {self.finding.threat_level.upper()}[/]  {self.finding.signature_name}")
                    yield Label(f"[b]File:[/b] {self.finding.file_path}:{self.finding.line_number}")
                    yield Label(f"[b]Signature ID:[/b] {self.finding.signature_id}    [b]Category:[/b] {self.finding.category}")
                    yield Label("[b]Code Context[/b]")
                    with VerticalScroll(classes="code-view"):
                        yield Static(self._render_code_panel())
                    yield Label(f"[b]What it means:[/b] {self.finding.description}", classes="wrap")
                    yield Label(f"[b]How to remove:[/b] {self.finding.remediation}", classes="wrap")

        def _language_for_file(self) -> str:
            ext = Path(self.finding.file_path).suffix.lower()
            lexer = "php"
            if ext in {".js"}:
                lexer = "javascript"
            elif ext in {".css"}:
                lexer = "css"
            elif ext in {".html", ".htm"}:
                lexer = "html"
            elif ext in {".json"}:
                lexer = "json"
            elif ext in {".xml"}:
                lexer = "xml"
            return lexer

        def _guess_lexer(self, code: str) -> str:
            filename = Path(self.finding.file_path).name
            if find_lexer_class is not None:
                try:
                    lexer_cls = find_lexer_class("JavascriptPhpLexer")
                    if lexer_cls is not None:
                        lexer = lexer_cls()
                        aliases = getattr(lexer, "aliases", None)
                        if aliases:
                            return aliases[0]
                except Exception:
                    pass
            if get_lexer_by_name is not None:
                for candidate in ("js+php", "javascript+php", "html+php"):
                    try:
                        lexer = get_lexer_by_name(candidate)
                        aliases = getattr(lexer, "aliases", None)
                        if aliases:
                            return aliases[0]
                    except Exception:
                        continue
            # Prefer php for .php/.phtml files.
            if filename.lower().endswith((".php", ".phtml", ".php5", ".php7", ".inc")):
                return "php"
            if guess_lexer_for_filename is not None:
                try:
                    guessed = guess_lexer_for_filename(filename, code)
                    if getattr(guessed, "aliases", None):
                        return guessed.aliases[0]
                except Exception:
                    pass
            return self._language_for_file()

        def _render_syntax(self):
            context, highlight_line, start_line = self._raw_context_source()
            lexer = self._guess_lexer(context)
            return Syntax(
                context,
                lexer=lexer,
                theme="monokai",
                line_numbers=True,
                start_line=start_line,
                word_wrap=False,
                indent_guides=True,
                highlight_lines={highlight_line},
            )

        def _render_code_panel(self):
            return Panel(self._render_syntax(), title=Path(self.finding.file_path).name)

    class RestoreFromQuarantineScreen(ModalScreen):
        BINDINGS = [
            Binding("escape", "cancel", "Close"),
            Binding("enter", "restore_selected", "Restore"),
            Binding("space", "toggle_selected", "Select"),
            Binding("a", "toggle_select_all", "Select All"),
        ]

        def __init__(self, audit_log_path: Path):
            super().__init__()
            self.audit_log_path = audit_log_path
            self.entries: List[Dict[str, str]] = []
            self.selected_restore_keys: Set[str] = set()

        def compose(self) -> ComposeResult:
            with Container(classes="popup-host"):
                with Container(id="detail-container", classes="popup"):
                    yield Label("[b]Restore From Quarantine[/b]")
                    yield Label("Select a quarantined file and press Restore.", classes="wrap")
                    yield DataTable(id="restore-table")
                    with Horizontal():
                        yield Button("Restore Selected", id="restore-confirm", variant="success")
                        yield Button("Close", id="restore-cancel")

        def on_mount(self) -> None:
            table = self.query_one("#restore-table", DataTable)
            table.add_columns("Sel", "Status", "Quarantined At", "Original File", "Quarantine Path")
            table.cursor_type = "row"
            self._refresh_restore_table(0)

        def _refresh_restore_table(self, keep_row: int) -> None:
            table = self.query_one("#restore-table", DataTable)
            self.entries = _list_restorable_quarantine_entries(self.audit_log_path)
            valid_keys = {f"restore_{idx}" for idx in range(len(self.entries))}
            self.selected_restore_keys &= valid_keys
            table.clear()
            for idx, entry in enumerate(self.entries):
                status = entry.get("status", "")
                status_render = f"[green]{status}[/]" if status == "available" else f"[red]{status}[/]"
                key = f"restore_{idx}"
                mark = "[green]☑[/]" if key in self.selected_restore_keys else "☐"
                table.add_row(
                    mark,
                    status_render,
                    entry.get("timestamp", ""),
                    entry.get("target", ""),
                    entry.get("quarantine_path", ""),
                    key=key,
                )
            if table.row_count > 0:
                table.cursor_coordinate = (min(keep_row, table.row_count - 1), 0)

        def action_cancel(self) -> None:
            self.dismiss(None)

        def action_restore_selected(self) -> None:
            table = self.query_one("#restore-table", DataTable)
            if table.row_count == 0:
                self.dismiss(None)
                return
            if self.selected_restore_keys:
                selected_entries: List[Dict[str, str]] = []
                for key in sorted(self.selected_restore_keys):
                    try:
                        idx = int(key.split("_", 1)[1])
                    except (ValueError, IndexError):
                        continue
                    if 0 <= idx < len(self.entries):
                        selected_entries.append(self.entries[idx])
                self.dismiss(selected_entries if selected_entries else None)
                return
            row_index = table.cursor_coordinate.row
            if row_index < 0 or row_index >= len(self.entries):
                return
            self.dismiss([self.entries[row_index]])

        def action_toggle_selected(self) -> None:
            table = self.query_one("#restore-table", DataTable)
            if table.row_count == 0:
                return
            row_index = table.cursor_coordinate.row
            if row_index < 0 or row_index >= len(self.entries):
                return
            key = f"restore_{row_index}"
            if key in self.selected_restore_keys:
                self.selected_restore_keys.remove(key)
            else:
                self.selected_restore_keys.add(key)
            self._refresh_restore_table(row_index)

        def action_toggle_select_all(self) -> None:
            table = self.query_one("#restore-table", DataTable)
            if table.row_count == 0:
                return
            all_keys = {f"restore_{idx}" for idx in range(len(self.entries))}
            if all_keys.issubset(self.selected_restore_keys):
                self.selected_restore_keys.clear()
            else:
                self.selected_restore_keys = set(all_keys)
            current_row = table.cursor_coordinate.row
            self._refresh_restore_table(current_row)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "restore-confirm":
                self.action_restore_selected()
            else:
                self.dismiss(None)

    class RemotePasswordScreen(ModalScreen):
        BINDINGS = [
            Binding("enter", "submit", "Connect"),
            Binding("escape", "cancel", "Cancel"),
        ]

        def __init__(self, host_target: str):
            super().__init__()
            self.host_target = host_target

        def compose(self) -> ComposeResult:
            with Container(classes="popup-host"):
                with Container(id="confirm-container", classes="popup"):
                    yield Label(f"Enter SSH password for [b]{self.host_target}[/b]")
                    yield Input(placeholder="Password", password=True, id="remote-password-input")
                    with Horizontal():
                        yield Button("Connect", id="remote-password-connect", variant="primary")
                        yield Button("Cancel", id="remote-password-cancel")

        def on_mount(self) -> None:
            self.query_one("#remote-password-input", Input).focus()

        def action_submit(self) -> None:
            password = self.query_one("#remote-password-input", Input).value
            if not password:
                self.app.bell()
                return
            self.dismiss(password)

        def action_cancel(self) -> None:
            self.dismiss(None)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "remote-password-connect":
                self.action_submit()
            else:
                self.dismiss(None)

    class ScannerTUI(App):
        LOGO = """██╗    ██╗██████╗       ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██║    ██║██╔══██╗      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██╔═══╝ ╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝██║           ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝           ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"""
        BINDINGS = [
            ("q", "quit", "Quit"),
            ("d", "show_detail", "Details"),
            ("enter", "show_detail", "Details"),
            ("p", "toggle_pause", "Pause"),
            ("s", "toggle_sort", "Sort"),
            ("j", "cursor_down", "Down"),
            ("k", "cursor_up", "Up"),
            ("r", "stop_restart", "Stop/Restart"),
            ("e", "export_results", "Export"),
            ("space", "toggle_selected", "Select"),
            ("a", "toggle_select_all_visible", "Select All"),
            ("x", "quarantine_selected", "Quarantine"),
            ("delete", "delete_selected", "Delete"),
            ("u", "restore_selected", "Restore"),
        ]
        CSS = """
        #main-container { padding: 1; height: 1fr; }
        #top-row { height: 9; margin: 0; }
        #left-panel { width: 1fr; }
        #logo-panel {
            width: 96;
            padding: 0 1;
        }
        #logo {
            color: #ff4d4f;
            text-style: bold;
        }
        #stats-grid { height: 1; }
        #found-grid { height: 1; margin: 0; }
        #found-label { width: 8; }
        #filter-row { height: 3; margin: 0; }
        #filter-row Button { min-width: 10; margin-right: 1; }
        #action-row { height: 3; margin: 0; }
        #action-row Button { min-width: 0; width: auto; margin-right: 1; padding: 0 1; }
        #scan-state { color: #7f8c8d; margin: 0; }
        #sort-help { color: #7f8c8d; margin: 0 0 1 0; }
        #findings-table { height: 1fr; min-height: 8; }
        .popup-host {
            width: 1fr;
            height: 1fr;
            align: center middle;
        }
        #detail-container {
            width: 90%;
            height: 90%;
            border: heavy #3d4754;
            background: #0f141a;
            padding: 1 2;
        }
        #confirm-container {
            width: 70;
            height: auto;
            max-height: 70%;
            border: heavy #3d4754;
            background: #0f141a;
            padding: 1 2;
        }
        #restore-table {
            height: 1fr;
            min-height: 8;
        }
        .code-view {
            border: round #334;
            background: #151a23;
            padding: 1;
            height: 14;
        }
        .wrap { text-wrap: wrap; }
        """

        total_files = reactive(0)
        files_scanned = reactive(0)
        critical_count = reactive(0)
        high_count = reactive(0)
        medium_count = reactive(0)
        low_count = reactive(0)
        ignored_files = reactive(0)
        sort_label = reactive("severity")
        
        def __init__(
            self,
            scanner: FileScanner,
            scan_path: str,
            threads: int,
            audit_log_path: str = "wp-scan-remediation-audit.jsonl",
            core_verifier: Optional[WordPressCoreVerifier] = None,
            extension_verifier: Optional[WordPressExtensionVerifier] = None,
            remote_config: Optional["RemoteSSHConfig"] = None,
        ):
            super().__init__()
            self.scanner = scanner
            self.scan_path = scan_path
            self.threads = threads
            self.audit_log_path = Path(audit_log_path)
            self.core_verifier = core_verifier
            self.extension_verifier = extension_verifier
            self.remote_config = remote_config
            self.remote_collector: Optional["RemoteSSHCollector"] = None
            self.signature_target_types: Dict[str, str] = {
                sig.id: (sig.target_type or "all") for sig in self.scanner.signatures
            }
            self.findings_map: Dict[str, Finding] = {}
            self.finding_rows: List[Tuple[str, Finding]] = []
            self.visible_rows: List[Tuple[str, Finding]] = []
            self.selected_keys: Set[str] = set()
            self.scan_complete = False
            self.scan_running = False
            self.executor: Optional[ThreadPoolExecutor] = None
            self.scan_worker = None
            self._paused = False
            self._stopping = False
            self._sort_columns = ["severity", "file", "threat"]
            self._sort_index = 0
            self._sorting_active = False
            self._severity_filters = ["all", "critical", "high", "medium", "low"]
            self._severity_filter_index = 0

        def compose(self) -> ComposeResult:
            yield Header()
            with Container(id="main-container"):
                with Horizontal(id="top-row"):
                    with Container(id="left-panel"):
                        with Horizontal(id="stats-grid"):
                            yield Label("Files: 0/0", id="files-stat")
                        with Horizontal(id="found-grid"):
                            yield Label("Found:", id="found-label")
                            yield Label("[#ff4d4f]Critical: 0  [/]", id="critical-stat")
                            yield Label("[#ff9f1a]High: 0  [/]", id="high-stat")
                            yield Label("[#ffd166]Medium: 0  [/]", id="medium-stat")
                            yield Label("[#66d9ef]Low: 0[/]", id="low-stat")
                        with Horizontal(id="filter-row"):
                            yield Button("All", id="filter-all")
                            yield Button("Critical", id="filter-critical")
                            yield Button("High", id="filter-high")
                            yield Button("Medium", id="filter-medium")
                            yield Button("Low", id="filter-low")
                        with Horizontal(id="action-row"):
                            yield Button("Rescan", id="action-rescan")
                            yield Button("Export", id="action-export")
                            yield Button("Quarantine Selected", id="action-quarantine")
                            yield Button("Delete Selected", id="action-delete")
                            yield Button("Restore", id="action-restore")
                    with Container(id="logo-panel"):
                        yield Static(Text(self.LOGO, no_wrap=True, overflow="crop"), id="logo")
                yield Static("Status: RUNNING", id="scan-state")
                yield ProgressBar(total=100, id="progress-bar")
                yield DataTable(id="findings-table")
                yield Static("Sort/Details/Export are enabled after scan completes", id="sort-help")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one(DataTable)
            table.add_columns("Sel", "Level", "File", "Location", "Threat", "Line")
            table.cursor_type = "row"
            table.focus()
            if self.remote_config:
                self._prepare_remote_snapshot()
            else:
                self._start_scan()

        def _prepare_remote_snapshot(self) -> None:
            if not self.remote_config:
                self._start_scan()
                return
            if not self.remote_config.key_file and not self.remote_config.password:
                def _after(password: Optional[str]) -> None:
                    if not password:
                        self.exit()
                        return
                    self.remote_config.password = password
                    self._run_remote_fetch_worker()
                self.push_screen(RemotePasswordScreen(self.remote_config.host_target), _after)
                return
            self._run_remote_fetch_worker()

        def _run_remote_fetch_worker(self) -> None:
            self.query_one("#sort-help", Static).update("Preparing remote SSH snapshot...")
            self._set_status_message("Connecting to remote host...", "cyan")
            self.run_worker(self._fetch_remote_snapshot_worker)

        async def _fetch_remote_snapshot_worker(self) -> None:
            if not self.remote_config:
                self._start_scan()
                return
            collector = RemoteSSHCollector(self.remote_config)
            self.remote_collector = collector
            loop = asyncio.get_running_loop()

            def _progress(message: str) -> None:
                self.call_from_thread(self._set_status_message, message, "cyan")
                self.call_from_thread(setattr, self, "sub_title", message)

            try:
                snapshot_path = await loop.run_in_executor(None, collector.fetch_snapshot, _progress)
            except Exception as exc:
                collector.cleanup()
                self.remote_collector = None
                self._set_status_message(f"Remote fetch failed: {exc}", "red")
                self.query_one("#sort-help", Static).update("Remote fetch failed")
                self.bell()
                return
            self.scan_path = str(snapshot_path)
            self._set_status_message("Remote snapshot ready", "green")
            self._start_scan()

        def _reset_scan_state(self) -> None:
            self.findings_map.clear()
            self.finding_rows.clear()
            self.visible_rows.clear()
            self.selected_keys.clear()
            self.total_files = 0
            self.files_scanned = 0
            self.critical_count = 0
            self.high_count = 0
            self.medium_count = 0
            self.low_count = 0
            self.ignored_files = 0
            self._paused = False
            self._stopping = False
            self._sorting_active = False
            self._sort_index = -1
            self._severity_filter_index = 0
            self.query_one(DataTable).clear()
            self.query_one(ProgressBar).update(progress=0)
            self.query_one("#sort-help", Static).update("Sort/Details/Export are enabled after scan completes")
            self._update_pause_state()
            self._refresh_filter_buttons()

        def _start_scan(self) -> None:
            self._reset_scan_state()
            self.scan_complete = False
            self.scan_running = True
            self.executor = ThreadPoolExecutor(max_workers=self.threads)
            self.sub_title = "Starting scan..."
            self._update_pause_state()
            self.scan_worker = self.run_worker(self._run_scan)

        def _stop_scan(self) -> None:
            self._stopping = True
            self.scan_running = False
            self._paused = False
            self._update_pause_state()
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)
                self.executor = None

        def _severity_markup(self, finding: Finding) -> str:
            color = SEVERITY_STYLES.get(finding.threat_level, "white")
            return f"[{color}]{finding.threat_level.upper()}[/]"

        def _sort_key(self, item: Tuple[str, Finding]) -> Tuple:
            _, finding = item
            key = self._sort_columns[self._sort_index]
            if key == "severity":
                return (SEVERITY_RANK.get(finding.threat_level, 99), finding.file_path, finding.line_number)
            if key == "file":
                return (finding.file_path.lower(), SEVERITY_RANK.get(finding.threat_level, 99), finding.line_number)
            if key == "threat":
                return (finding.signature_name.lower(), finding.file_path.lower(), finding.line_number)
            return (finding.line_number, finding.file_path.lower(), SEVERITY_RANK.get(finding.threat_level, 99))

        def _refresh_table(self) -> None:
            table = self.query_one(DataTable)
            keep_row = table.cursor_coordinate.row if table.row_count > 0 else 0
            keep_key: Optional[str] = None
            if 0 <= keep_row < len(self.visible_rows):
                keep_key = self.visible_rows[keep_row][0]
            table.clear()
            rows = list(self.finding_rows)
            if self._sorting_active:
                rows.sort(key=self._sort_key)
            selected_filter = self._severity_filters[self._severity_filter_index]
            if selected_filter != "all":
                rows = [(k, f) for k, f in rows if f.threat_level == selected_filter]
            self.visible_rows = rows
            for key, finding in self.visible_rows:
                mark = "[green]☑[/]" if key in self.selected_keys else "☐"
                table.add_row(
                    mark,
                    self._severity_markup(finding),
                    Path(finding.file_path).name,
                    finding.location,
                    finding.signature_name,
                    str(finding.line_number),
                    key=key,
                )
            if table.row_count > 0:
                if keep_key is not None:
                    new_index = next((idx for idx, (row_key, _f) in enumerate(self.visible_rows) if row_key == keep_key), None)
                    if new_index is not None:
                        table.cursor_coordinate = (new_index, 0)
                    else:
                        table.cursor_coordinate = (min(keep_row, table.row_count - 1), 0)
                else:
                    table.cursor_coordinate = (min(keep_row, table.row_count - 1), 0)

        def _set_filter(self, filter_name: str) -> None:
            if filter_name not in self._severity_filters:
                return
            self._severity_filter_index = self._severity_filters.index(filter_name)
            self._refresh_filter_buttons()
            sort_name = self._sort_columns[self._sort_index] if self._sorting_active else "append-order"
            self.query_one("#sort-help", Static).update(f"Sort: {sort_name} | Filter: {filter_name} (s=sort, d/enter=details, e=export)")
            self._refresh_table()

        def _refresh_filter_buttons(self) -> None:
            selected = self._severity_filters[self._severity_filter_index]
            for filter_name in self._severity_filters:
                btn = self.query_one(f"#filter-{filter_name}", Button)
                if filter_name == selected:
                    btn.label = f"[b]{filter_name.capitalize()}[/b]"
                    btn.variant = "primary"
                else:
                    btn.label = filter_name.capitalize()
                    btn.variant = "default"

        def _append_finding_row(self, key: str, finding: Finding) -> None:
            if self._severity_filters[self._severity_filter_index] != "all":
                return
            self.visible_rows.append((key, finding))
            table = self.query_one(DataTable)
            mark = "[green]☑[/]" if key in self.selected_keys else "☐"
            table.add_row(
                mark,
                self._severity_markup(finding),
                Path(finding.file_path).name,
                finding.location,
                finding.signature_name,
                str(finding.line_number),
                key=key,
            )

        async def _run_scan(self) -> None:
            loop = asyncio.get_running_loop()
            self.sub_title = "Collecting files..."
            if not self.executor:
                return
            files = await loop.run_in_executor(self.executor, self.scanner.collect_files, Path(self.scan_path))
            core_hashes: Dict[str, str] = {}
            if self.core_verifier:
                def _progress(message: str) -> None:
                    self.call_from_thread(setattr, self, "sub_title", message)
                    self.call_from_thread(self._set_status_message, message)

                ok, msg = await loop.run_in_executor(
                    self.executor,
                    self.core_verifier.prepare,
                    Path(self.scan_path),
                    _progress,
                )
                if ok:
                    files, skipped, modified = await loop.run_in_executor(
                        self.executor,
                        self.core_verifier.filter_identical_core_files,
                        Path(self.scan_path),
                        files,
                        _progress,
                    )
                    self.ignored_files += skipped
                    core_hashes = dict(self.core_verifier.core_hashes)
                    self.sub_title = f"Core baseline active ({self.core_verifier.version}), skipped {skipped} unchanged core files"
                    self._set_status_message("RUNNING", "green")
                else:
                    self.sub_title = f"Core baseline skipped: {msg}"
                    self._set_status_message("RUNNING", "green")
            if self.extension_verifier:
                def _ext_progress(message: str) -> None:
                    self.call_from_thread(setattr, self, "sub_title", message)
                    self.call_from_thread(self._set_status_message, message)
                ok, msg = await loop.run_in_executor(
                    self.executor,
                    self.extension_verifier.prepare,
                    Path(self.scan_path),
                    core_hashes,
                    _ext_progress,
                )
                if ok:
                    files, skipped_ext = await loop.run_in_executor(
                        self.executor,
                        self.extension_verifier.filter_identical_extension_files,
                        Path(self.scan_path),
                        files,
                        _ext_progress,
                    )
                    self.ignored_files += skipped_ext
                    self.scanner.unverified_extension_prefixes = set(self.extension_verifier.unverifiable_prefixes)
                    self.sub_title = f"Extension baseline active, skipped {skipped_ext} unchanged extension files"
                    self._set_status_message("RUNNING", "green")
                else:
                    self.scanner.unverified_extension_prefixes = set()
                    self.sub_title = f"Extension baseline skipped: {msg}"
                    self._set_status_message("RUNNING", "green")
            self.total_files = len(files)
            if not files:
                self.sub_title = "✓ No files to scan."
                self.scan_running = False
                self.scan_complete = True
                return

            self.sub_title = "Scanning..."
            self._set_status_message("RUNNING", "green")
            pending: set[asyncio.Future] = set()
            for file_path in files:
                if not self.executor:
                    break
                future = loop.run_in_executor(self.executor, self.scanner.scan_file, file_path)
                pending.add(future)
            while pending and not self._stopping:
                while self._paused and not self._stopping:
                    self.sub_title = "⏸ PAUSED"
                    await asyncio.sleep(0.1)
                if self._stopping:
                    break
                self.sub_title = "Scanning..."

                done, pending = await asyncio.wait(
                    pending,
                    timeout=0.1,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    continue

                for future in done:
                    result: ScanResult = future.result()
                    self.files_scanned += 1

                    if result.findings:
                        for finding in result.findings:
                            key = f"f_{len(self.findings_map)}"
                            self.findings_map[key] = finding
                            self.finding_rows.append((key, finding))
                            if finding.threat_level == 'critical': self.critical_count += 1
                            elif finding.threat_level == 'high': self.high_count += 1
                            elif finding.threat_level == 'medium': self.medium_count += 1
                            else: self.low_count += 1
                            if not self._sorting_active:
                                self._append_finding_row(key, finding)
                        if self._sorting_active:
                            self._refresh_table()
                await asyncio.sleep(0)

            if self._stopping:
                for task in pending:
                    task.cancel()
                self.sub_title = "■ Scan stopped"
            else:
                self.scan_complete = True
                self.sub_title = "✓ Scan Complete"
                self.query_one("#sort-help", Static).update("Sort: severity | Filter: all (s=sort, d/enter=details, e=export)")
            self.scan_running = False
            self._update_pause_state()
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)
                self.executor = None
        
        def watch_files_scanned(self, val:int): 
            self.query_one("#files-stat").update(f"Files: {val}/{self.total_files} ({self.ignored_files} files ignored)")
            if self.total_files > 0:
                self.query_one(ProgressBar).update(progress=val / self.total_files * 100)
        def watch_ignored_files(self, val:int):
            self.query_one("#files-stat").update(f"Files: {self.files_scanned}/{self.total_files} ({val} files ignored)")
        def watch_critical_count(self, val:int): self.query_one("#critical-stat").update(f"[#ff4d4f]Critical: {val}  [/]")
        def watch_high_count(self, val:int): self.query_one("#high-stat").update(f"[#ff9f1a]High: {val}  [/]")
        def watch_medium_count(self, val:int): self.query_one("#medium-stat").update(f"[#ffd166]Medium: {val}  [/]")
        def watch_low_count(self, val:int): self.query_one("#low-stat").update(f"[#66d9ef]Low: {val}[/]")
        def _update_pause_state(self) -> None:
            if self.scan_running and self._paused:
                state, color = "PAUSED", "yellow"
            elif self.scan_running:
                state, color = "RUNNING", "green"
            elif self.scan_complete:
                state, color = "COMPLETE", "cyan"
            else:
                state, color = "STOPPED", "red"
            self.query_one("#scan-state", Static).update(f"Status: [{color}]{state}[/]")

        def _set_status_message(self, message: str, color: str = "cyan") -> None:
            self.query_one("#scan-state", Static).update(f"Status: [{color}]{message}[/]")

        def action_quit(self) -> None:
            self._stop_scan()
            if self.remote_collector:
                self.remote_collector.cleanup()
            self.exit()
        def action_toggle_pause(self) -> None:
            if not self.scan_running:
                self.bell()
                return
            self._paused = not self._paused
            self._update_pause_state()
        def action_stop_restart(self) -> None:
            if self.scan_running:
                self._stop_scan()
                self.query_one("#sort-help", Static).update("Scan stopped (press r to restart)")
            else:
                self._start_scan()
                self._update_pause_state()
        def action_cursor_down(self) -> None:
            self.query_one(DataTable).action_cursor_down()
        def action_cursor_up(self) -> None:
            self.query_one(DataTable).action_cursor_up()
        def action_toggle_sort(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            if not self.finding_rows:
                self.bell()
                return
            self._sorting_active = True
            self._sort_index = (self._sort_index + 1) % len(self._sort_columns)
            self.sort_label = self._sort_columns[self._sort_index]
            filter_name = self._severity_filters[self._severity_filter_index]
            self.query_one("#sort-help", Static).update(f"Sort: {self.sort_label} | Filter: {filter_name} (s=sort, d/enter=details, e=export)")
            self._refresh_table()

        def action_export_results(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            if not self.finding_rows:
                self.query_one("#sort-help", Static).update("No findings to export")
                self.bell()
                return

            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            json_path = Path(f"wp-scan-findings-{timestamp}.json")
            csv_path = Path(f"wp-scan-findings-{timestamp}.csv")

            rows = []
            for _, finding in self.finding_rows:
                target_type = self.signature_target_types.get(finding.signature_id, "all")
                rows.append(
                    {
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "signature_id": finding.signature_id,
                        "target_type": target_type,
                        "signature_name": finding.signature_name,
                        "threat_level": finding.threat_level,
                        "category": finding.category,
                        "location": finding.location,
                        "matched_content": finding.matched_content,
                        "description": finding.description,
                        "remediation": finding.remediation,
                        "timestamp": finding.timestamp,
                    }
                )

            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump(rows, jf, indent=2)

            with open(csv_path, "w", encoding="utf-8", newline="") as cf:
                writer = csv.DictWriter(cf, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            self.query_one("#sort-help", Static).update(
                f"Exported: {json_path.name}, {csv_path.name}"
            )

        def _selected_finding(self) -> Optional[Finding]:
            table = self.query_one(DataTable)
            if table.row_count == 0:
                return None
            row_index = table.cursor_coordinate.row
            if row_index < 0 or row_index >= len(self.visible_rows):
                return None
            _, finding = self.visible_rows[row_index]
            return finding

        def _drop_file_findings(self, file_path: str) -> None:
            removed = {k for k, f in self.finding_rows if f.file_path == file_path}
            self.selected_keys -= removed
            self.finding_rows = [(k, f) for k, f in self.finding_rows if f.file_path != file_path]
            self.visible_rows = [(k, f) for k, f in self.visible_rows if f.file_path != file_path]
            self.findings_map = {k: f for k, f in self.findings_map.items() if f.file_path != file_path}
            self._refresh_table()

        def _selected_findings(self) -> List[Finding]:
            if self.selected_keys:
                return [f for k, f in self.finding_rows if k in self.selected_keys]
            finding = self._selected_finding()
            return [finding] if finding else []

        def action_toggle_selected(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            table = self.query_one(DataTable)
            if table.row_count == 0:
                self.bell()
                return
            row_index = table.cursor_coordinate.row
            if row_index < 0 or row_index >= len(self.visible_rows):
                self.bell()
                return
            key, _finding = self.visible_rows[row_index]
            if key in self.selected_keys:
                self.selected_keys.remove(key)
            else:
                self.selected_keys.add(key)
            self._refresh_table()

        def action_toggle_select_all_visible(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            keys = {k for k, _ in self.visible_rows}
            if not keys:
                self.bell()
                return
            if keys.issubset(self.selected_keys):
                self.selected_keys -= keys
            else:
                self.selected_keys |= keys
            self._refresh_table()

        def _confirm_and_run(self, action: str, findings: List[Finding]) -> None:
            targets = sorted({f.file_path for f in findings})
            label = f"Quarantine {len(targets)} file(s)?" if action == "quarantine" else f"Delete {len(targets)} file(s)?"
            preview = "\n".join(targets[:8])
            if len(targets) > 8:
                preview += f"\n... and {len(targets) - 8} more"

            def _after(confirm: bool) -> None:
                if not confirm:
                    self.query_one("#sort-help", Static).update(f"{action.capitalize()} cancelled")
                    return
                paths = [Path(p) for p in targets if Path(p).exists()]
                if not paths:
                    self.query_one("#sort-help", Static).update("Selected target files no longer exist")
                    self.bell()
                    return
                if action == "quarantine":
                    moved, failed, records = _apply_quarantine(paths, Path("quarantine"))
                    self.query_one("#sort-help", Static).update(f"Quarantine complete: moved={moved}, failed={failed}")
                    for rec in records:
                        _append_audit_log(
                            self.audit_log_path,
                            mode="tui",
                            action="quarantine",
                            target=rec["target"],
                            result=rec["result"],
                            details={
                                "moved": moved,
                                "failed": failed,
                                "quarantine_path": rec.get("quarantine_path", ""),
                                "error": rec.get("error", ""),
                            },
                        )
                    if moved:
                        for rec in records:
                            if rec.get("result") == "success":
                                self._drop_file_findings(rec["target"])
                else:
                    deleted, failed = _apply_delete(paths)
                    self.query_one("#sort-help", Static).update(f"Delete complete: deleted={deleted}, failed={failed}")
                    result_state = "success" if failed == 0 and deleted > 0 else "partial" if deleted > 0 else "failed"
                    for path in paths:
                        _append_audit_log(
                            self.audit_log_path,
                            mode="tui",
                            action="delete",
                            target=str(path),
                            result=result_state,
                            details={"deleted": deleted, "failed": failed},
                        )
                    if deleted:
                        for path in paths:
                            self._drop_file_findings(str(path))

            self.push_screen(ConfirmActionScreen(label, preview), _after)

        def action_quarantine_selected(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            findings = self._selected_findings()
            if not findings:
                self.bell()
                return
            self._confirm_and_run("quarantine", findings)

        def action_delete_selected(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            findings = self._selected_findings()
            if not findings:
                self.bell()
                return
            self._confirm_and_run("delete", findings)

        def action_restore_selected(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            entries = _list_restorable_quarantine_entries(self.audit_log_path)
            if not entries:
                self.query_one("#sort-help", Static).update("No restorable quarantined files found in audit log")
                self.bell()
                return

            def _after(selection: Optional[List[Dict[str, str]]]) -> None:
                if not selection:
                    self.query_one("#sort-help", Static).update("Restore cancelled")
                    return
                restored = 0
                failed = 0
                for row in selection:
                    target = row.get("target", "")
                    quarantine_path = row.get("quarantine_path", "")
                    ok, error = _restore_single_entry(target, quarantine_path)
                    if ok:
                        restored += 1
                    else:
                        failed += 1
                    _append_audit_log(
                        self.audit_log_path,
                        mode="tui",
                        action="restore",
                        target=target or "*",
                        result="success" if ok else "failed",
                        details={"quarantine_path": quarantine_path, "error": error},
                    )
                self.query_one("#sort-help", Static).update(f"Restore complete: restored={restored}, failed={failed}")
                if failed:
                    self.bell()

            self.push_screen(RestoreFromQuarantineScreen(self.audit_log_path), _after)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = event.button.id or ""
            if button_id == "action-rescan":
                self.action_stop_restart()
                return
            if button_id == "action-export":
                self.action_export_results()
                return
            if button_id == "action-quarantine":
                self.action_quarantine_selected()
                return
            if button_id == "action-delete":
                self.action_delete_selected()
                return
            if button_id == "action-restore":
                self.action_restore_selected()
                return
            if not button_id.startswith("filter-"):
                return
            if not self.scan_complete:
                self.bell()
                return
            filter_name = button_id.replace("filter-", "", 1)
            self._set_filter(filter_name)

        def action_show_detail(self) -> None:
            if not self.scan_complete:
                self.bell()
                return
            table = self.query_one(DataTable)
            if table.row_count == 0:
                self.bell()
                return
            try:
                row_index = table.cursor_coordinate.row
                if row_index < 0:
                    self.bell()
                    return
                if row_index >= len(self.visible_rows):
                    self.bell()
                    return
                _, finding = self.visible_rows[row_index]
                self.push_screen(FindingDetailScreen(finding))
            except Exception:
                self.bell()

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            if not self.scan_complete:
                return
            row_index = event.cursor_row
            if row_index < 0 or row_index >= len(self.visible_rows):
                return
            _, finding = self.visible_rows[row_index]
            self.push_screen(FindingDetailScreen(finding))

# =============================================================================
# REMOTE SSH SNAPSHOT
# =============================================================================

def parse_remote_ssh_target(value: str) -> Tuple[str, str]:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("remote SSH target is empty")
    if raw.startswith("ssh://"):
        parsed = urlparse(raw)
        if not parsed.hostname:
            raise ValueError("remote SSH target must include a host")
        remote_path = parsed.path or "/"
        user = parsed.username
        host = parsed.hostname
        host_target = f"{user}@{host}" if user else host
        return host_target, remote_path
    if ":" not in raw:
        raise ValueError("remote SSH target must be in form user@host:/path or ssh://user@host/path")
    host_target, remote_path = raw.split(":", 1)
    host_target = host_target.strip()
    remote_path = remote_path.strip()
    if not host_target:
        raise ValueError("remote SSH target missing host")
    if not remote_path:
        raise ValueError("remote SSH target missing remote path")
    return host_target, remote_path


@dataclass
class RemoteSSHConfig:
    host_target: str
    remote_path: str
    port: int = 22
    key_file: str = ""
    password: str = ""
    known_hosts: str = ""
    strict_host_key_checking: bool = True


class RemoteSSHCollector:
    def __init__(self, config: RemoteSSHConfig):
        self.config = config
        self.work_dir: Optional[Path] = None

    def _build_ssh_base_command(self) -> List[str]:
        cmd = ["ssh", "-p", str(self.config.port)]
        if self.config.password:
            cmd.extend(
                [
                    "-o",
                    "NumberOfPasswordPrompts=1",
                    "-o",
                    "PreferredAuthentications=password,keyboard-interactive",
                    "-o",
                    "PubkeyAuthentication=no",
                ]
            )
        if self.config.key_file:
            cmd.extend(["-i", self.config.key_file])
        if self.config.strict_host_key_checking:
            cmd.extend(["-o", "StrictHostKeyChecking=yes"])
        else:
            cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
        if self.config.known_hosts:
            cmd.extend(["-o", f"UserKnownHostsFile={self.config.known_hosts}"])
        return cmd

    def _probe_remote_size(self) -> Optional[int]:
        ssh_cmd = self._build_ssh_base_command()
        remote_cmd = f"du -sb {shlex.quote(self.config.remote_path)} | awk '{{print $1}}'"
        env = os.environ.copy()
        if self.config.password:
            if not self.work_dir:
                return None
            askpass_script = self.work_dir / "askpass.sh"
            askpass_script.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$WP_SCANNER_SSH_PASSWORD\"\n",
                encoding="utf-8",
            )
            askpass_script.chmod(0o700)
            env["SSH_ASKPASS"] = str(askpass_script)
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = "wp-scanner:0"
            env["WP_SCANNER_SSH_PASSWORD"] = self.config.password
            cmd = ["setsid"] + ssh_cmd + [self.config.host_target, remote_cmd]
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
        else:
            cmd = ssh_cmd + [self.config.host_target, remote_cmd]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if proc.returncode != 0:
            return None
        out = proc.stdout.decode("utf-8", errors="ignore").strip()
        if not out.isdigit():
            return None
        try:
            value = int(out)
        except ValueError:
            return None
        return value if value > 0 else None

    @staticmethod
    def _format_transfer_progress(transferred: int, total: Optional[int], elapsed: float) -> str:
        mib = transferred / (1024 * 1024)
        rate = (transferred / elapsed) if elapsed > 0 else 0.0
        rate_mib = rate / (1024 * 1024)
        if total and total > 0:
            pct = min(100.0, (transferred / total) * 100.0)
            remaining = max(0, total - transferred)
            eta = (remaining / rate) if rate > 0 else 0
            return f"Fetching remote files... {mib:.1f} MiB / {total/(1024*1024):.1f} MiB ({pct:.1f}%) at {rate_mib:.1f} MiB/s ETA {_format_duration(eta)}"
        return f"Fetching remote files... {mib:.1f} MiB transferred at {rate_mib:.1f} MiB/s"

    def _stream_archive(
        self,
        cmd: List[str],
        archive_path: Path,
        env: Optional[Dict[str, str]] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> Tuple[int, str]:
        chunk_size = 1024 * 128
        transferred = 0
        started = time.time()
        last_update = 0.0
        total_bytes = self._probe_remote_size()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            close_fds=True,
        )
        with open(archive_path, "wb") as out:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read(chunk_size)
                if not chunk:
                    break
                out.write(chunk)
                transferred += len(chunk)
                now = time.time()
                if progress_cb and (now - last_update >= 0.5):
                    progress_cb(self._format_transfer_progress(transferred, total_bytes, max(0.001, now - started)))
                    last_update = now
        stderr_data = b""
        if proc.stderr is not None:
            stderr_data = proc.stderr.read() or b""
        returncode = proc.wait()
        if progress_cb and transferred > 0:
            progress_cb(self._format_transfer_progress(transferred, total_bytes, max(0.001, time.time() - started)))
        return returncode, stderr_data.decode("utf-8", errors="ignore")

    def _run_ssh_with_password(
        self,
        cmd: List[str],
        archive_path: Path,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> Tuple[int, str]:
        if not self.work_dir:
            raise RuntimeError("internal error: remote work_dir not initialized")
        askpass_script = self.work_dir / "askpass.sh"
        askpass_script.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$WP_SCANNER_SSH_PASSWORD\"\n",
            encoding="utf-8",
        )
        askpass_script.chmod(0o700)
        env = os.environ.copy()
        env["SSH_ASKPASS"] = str(askpass_script)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = "wp-scanner:0"
        env["WP_SCANNER_SSH_PASSWORD"] = self.config.password
        full_cmd = ["setsid"] + cmd
        return self._stream_archive(full_cmd, archive_path, env=env, progress_cb=progress_cb)

    @staticmethod
    def _safe_extract_tar(archive: Path, destination: Path) -> None:
        destination = destination.resolve()
        with tarfile.open(archive, "r:*") as tf:
            for member in tf.getmembers():
                member_path = (destination / member.name).resolve()
                if not str(member_path).startswith(str(destination)):
                    raise RuntimeError(f"unsafe path in remote archive: {member.name}")
            tf.extractall(destination)

    def fetch_snapshot(self, progress_cb: Optional[Callable[[str], None]] = None) -> Path:
        if progress_cb:
            progress_cb(f"Connecting to {self.config.host_target} via SSH...")
        self.work_dir = Path(tempfile.mkdtemp(prefix="wp-scanner-remote-"))
        archive_path = self.work_dir / "remote.tar"
        snapshot_dir = self.work_dir / "snapshot"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        ssh_cmd = self._build_ssh_base_command()
        remote_cmd = f"tar -C {shlex.quote(self.config.remote_path)} -cf - ."
        cmd = ssh_cmd + [self.config.host_target, remote_cmd]
        if progress_cb:
            progress_cb(f"Fetching remote files from {self.config.remote_path}...")
        if self.config.password:
            returncode, stderr = self._run_ssh_with_password(cmd, archive_path, progress_cb=progress_cb)
        else:
            returncode, stderr = self._stream_archive(cmd, archive_path, progress_cb=progress_cb)
        if returncode != 0:
            stderr = stderr.strip()
            raise RuntimeError(f"SSH fetch failed: {stderr or f'exit code {returncode}'}")
        try:
            size = archive_path.stat().st_size
        except OSError:
            size = 0
        if size <= 0:
            raise RuntimeError(
                "SSH fetch produced an empty archive. "
                "Verify remote path exists and that the SSH user can read it."
            )
        if progress_cb:
            progress_cb("Extracting remote snapshot...")
        self._safe_extract_tar(archive_path, snapshot_dir)
        return snapshot_dir

    def cleanup(self) -> None:
        if self.work_dir and self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
        self.work_dir = None

# =============================================================================
# MAIN
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="WordPress Malware Scanner")
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')

    general = parser.add_argument_group("General Options")
    general.add_argument('--threads', type=int, default=os.cpu_count(), help='Number of threads')
    general.add_argument('--signatures', default='', help='Path to custom JSON signatures file')
    general.add_argument('--export-signatures', default='', help='Write active signatures to JSON file and exit')
    general.add_argument('--verify-core', action='store_true', help='Pre-verify against official WordPress core and skip unchanged core files')
    general.add_argument('--verify-core-offline', action='store_true', help='Use only cached core baseline data (no network download)')
    general.add_argument('--verify-core-cache', default='.wp-scanner-cache', help='Cache directory for official WordPress core files')
    general.add_argument('--verify-extensions', action='store_true', help='Pre-verify plugins/themes against extension baselines and skip unchanged files')
    general.add_argument('--verify-extensions-offline', action='store_true', help='Use only cached extension baseline data (no network download)')
    remote_group = parser.add_argument_group("Remote Scan Options")
    remote_group.add_argument('--remote-ssh', default='', help='Remote SSH target: user@host:/path or ssh://user@host/path')
    remote_group.add_argument('--remote-port', type=int, default=22, help='SSH port for --remote-ssh')
    remote_group.add_argument('--remote-key', default='', help='SSH private key file for --remote-ssh')
    remote_group.add_argument('--remote-known-hosts', default='', help='Known hosts file path for SSH host key verification')
    remote_group.add_argument('--remote-insecure-host-key', action='store_true', help='Disable SSH host key verification (not recommended)')

    tui_group = parser.add_argument_group("TUI Mode Options")
    tui_group.add_argument('--no-tui', action='store_true', help='Disable TUI and run headless scan')

    headless_report = parser.add_argument_group("Headless Reporting Options (--no-tui)")
    headless_report.add_argument('--report-json', default='', help='Write JSON report to this file path')
    headless_report.add_argument('--report-html', default='', help='Write HTML report to this file path')

    remediation = parser.add_argument_group("Headless Remediation Options (--no-tui)")
    remediation.add_argument('--quarantine', action='store_true', help='Move infected files to quarantine directory after scan')
    remediation.add_argument('--quarantine-dir', default='quarantine', help='Quarantine directory path used with --quarantine')
    remediation.add_argument('--delete', action='store_true', help='Delete infected files after scan')
    remediation.add_argument('--restore', action='store_true', help='Restore files from quarantine using the audit log and exit')
    remediation.add_argument('--yes', action='store_true', help='Skip remediation confirmation prompt for --quarantine/--delete/--restore')
    remediation.add_argument('--audit-log', default='wp-scan-remediation-audit.jsonl', help='Append remediation audit log to this JSONL file')
    args = parser.parse_args()
    selected_actions = sum(bool(x) for x in (args.quarantine, args.delete, args.restore))
    if selected_actions > 1:
        parser.error("--quarantine, --delete and --restore are mutually exclusive")
    if args.remote_ssh and args.restore:
        parser.error("--restore operates on local audit/quarantine files and cannot be combined with --remote-ssh")

    sig_manager = SignatureManager(custom_signature_file=args.signatures or None)
    sig_manager.load_builtin()
    if args.signatures:
        loaded_custom = sig_manager.load_custom()
        print(f"Loaded {loaded_custom} custom signatures from {args.signatures}")
    if args.export_signatures:
        exported = sig_manager.export_to_file(args.export_signatures)
        print(f"Exported {exported} signatures to {args.export_signatures}")
        return

    scan_path = args.path
    remote_collector: Optional[RemoteSSHCollector] = None
    remote_config: Optional[RemoteSSHConfig] = None
    if args.remote_ssh:
        host_target, remote_path = parse_remote_ssh_target(args.remote_ssh)
        remote_config = RemoteSSHConfig(
            host_target=host_target,
            remote_path=remote_path,
            port=args.remote_port,
            key_file=args.remote_key,
            password="",
            known_hosts=args.remote_known_hosts,
            strict_host_key_checking=not args.remote_insecure_host_key,
        )
        if args.no_tui or not TEXTUAL_AVAILABLE:
            if not args.remote_key:
                remote_config.password = getpass.getpass(f"SSH password for {host_target}: ")
            remote_collector = RemoteSSHCollector(remote_config)
            try:
                print(f"Preparing remote snapshot from {host_target}:{remote_path} ...")
                snapshot_path = remote_collector.fetch_snapshot(progress_cb=print)
                scan_path = str(snapshot_path)
                print(f"Remote snapshot ready: {scan_path}")
            except Exception as exc:
                if remote_collector:
                    remote_collector.cleanup()
                print(f"Remote scan preparation failed: {exc}")
                sys.exit(1)

    scanner = FileScanner(sig_manager.get_all())
    verifier = None
    extension_verifier = None
    if args.verify_core:
        verifier = WordPressCoreVerifier(
            cache_dir=Path(args.verify_core_cache),
            offline=args.verify_core_offline,
        )
    if args.verify_extensions:
        extension_verifier = WordPressExtensionVerifier(
            cache_dir=Path(args.verify_core_cache),
            offline=args.verify_extensions_offline,
        )

    if args.no_tui or not TEXTUAL_AVAILABLE:
        if not TEXTUAL_AVAILABLE and not args.no_tui:
            reason = TEXTUAL_IMPORT_ERROR or "missing TUI dependencies"
            print(
                f"TUI unavailable ({reason}). Falling back to headless mode.\n"
                "Install TUI dependencies with: pip install 'wp-scanner[tui]'"
            )
        if args.restore:
            if _confirm_remediation("Restore files from quarantine", 0, args.yes):
                outcome = _restore_from_audit(Path(args.audit_log))
                print(
                    f"Restore complete: restored={outcome['restored']}, "
                    f"failed={outcome['failed']}, skipped={outcome['skipped']}"
                )
                _append_audit_log(
                    Path(args.audit_log),
                    mode="headless",
                    action="restore",
                    target="*",
                    result="success" if outcome["restored"] > 0 and outcome["failed"] == 0 else "partial" if outcome["restored"] > 0 else "failed",
                    details=outcome,
                )
            else:
                print("Restore cancelled.")
                _append_audit_log(
                    Path(args.audit_log),
                    mode="headless",
                    action="restore",
                    target="*",
                    result="cancelled",
                    details={},
                )
            return
        
        print(f"Scanning {scan_path}...")
        start_time = time.time()
        stats = ScanStats()
        results = []
        
        scan_root = Path(scan_path)
        files = scanner.collect_files(scan_root)
        ignored_files = 0
        core_hashes: Dict[str, str] = {}
        if verifier:
            ok, msg = verifier.prepare(scan_root, progress_cb=print)
            if ok:
                files, skipped, modified = verifier.filter_identical_core_files(scan_root, files, progress_cb=print)
                ignored_files += skipped
                core_hashes = dict(verifier.core_hashes)
                print(f"Core baseline active (version {verifier.version}); skipped {skipped} unchanged core files.")
            else:
                print(f"Core baseline skipped: {msg}")
        if extension_verifier:
            ok, msg = extension_verifier.prepare(scan_root, core_hashes=core_hashes, progress_cb=print)
            if ok:
                files, skipped_ext = extension_verifier.filter_identical_extension_files(scan_root, files, progress_cb=print)
                ignored_files += skipped_ext
                scanner.unverified_extension_prefixes = set(extension_verifier.unverifiable_prefixes)
                print(
                    f"Extension baseline active; skipped {skipped_ext} unchanged extension files. "
                    f"Unverifiable extensions: {len(extension_verifier.unverifiable_extensions)}"
                )
            else:
                scanner.unverified_extension_prefixes = set()
                print(f"Extension baseline skipped: {msg}")
        stats.total_files = len(files)
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scanner.scan_file, f): f for f in files}
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                results.append(result)
                stats.scanned_files += 1
                if result.findings:
                    # A file is infected if it has one or more findings.
                    # We use a set to keep track of infected file paths to avoid double counting.
                    infected_paths = {r.file_path for r in results if r.findings}
                    stats.infected_files = len(infected_paths)

                    for finding in result.findings:
                        if finding.threat_level == 'critical': stats.critical += 1
                        elif finding.threat_level == 'high': stats.high += 1
                        elif finding.threat_level == 'medium': stats.medium += 1
                        else: stats.low += 1
                
                progress = (i + 1) / stats.total_files * 100 if stats.total_files > 0 else 0
                elapsed = time.time() - start_time
                processed = i + 1
                rate = processed / elapsed if elapsed > 0 else 0
                remaining = stats.total_files - processed
                eta_seconds = (remaining / rate) if rate > 0 else 0
                sys.stdout.write(
                    f"\rScanning... {progress:.2f}% ({processed}/{stats.total_files}) ({ignored_files} files ignored) "
                    f"ETA: {_format_duration(eta_seconds)}"
                )
                sys.stdout.flush()
        
        end_time = time.time()
        stats.scan_duration_seconds = end_time - start_time
        stats.total_findings = stats.critical + stats.high + stats.medium + stats.low
        print("\nScan complete.")
        
        remediation_audit = _load_audit_summary(Path(args.audit_log))
        report = ReportGenerator.generate_text_report(results, stats)
        print(report)

        if args.report_json:
            json_report = ReportGenerator.generate_json_report(results, stats, remediation_audit=remediation_audit)
            report_path = _resolve_report_output_path(
                args.report_json,
                extension="json",
                stem_prefix="wp-scan-report",
            )
            report_path.write_text(json.dumps(json_report, indent=2), encoding="utf-8")
            print(f"JSON report written: {report_path}")

        if args.report_html:
            html_report = ReportGenerator.generate_html_report(results, stats, remediation_audit=remediation_audit)
            report_path = _resolve_report_output_path(
                args.report_html,
                extension="html",
                stem_prefix="wp-scan-report",
            )
            report_path.write_text(html_report, encoding="utf-8")
            print(f"HTML report written: {report_path}")

        infected_paths = _collect_infected_paths(results)
        if args.quarantine and infected_paths:
            if _confirm_remediation("Quarantine", len(infected_paths), args.yes):
                moved, failed, records = _apply_quarantine(infected_paths, Path(args.quarantine_dir))
                print(f"Quarantine complete: moved={moved}, failed={failed}, dir={Path(args.quarantine_dir)}")
                for rec in records:
                    _append_audit_log(
                        Path(args.audit_log),
                        mode="headless",
                        action="quarantine",
                        target=rec["target"],
                        result=rec["result"],
                        details={
                            "quarantine_dir": str(Path(args.quarantine_dir)),
                            "moved": moved,
                            "failed": failed,
                            "quarantine_path": rec.get("quarantine_path", ""),
                            "error": rec.get("error", ""),
                        },
                    )
            else:
                print("Quarantine cancelled.")
                _append_audit_log(
                    Path(args.audit_log),
                    mode="headless",
                    action="quarantine",
                    target="*",
                    result="cancelled",
                    details={"requested_files": len(infected_paths)},
                )
        elif args.delete and infected_paths:
            if _confirm_remediation("Delete", len(infected_paths), args.yes):
                deleted, failed = _apply_delete(infected_paths)
                print(f"Delete complete: deleted={deleted}, failed={failed}")
                for path in infected_paths:
                    _append_audit_log(
                        Path(args.audit_log),
                        mode="headless",
                        action="delete",
                        target=str(path),
                        result="success" if deleted > 0 and failed == 0 else "partial" if deleted > 0 else "failed",
                        details={"deleted": deleted, "failed": failed},
                    )
            else:
                print("Delete cancelled.")
                _append_audit_log(
                    Path(args.audit_log),
                    mode="headless",
                    action="delete",
                    target="*",
                    result="cancelled",
                    details={"requested_files": len(infected_paths)},
                )
        elif (args.quarantine or args.delete) and not infected_paths:
            print("No infected files to remediate.")
            _append_audit_log(
                Path(args.audit_log),
                mode="headless",
                action="quarantine" if args.quarantine else "delete",
                target="*",
                result="no-op",
                details={"reason": "no infected files"},
            )

    else:
        if args.report_json or args.report_html:
            print(
                "Note: --report-json/--report-html are only written in headless mode. "
                "Use --no-tui, or export from TUI with the Export button / 'e'."
            )
        if args.quarantine or args.delete:
            print("Note: --quarantine/--delete are only available in headless mode (--no-tui).")
        app = ScannerTUI(
            scanner=scanner,
            scan_path=scan_path,
            threads=args.threads,
            audit_log_path=args.audit_log,
            core_verifier=verifier,
            extension_verifier=extension_verifier,
            remote_config=remote_config,
        )
        app.run()
    if remote_collector:
        remote_collector.cleanup()

if __name__ == '__main__':
    main()
