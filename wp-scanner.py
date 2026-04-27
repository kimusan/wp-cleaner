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
import hashlib
import math
import argparse
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

# Version
__version__ = "1.0.0"


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class ThreatLevel(Enum):
    """Severity levels for detected threats."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(Enum):
    """Status for scan operations."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class Signature:
    """Represents a malware signature pattern."""
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
    """Represents a detected threat."""
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
    """Results from scanning a single file."""
    file_path: str
    status: str
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    scan_time_ms: float = 0.0


@dataclass
class ScanStats:
    """Overall scan statistics."""
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
# SIGNATURE DATABASE - Built-in signatures
# =============================================================================

def get_builtin_signatures() -> List[Signature]:
    """Return the built-in signature database."""
    return [
        # Original signatures from wp-cleaner.sh
        Signature("WP001", "FilesMan Backdoor", r"FilesMan",
                  "FilesMan backdoor - common WordPress backdoor",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the infected file or clean the malicious code"),
        Signature("WP002", "Base64 Decode Return", r'"base64_decode"\s*;\s*return',
                  "Obfuscated code using base64_decode with return",
                  ThreatLevel.HIGH, "obfuscation",
                  "Decode and analyze the payload, then remove malicious code"),
        Signature("WP003", "GLOBALS Injection", r';\s*\$GLOBALS',
                  "Suspicious GLOBALS variable access",
                  ThreatLevel.MEDIUM, "injection",
                  "Review code for unauthorized variable injection"),
        Signature("WP004", "Variable Variable", r'<\?php\s*\$\{',
                  "Variable variable syntax - often used in backdoors",
                  ThreatLevel.HIGH, "backdoor",
                  "Remove the malicious code block"),
        Signature("WP005", "Array Assignment Backdoor", r'<\?php\s*\$array\s*=\s*array\s*\(',
                  "Suspicious array assignment pattern",
                  ThreatLevel.MEDIUM, "backdoor",
                  "Verify if this is legitimate code or backdoor"),
        Signature("WP006", "Mail Stripslashes", r'mail\s*\(\s*stripslashes\s*\(',
                  "Mail function with stripslashes - spam indicator",
                  ThreatLevel.HIGH, "spam",
                  "Remove spam-sending code"),
        Signature("WP007", "Array Diff Ukey", r'<\?php\s*@array_diff_ukey\s*\(',
                  "array_diff_ukey backdoor pattern",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the infected file"),
        Signature("WP008", "Request Chr Injection", r'\$_REQUEST\s*\[\s*chr\s*\(',
                  "REQUEST with chr() - command injection",
                  ThreatLevel.CRITICAL, "injection",
                  "Remove the malicious code"),
        Signature("WP009", "Eval Variable", r'eval\s*\(\s*\$\{',
                  "Eval with variable - code execution",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the eval statement and analyze payload"),
        Signature("WP010", "Isset Variable Variable", r'isset\s*\(\s*\$\{',
                  "Isset with variable variable",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Review for malicious intent"),
        Signature("WP011", "PhpReverseProxy", r'PhpReverseProxy',
                  "PHP Reverse Proxy backdoor",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the entire file"),
        Signature("WP012", "Str Rot13", r'str_rot13\s*\(',
                  "ROT13 encoding - often used to hide code",
                  ThreatLevel.MEDIUM, "obfuscation",
                  "Decode and verify content"),
        Signature("WP013", "Set Time Limit Zero", r'@set_time_limit\s*\(\s*0\s*\)',
                  "Removing time limit - common in long-running malware",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Review if legitimate or crypto miner"),
        Signature("WP014", "Sha1 Strripos", r'strripos\s*\(\s*@sha1\s*\(',
                  "SHA1 comparison pattern",
                  ThreatLevel.HIGH, "backdoor",
                  "Remove the authentication bypass code"),
        Signature("WP015", "Assert Function", r'@assert\s*\(',
                  "Assert function - can execute arbitrary code",
                  ThreatLevel.HIGH, "backdoor",
                  "Remove the assert statement"),
        Signature("WP016", "Made in China Link", r'made-in-china\.com',
                  "Suspicious external link",
                  ThreatLevel.LOW, "seo_spam",
                  "Remove the spam link"),
        Signature("WP017", "Curl Exec Trim", r'trim\s*\(\s*curl_exec\s*\(',
                  "Curl execution with trim",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify the curl usage is legitimate"),
        Signature("WP018", "Rot13 Obfuscated", r'onfr64_qrpbqr',
                  "ROT13 encoded string (base64_qrpbqr)",
                  ThreatLevel.HIGH, "obfuscation",
                  "Decode and remove malicious code"),
        Signature("WP019", "Obfuscated Function Chain", r'function.*for.*strlen.*isset',
                  "Obfuscated function pattern",
                  ThreatLevel.HIGH, "obfuscation",
                  "Analyze and remove the obfuscated code"),
        Signature("WP020", "Eval Hex Function", r'eval\s*\(\s*function\s*_0x',
                  "Hex-encoded eval function",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the entire malicious block"),
        # Additional common WordPress malware signatures
        Signature("WP021", "Base64 Decode Eval", r'eval\s*\(\s*base64_decode\s*\(',
                  "Eval with base64_decode - very common backdoor",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the eval statement and decode payload for analysis"),
        Signature("WP022", "Gzip Uncompress", r'gzuncompress\s*\(\s*base64_decode',
                  "Compressed and encoded payload",
                  ThreatLevel.HIGH, "obfuscation",
                  "Decode and decompress to analyze"),
        Signature("WP023", "Preg Replace Eval", r'preg_replace\s*\([^)]*\/e[^)]*\)',
                  "Preg_replace with /e modifier - code execution",
                  ThreatLevel.HIGH, "injection",
                  "Remove or replace with preg_replace_callback"),
        Signature("WP024", "Create Function", r'create_function\s*\(',
                  "create_function - arbitrary code execution",
                  ThreatLevel.HIGH, "backdoor",
                  "Replace with anonymous function or remove"),
        Signature("WP025", "Shell Exec", r'shell_exec\s*\(',
                  "Shell execution function",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove unless legitimately needed"),
        Signature("WP026", "System Call", r'\bsystem\s*\(',
                  "System call - command execution",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove unless legitimately needed"),
        Signature("WP027", "Passthru", r'passthru\s*\(',
                  "Passthru - command execution",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove unless legitimately needed"),
        Signature("WP028", "Proc Open", r'proc_open\s*\(',
                  "Process opening - command execution",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove unless legitimately needed"),
        Signature("WP029", "Pcntl Exec", r'pcntl_exec\s*\(',
                  "Process control execution",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove unless legitimately needed"),
        Signature("WP030", "Socket Connect", r'socket_connect\s*\(',
                  "Socket connection - potential C2",
                  ThreatLevel.HIGH, "backdoor",
                  "Verify if legitimate or command & control"),
        Signature("WP031", "Fsockopen", r'fsockopen\s*\(',
                  "File socket open - potential C2",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify the destination is legitimate"),
        Signature("WP032", "Curl Init", r'curl_init\s*\(',
                  "Curl initialization",
                  ThreatLevel.LOW, "suspicious",
                  "Verify curl usage is legitimate"),
        Signature("WP033", "Wp Config Get", r'get_currentuserinfo|wp_get_current_user',
                  "WordPress user info access",
                  ThreatLevel.LOW, "suspicious",
                  "Verify in context - could be credential harvester"),
        Signature("WP034", "Admin Email Grabber", r'get_option\s*\(\s*[\'"]admin_email',
                  "Admin email retrieval",
                  ThreatLevel.MEDIUM, "data_theft",
                  "Verify if used for spam or legitimate purpose"),
        Signature("WP035", "Wp Users Query", r'WP_User_Query|get_users',
                  "User query - potential data harvesting",
                  ThreatLevel.MEDIUM, "data_theft",
                  "Verify the purpose of user enumeration"),
        Signature("WP036", "Crypto Miner Pool", r'(stratum\+tcp|cryptonight|monero|bitcoin)',
                  "Cryptocurrency mining pool connection",
                  ThreatLevel.CRITICAL, "crypto_miner",
                  "Remove the miner and check for persistence"),
        Signature("WP037", "Coinhive", r'coinhive|cnv1\.js',
                  "Coinhive crypto miner",
                  ThreatLevel.CRITICAL, "crypto_miner",
                  "Remove Coinhive integration"),
        Signature("WP038", "Jquery Load Suspicious", r'\$\.getScript\s*\([^)]*\.js',
                  "Dynamic script loading",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify the script source is legitimate"),
        Signature("WP039", "Document Write", r'document\.write\s*\(',
                  "Document write - potential XSS",
                  ThreatLevel.MEDIUM, "injection",
                  "Review for malicious content injection"),
        Signature("WP040", "FromCharCode", r'fromCharCode\s*\(',
                  "Character code conversion - often obfuscated",
                  ThreatLevel.MEDIUM, "obfuscation",
                  "Decode and verify the actual content"),
        Signature("WP041", "Iframe Inject", r'<iframe[^>]*style\s*=\s*["\'][^"\']*display:\s*none',
                  "Hidden iframe - potential malware delivery",
                  ThreatLevel.HIGH, "injection",
                  "Remove the hidden iframe"),
        Signature("WP042", "Script Src External", r'<script[^>]*src\s*=\s*["\'][^"\']*(?:pastebin|raw\.github|bit\.ly)',
                  "External script from suspicious source",
                  ThreatLevel.HIGH, "injection",
                  "Remove the external script reference"),
        Signature("WP043", "Eval Gzip", r'eval\s*\(\s*gzinflate\s*\(\s*base64_decode',
                  "Eval with gzinflate and base64",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove and decode payload for analysis"),
        Signature("WP044", "Strtr Base64", r'strtr\s*\(\s*base64_decode',
                  "String translation with base64",
                  ThreatLevel.HIGH, "obfuscation",
                  "Decode and analyze the payload"),
        Signature("WP045", "Pack Base64", r'pack\s*\(\s*[\'"]H[\'"]\s*,\s*base64_decode',
                  "Pack with base64 - heavy obfuscation",
                  ThreatLevel.HIGH, "obfuscation",
                  "Decode and analyze"),
        Signature("WP046", "Call User Func", r'call_user_func\s*\(\s*[\'"]assert',
                  "Call user func with assert",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the malicious call"),
        Signature("WP047", "Array Map Assert", r'array_map\s*\(\s*[\'"]assert',
                  "Array map with assert",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Remove the malicious code"),
        Signature("WP048", "Wp Option Add", r'add_option|update_option.*siteurl',
                  "Site URL modification",
                  ThreatLevel.HIGH, "defacement",
                  "Verify and restore correct URL"),
        Signature("WP049", "Htaccess Modify", r'RewriteRule.*\$',
                  "Suspicious htaccess rewrite rule",
                  ThreatLevel.MEDIUM, "defacement",
                  "Review and clean htaccess"),
        Signature("WP050", "Phar Stream", r'phar://',
                  "Phar stream wrapper - potential RCE",
                  ThreatLevel.HIGH, "injection",
                  "Remove unless legitimately needed"),
        # SEO Spam signatures
        Signature("WP051", "Viagra Cialis", r'(viagra|cialis|pharmacy|pills)',
                  "Pharmaceutical spam keywords",
                  ThreatLevel.LOW, "seo_spam",
                  "Remove spam content"),
        Signature("WP052", "Casino Gambling", r'(casino|poker|blackjack|gambling)',
                  "Gambling spam keywords",
                  ThreatLevel.LOW, "seo_spam",
                  "Remove spam content"),
        Signature("WP053", "Replica Watch", r'(replica|rolex|omega|watches)',
                  "Replica product spam",
                  ThreatLevel.LOW, "seo_spam",
                  "Remove spam content"),
        Signature("WP054", "Cheap Meds", r'(cheap.*meds|prescription.*online)',
                  "Online pharmacy spam",
                  ThreatLevel.LOW, "seo_spam",
                  "Remove spam content"),
        Signature("WP055", "Adult Content", r'(xxx|porn|sex|adult.*content)',
                  "Adult content spam",
                  ThreatLevel.LOW, "seo_spam",
                  "Remove spam content"),
        # Suspicious file patterns
        Signature("WP056", "Backdoor File Name", r'(c9|r57|ws0|b374k|wso)\.php',
                  "Known backdoor filename pattern",
                  ThreatLevel.CRITICAL, "backdoor",
                  "Delete the entire file"),
        Signature("WP057", "Shell File Name", r'(shell|hack|exploit|inject)\.php',
                  "Suspicious filename pattern",
                  ThreatLevel.HIGH, "backdoor",
                  "Review and likely delete"),
        Signature("WP058", "Temp PHP File", r'tmp_[a-z0-9]+\.php',
                  "Temporary PHP file - potential dropped payload",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Review content and delete if malicious"),
        Signature("WP059", "Uploads PHP File", r'wp-content/uploads/[^/]+\.php',
                  "PHP file in uploads directory",
                  ThreatLevel.HIGH, "backdoor",
                  "Delete - PHP should not be in uploads"),
        Signature("WP060", "Cache PHP File", r'wp-content/cache/[^/]+\.php',
                  "PHP file in cache directory",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Review and delete if not legitimate"),
        # Additional obfuscation patterns
        Signature("WP061", "Hex String", r'0x[0-9a-fA-F]{20,}',
                  "Long hex string - potential obfuscated code",
                  ThreatLevel.MEDIUM, "obfuscation",
                  "Decode and verify content"),
        Signature("WP062", "Chr Concat", r'(chr\s*\(\s*\d+\s*\)\s*\.\s*)+',
                  "Chr() concatenation - string obfuscation",
                  ThreatLevel.HIGH, "obfuscation",
                  "Decode the concatenated string"),
        Signature("WP063", "Ord Chr Mix", r'ord\s*\(\s*chr\s*\(',
                  "Ord/chr manipulation - obfuscation",
                  ThreatLevel.MEDIUM, "obfuscation",
                  "Analyze the actual output"),
        Signature("WP064", "Xor Encryption", r'\^\s*[\'"]',
                  "XOR encryption pattern",
                  ThreatLevel.HIGH, "obfuscation",
                  "Decrypt and analyze payload"),
        Signature("WP065", "Base64 String", r'[A-Za-z0-9+/]{50,}={0,2}',
                  "Long base64 string",
                  ThreatLevel.LOW, "obfuscation",
                  "Decode and verify content"),
        # WordPress specific attacks
        Signature("WP066", "Wp Cron Exploit", r'wp-cron\.php.*\?',
                  "Potential wp-cron exploitation",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify cron usage is legitimate"),
        Signature("WP067", "Xmlrpc Exploit", r'xmlrpc\.php.*system\.',
                  "XML-RPC exploitation attempt",
                  ThreatLevel.HIGH, "injection",
                  "Disable xmlrpc.php or block access"),
        Signature("WP068", "Rest Api Abuse", r'wp-json\s*/\s*users',
                  "REST API user enumeration",
                  ThreatLevel.MEDIUM, "data_theft",
                  "Restrict REST API access"),
        Signature("WP069", "Wp Config Backup", r'wp-config\.php\.(bak|old|save|orig)',
                  "WordPress config backup file",
                  ThreatLevel.HIGH, "data_theft",
                  "Delete backup files immediately"),
        Signature("WP070", "Debug Log Enabled", r'WP_DEBUG.*true',
                  "Debug mode enabled in production",
                  ThreatLevel.MEDIUM, "info_leak",
                  "Disable WP_DEBUG in production"),
        # Malicious redirects
        Signature("WP071", "Header Location", r'header\s*\(\s*[\'"]Location:',
                  "HTTP redirect header",
                  ThreatLevel.MEDIUM, "redirect",
                  "Verify redirect is legitimate"),
        Signature("WP072", "Js Window Location", r'window\.location\s*=\s*[\'"]',
                  "JavaScript redirect",
                  ThreatLevel.MEDIUM, "redirect",
                  "Verify redirect destination"),
        Signature("WP073", "Meta Refresh", r'<meta[^>]*http-equiv\s*=\s*[\'"]refresh',
                  "Meta refresh redirect",
                  ThreatLevel.MEDIUM, "redirect",
                  "Remove if malicious redirect"),
        Signature("WP074", "Base64 In Cookie", r'\$_COOKIE.*base64',
                  "Base64 encoded cookie handling",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify cookie handling is safe"),
        Signature("WP075", "Unserialize User Input", r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                  "Unserialize with user input - RCE risk",
                  ThreatLevel.CRITICAL, "injection",
                  "Replace with json_decode or validate input"),
        # File operations
        Signature("WP076", "File Get Contents Remote", r'file_get_contents\s*\(\s*http',
                  "Remote file fetching",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify the remote source is trusted"),
        Signature("WP077", "Fopen Remote", r'fopen\s*\(\s*http',
                  "Remote file opening",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify the remote source is trusted"),
        Signature("WP078", "File Put Contents", r'file_put_contents\s*\([^,]*\$_',
                  "File write with user input",
                  ThreatLevel.HIGH, "injection",
                  "Sanitize input or remove"),
        Signature("WP079", "Unlink Call", r'unlink\s*\(',
                  "File deletion function",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify deletion is legitimate"),
        Signature("WP080", "Chmod Call", r'chmod\s*\(',
                  "Permission change function",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify permission change is needed"),
        # Database related
        Signature("WP081", "Mysql Connect", r'mysql_connect|mysqli_connect',
                  "Database connection",
                  ThreatLevel.LOW, "suspicious",
                  "Verify database connection is legitimate"),
        Signature("WP082", "Query Execution", r'mysql_query|mysqli_query.*\$_',
                  "Query with user input",
                  ThreatLevel.HIGH, "injection",
                  "Use prepared statements"),
        Signature("WP083", "Wpdb Prepare Missing", r'\$wpdb->query\s*\([^)]*\$_',
                  "WPDB query without prepare",
                  ThreatLevel.HIGH, "injection",
                  "Use $wpdb->prepare()"),
        # Evasion techniques
        Signature("WP084", "Error Suppression", r'@\s*(include|require|eval)',
                  "Error suppression on dangerous functions",
                  ThreatLevel.MEDIUM, "evasion",
                  "Review for malicious intent"),
        Signature("WP085", "Conditional Include", r'if\s*\(\s*!\s*defined\s*\(',
                  "Conditional include pattern",
                  ThreatLevel.LOW, "evasion",
                  "Verify the condition is legitimate"),
        Signature("WP086", "Time Based Execution", r'time\s*\(\s*\)\s*[<>=]',
                  "Time-based condition - potential time bomb",
                  ThreatLevel.MEDIUM, "evasion",
                  "Check for time-based malware"),
        Signature("WP087", "Domain Check", r'\$_SERVER\s*\[\s*[\'"]HTTP_HOST',
                  "Domain checking - potential cloaking",
                  ThreatLevel.MEDIUM, "evasion",
                  "Verify for SEO cloaking"),
        Signature("WP088", "User Agent Check", r'\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT',
                  "User agent checking - potential cloaking",
                  ThreatLevel.MEDIUM, "evasion",
                  "Verify for search engine cloaking"),
        Signature("WP089", "Referrer Check", r'\$_SERVER\s*\[\s*[\'"]HTTP_REFERER',
                  "Referrer checking - potential cloaking",
                  ThreatLevel.LOW, "evasion",
                  "Verify for traffic filtering"),
        Signature("WP090", "IP Address Check", r'\$_SERVER\s*\[\s*[\'"]REMOTE_ADDR',
                  "IP address checking",
                  ThreatLevel.MEDIUM, "evasion",
                  "Verify for access control or cloaking"),
        # Additional backdoor patterns
        Signature("WP091", "Lambda Function", r'create_function|lambda\s*function',
                  "Anonymous function creation - code execution",
                  ThreatLevel.HIGH, "backdoor",
                  "Review and remove if malicious"),
        Signature("WP092", "Callback Injection", r'call_user_func_array',
                  "Callback injection potential",
                  ThreatLevel.MEDIUM, "injection",
                  "Verify callbacks are safe"),
        Signature("WP093", "Variable Function", r'\$\{?\w+\}?\s*\(',
                  "Variable function call",
                  ThreatLevel.MEDIUM, "backdoor",
                  "Verify function call is safe"),
        Signature("WP094", "Dynamic Property", r'\$\$\w+|\$\{\$',
                  "Dynamic property access",
                  ThreatLevel.MEDIUM, "injection",
                  "Review for property injection"),
        Signature("WP095", "Include From Variable", r'(include|require)\s*\(\s*\$',
                  "Include from variable",
                  ThreatLevel.HIGH, "backdoor",
                  "Ensure variable is sanitized"),
        # Crypto and blockchain spam
        Signature("WP096", "Bitcoin Wallet", r'(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}',
                  "Bitcoin wallet address pattern",
                  ThreatLevel.LOW, "crypto_spam",
                  "Remove if spam content"),
        Signature("WP097", "Ethereum Wallet", r'0x[a-fA-F0-9]{40}',
                  "Ethereum wallet address",
                  ThreatLevel.LOW, "crypto_spam",
                  "Remove if spam content"),
        Signature("WP098", "Mining Script", r'(cryptonight|randomx|monero-miner)',
                  "Cryptocurrency mining script",
                  ThreatLevel.CRITICAL, "crypto_miner",
                  "Remove the miner immediately"),
        # Suspicious external resources
        Signature("WP099", "Suspicious Domain", r'(pastebin\.com|raw\.githubusercontent\.com|bit\.ly|tinyurl)',
                  "Reference to suspicious domain",
                  ThreatLevel.MEDIUM, "suspicious",
                  "Verify external resource is safe"),
        Signature("WP100", "Data URI", r'data:text/html|data:application/javascript',
                  "Data URI - potential XSS vector",
                  ThreatLevel.MEDIUM, "injection",
                  "Review data URI content"),
    ]


# =============================================================================
# SIGNATURE MANAGER
# =============================================================================

class SignatureManager:
    """Manages malware signatures - loading, merging, and updating."""
    
    GITHUB_SIGNATURES_URL = (
        "https://raw.githubusercontent.com/kimusan/wp-cleaner/master/signatures.json"
    )
    
    def __init__(self, custom_signature_file: Optional[str] = None):
        self.signatures: List[Signature] = []
        self.signatures_by_id: Dict[str, Signature] = {}
        self.custom_file = custom_signature_file
        
    def load_builtin(self) -> int:
        """Load built-in signatures."""
        self.signatures = get_builtin_signatures()
        self.signatures_by_id = {s.id: s for s in self.signatures}
        return len(self.signatures)
    
    def load_custom(self, filepath: str) -> int:
        """Load custom signatures from JSON file."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            count = 0
            for sig_data in data.get('signatures', []):
                sig = Signature(
                    id=sig_data['id'],
                    name=sig_data['name'],
                    pattern=sig_data['pattern'],
                    description=sig_data['description'],
                    threat_level=ThreatLevel(sig_data['threat_level']),
                    category=sig_data['category'],
                    remediation=sig_data['remediation'],
                    is_regex=sig_data.get('is_regex', True)
                )
                # Override existing or add new
                if sig.id in self.signatures_by_id:
                    self.signatures_by_id[sig.id] = sig
                else:
                    self.signatures.append(sig)
                    self.signatures_by_id[sig.id] = sig
                count += 1
            return count
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.warning(f"Could not load custom signatures: {e}")
            return 0
    
    def fetch_remote(self) -> int:
        """Fetch latest signatures from GitHub."""
        try:
            import urllib.request
            with urllib.request.urlopen(self.GITHUB_SIGNATURES_URL, timeout=10) as response:
                data = json.loads(response.read().decode())
            
            count = 0
            for sig_data in data.get('signatures', []):
                sig = Signature(
                    id=sig_data['id'],
                    name=sig_data['name'],
                    pattern=sig_data['pattern'],
                    description=sig_data['description'],
                    threat_level=ThreatLevel(sig_data['threat_level']),
                    category=sig_data['category'],
                    remediation=sig_data['remediation'],
                    is_regex=sig_data.get('is_regex', True)
                )
                if sig.id not in self.signatures_by_id:
                    self.signatures.append(sig)
                    self.signatures_by_id[sig.id] = sig
                    count += 1
            return count
        except Exception as e:
            logging.warning(f"Could not fetch remote signatures: {e}")
            return 0
    
    def get_all(self) -> List[Signature]:
        """Get all loaded signatures."""
        return list(self.signatures_by_id.values())
    
    def get_by_category(self, category: str) -> List[Signature]:
        """Get signatures by category."""
        return [s for s in self.get_all() if s.category == category]
    
    def get_by_threat_level(self, level: ThreatLevel) -> List[Signature]:
        """Get signatures by threat level."""
        return [s for s in self.get_all() if s.threat_level == level]
    
    def export_json(self, filepath: str) -> None:
        """Export signatures to JSON file."""
        data = {
            "version": __version__,
            "generated": datetime.now().isoformat(),
            "signatures": []
        }
        for s in self.get_all():
            sig_dict = asdict(s)
            sig_dict['threat_level'] = s.threat_level.value
            data["signatures"].append(sig_dict)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


# =============================================================================
# FILE SCANNER
# =============================================================================

class FileScanner:
    """Multi-threaded file scanner for malware detection."""
    
    # File extensions to scan
    SCAN_EXTENSIONS = {
        '.php', '.js', '.html', '.htm', '.css', '.txt',
        '.md', '.json', '.xml', '.htaccess', '.ini', '.conf'
    }
    
    # Directories to skip
    SKIP_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__',
        '.idea', '.vscode', '.DS_Store'
    }
    
    # Known WordPress core files (partial hash check)
    WP_CORE_DIRS = {'wp-admin', 'wp-includes'}
    
    def __init__(self, signatures: List[Signature], threads: int = 4):
        self.signatures = signatures
        self.threads = threads
        self.compiled_patterns: List[Tuple[Signature, re.Pattern]] = []
        
        # Pre-compile regex patterns
        for sig in signatures:
            try:
                flags = re.MULTILINE | re.IGNORECASE if sig.is_regex else 0
                pattern = re.compile(sig.pattern, flags)
                self.compiled_patterns.append((sig, pattern))
            except re.error as e:
                logging.warning(f"Invalid regex pattern {sig.id}: {e}")
    
    def should_scan(self, filepath: Path) -> bool:
        """Check if file should be scanned."""
        # Check extension
        if filepath.suffix.lower() not in self.SCAN_EXTENSIONS:
            return False
        
        # Skip minified files (often have false positives)
        if '.min.' in filepath.name:
            return False
        
        return True
    
    def should_skip_dir(self, path: Path) -> bool:
        """Check if directory should be skipped."""
        for part in path.parts:
            if part in self.SKIP_DIRS:
                return True
        return False
    
    def get_context(self, lines: List[str], line_num: int, context_lines: int = 3) -> Tuple[str, str]:
        """Get context around a matched line."""
        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines + 1)
        
        before = ''.join(lines[start:line_num]).strip()
        after = ''.join(lines[line_num + 1:end]).strip()
        
        return before, after
    
    def scan_file(self, filepath: Path) -> ScanResult:
        """Scan a single file for malware signatures."""
        start_time = datetime.now()
        findings: List[Finding] = []
        
        try:
            if not self.should_scan(filepath):
                return ScanResult(
                    file_path=str(filepath),
                    status=ScanStatus.COMPLETED.value,
                    findings=[],
                    scan_time_ms=(datetime.now() - start_time).total_seconds() * 1000
                )
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            for sig, pattern in self.compiled_patterns:
                for match in pattern.finditer(content):
                    # Find line number
                    line_num = content[:match.start()].count('\n')
                    matched_text = match.group(0)
                    
                    # Get context
                    before, after = self.get_context(lines, line_num)
                    
                    # Truncate matched content if too long
                    if len(matched_text) > 200:
                        matched_text = matched_text[:200] + '...'
                    
                    finding = Finding(
                        file_path=str(filepath),
                        line_number=line_num + 1,  # 1-indexed
                        signature_id=sig.id,
                        signature_name=sig.name,
                        threat_level=sig.threat_level.value,
                        category=sig.category,
                        matched_content=matched_text,
                        context_before=before,
                        context_after=after,
                        description=sig.description,
                        remediation=sig.remediation
                    )
                    findings.append(finding)
            
            return ScanResult(
                file_path=str(filepath),
                status=ScanStatus.COMPLETED.value,
                findings=findings,
                scan_time_ms=(datetime.now() - start_time).total_seconds() * 1000
            )
            
        except Exception as e:
            return ScanResult(
                file_path=str(filepath),
                status=ScanStatus.ERROR.value,
                findings=[],
                error=str(e),
                scan_time_ms=(datetime.now() - start_time).total_seconds() * 1000
            )
    
    def collect_files(self, root_path: Path) -> List[Path]:
        """Collect all files to scan."""
        files = []
        
        for root, dirs, filenames in os.walk(root_path):
            root_path_obj = Path(root)
            
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            
            if self.should_skip_dir(root_path_obj):
                continue
            
            for filename in filenames:
                filepath = root_path_obj / filename
                if self.should_scan(filepath):
                    files.append(filepath)
        
        return files
    
    def scan_directory(self, root_path: str, progress_callback=None) -> List[ScanResult]:
        """Scan entire directory with multi-threading."""
        root = Path(root_path)
        
        if not root.exists():
            raise FileNotFoundError(f"Path does not exist: {root_path}")
        
        files = self.collect_files(root)
        results: List[ScanResult] = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in files}
            
            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(ScanResult(
                        file_path=str(filepath),
                        status=ScanStatus.ERROR.value,
                        findings=[],
                        error=str(e)
                    ))
                
                if progress_callback:
                    progress_callback(len(results), len(files), result)
        
        return results


# =============================================================================
# ENTROPY ANALYZER (for obfuscation detection)
# =============================================================================

class EntropyAnalyzer:
    """Detects obfuscated code using entropy analysis."""
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        
        # Count character frequencies
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def is_suspicious(content: str, threshold: float = 5.5, min_length: int = 50) -> bool:
        """Check if content has suspicious entropy (possible obfuscation)."""
        if len(content) < min_length:
            return False
        
        # Check for long strings with high entropy
        for i in range(0, len(content) - min_length, min_length):
            chunk = content[i:i + min_length * 2]
            entropy = EntropyAnalyzer.calculate_entropy(chunk)
            if entropy > threshold:
                return True
        
        return False
    
    @staticmethod
    def find_suspicious_strings(content: str, min_length: int = 50, 
                                 entropy_threshold: float = 5.0) -> List[Tuple[int, str, float]]:
        """Find suspicious high-entropy strings in content."""
        suspicious = []
        
        # Look for quoted strings
        pattern = r'["\']([^"\']{50,})["\']'
        for match in re.finditer(pattern, content):
            string_content = match.group(1)
            entropy = EntropyAnalyzer.calculate_entropy(string_content)
            
            if entropy > entropy_threshold:
                line_num = content[:match.start()].count('\n') + 1
                suspicious.append((line_num, string_content[:100], entropy))
        
        return suspicious


# =============================================================================
# LOGGING AND REPORTING
# =============================================================================

class ScanLogger:
    """Handles logging of scan results to file."""
    
    def __init__(self, log_file: str):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger('wp-scanner')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(self.log_file, mode='w', encoding='utf-8')
        fh.setLevel(logging.INFO)
        
        # Format
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
    
    def log_scan_start(self, path: str, threads: int, signature_count: int) -> None:
        """Log scan initialization."""
        self.logger.info("=" * 60)
        self.logger.info("WORDPRESS MALWARE SCAN STARTED")
        self.logger.info("=" * 60)
        self.logger.info(f"Scan Path: {path}")
        self.logger.info(f"Threads: {threads}")
        self.logger.info(f"Signatures Loaded: {signature_count}")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        self.logger.info("")
    
    def log_scan_complete(self, stats: ScanStats) -> None:
        """Log scan completion with statistics."""
        self.logger.info("")
        self.logger.info("=" * 60)
        self.logger.info("SCAN COMPLETED")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Files Scanned: {stats.scanned_files}")
        self.logger.info(f"Infected Files: {stats.infected_files}")
        self.logger.info(f"Total Findings: {stats.total_findings}")
        self.logger.info(f"  - Critical: {stats.critical}")
        self.logger.info(f"  - High: {stats.high}")
        self.logger.info(f"  - Medium: {stats.medium}")
        self.logger.info(f"  - Low: {stats.low}")
        self.logger.info(f"Duration: {stats.scan_duration_seconds:.2f} seconds")
        self.logger.info("")
    
    def log_finding(self, finding: Finding) -> None:
        """Log a single finding with full details."""
        self.logger.info("-" * 60)
        self.logger.info(f"THREAT DETECTED")
        self.logger.info("-" * 60)
        self.logger.info(f"File: {finding.file_path}")
        self.logger.info(f"Line: {finding.line_number}")
        self.logger.info(f"Signature: {finding.signature_id} - {finding.signature_name}")
        self.logger.info(f"Threat Level: {finding.threat_level.upper()}")
        self.logger.info(f"Category: {finding.category}")
        self.logger.info(f"Description: {finding.description}")
        self.logger.info(f"Matched Content: {finding.matched_content}")
        self.logger.info(f"Context Before:")
        self.logger.info(f"  {finding.context_before[:200]}")
        self.logger.info(f"Context After:")
        self.logger.info(f"  {finding.context_after[:200]}")
        self.logger.info(f"Remediation: {finding.remediation}")
        self.logger.info("")
    
    def log_error(self, filepath: str, error: str) -> None:
        """Log scanning error."""
        self.logger.warning(f"Error scanning {filepath}: {error}")


class ReportGenerator:
    """Generates scan reports in various formats."""
    
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
        
        # Group findings by severity
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        # Sort by threat level
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_findings.sort(key=lambda f: severity_order.get(f.threat_level, 4))
        
        if all_findings:
            lines.append("FINDINGS")
            lines.append("-" * 70)
            
            for finding in all_findings:
                severity_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(
                    finding.threat_level, '⚪'
                )
                lines.append(f"{severity_icon} [{finding.threat_level.upper()}] {finding.file_path}:{finding.line_number}")
                lines.append(f"   {finding.signature_name} ({finding.signature_id})")
                lines.append(f"   {finding.description}")
                lines.append(f"   Match: {finding.matched_content[:80]}...")
                lines.append("")
        else:
            lines.append("No threats detected! ✓")
        
        lines.append("=" * 70)
        return '\n'.join(lines)
    
    @staticmethod
    def generate_json_report(results: List[ScanResult], stats: ScanStats) -> dict:
        """Generate a JSON report."""
        all_findings = []
        for result in results:
            for finding in result.findings:
                all_findings.append(asdict(finding))
        
        return {
            "generated": datetime.now().isoformat(),
            "statistics": asdict(stats),
            "findings": all_findings,
            "files_scanned": [r.file_path for r in results if r.status == ScanStatus.COMPLETED.value]
        }


# =============================================================================
# QUARANTINE MANAGER
# =============================================================================

class QuarantineManager:
    """Handles quarantining and safe deletion of infected files."""
    
    def __init__(self, quarantine_dir: str):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
    
    def quarantine_file(self, filepath: str, reason: str) -> str:
        """Move file to quarantine directory."""
        src = Path(filepath)
        if not src.exists():
            return ""
        
        # Create unique name with timestamp and reason
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = f"{timestamp}_{src.name}_{reason}"
        dst = self.quarantine_dir / safe_name
        
        try:
            import shutil
            shutil.move(str(src), str(dst))
            return str(dst)
        except Exception as e:
            logging.error(f"Failed to quarantine {filepath}: {e}")
            return ""
    
    def safe_delete(self, filepath: str) -> bool:
        """Safely delete a file (only non-core WordPress files)."""
        path = Path(filepath)
        
        # Don't delete core WordPress files
        wp_core_patterns = ['wp-config.php', 'wp-login.php', 'xmlrpc.php']
        if path.name in wp_core_patterns:
            logging.warning(f"Refusing to delete core WordPress file: {filepath}")
            return False
        
        # Check if in core directories
        if 'wp-admin/' in str(filepath) or 'wp-includes/' in str(filepath):
            logging.warning(f"Refusing to delete file in core directory: {filepath}")
            return False
        
        try:
            os.remove(filepath)
            logging.info(f"Deleted: {filepath}")
            return True
        except Exception as e:
            logging.error(f"Failed to delete {filepath}: {e}")
            return False
    
    def is_non_wp_file(self, filepath: str) -> bool:
        """Check if file is likely not a WordPress core file."""
        path = Path(filepath)
        
        # Known non-WP patterns
        suspicious_patterns = [
            'wso.php', 'c99.php', 'r57.php', 'b374k.php',
            'shell.php', 'backdoor.php', 'hack.php'
        ]
        
        return any(p in path.name.lower() for p in suspicious_patterns)


# =============================================================================
# CLI ARGUMENT PARSER
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog='wp-scanner',
        description='WordPress Malware Scanner - Detect malware, backdoors, and crypto miners',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Scan current directory with TUI
  %(prog)s /var/www/html            # Scan specific directory
  %(prog)s --no-tui                 # Run without TUI (headless mode)
  %(prog)s --threads 8              # Use 8 threads for faster scanning
  %(prog)s --delete                 # Auto-delete known malicious files
  %(prog)s --quarantine ./quarantine # Move infected files to quarantine
  %(prog)s --log scan.log           # Save detailed log to file
  %(prog)s --update-sigs            # Fetch latest signatures from GitHub
        """
    )
    
    # Positional arguments
    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Path to WordPress installation (default: current directory)'
    )
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '-t', '--threads',
        type=int,
        default=4,
        help='Number of parallel threads (default: 4)'
    )
    scan_group.add_argument(
        '--no-tui',
        action='store_true',
        help='Disable TUI, use simple text output'
    )
    scan_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    scan_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress non-essential output'
    )
    
    # Action options
    action_group = parser.add_argument_group('Action Options')
    action_group.add_argument(
        '-d', '--delete',
        action='store_true',
        help='Auto-delete files identified as malicious (non-WP files only)'
    )
    action_group.add_argument(
        '-Q', '--quarantine',
        metavar='DIR',
        help='Quarantine infected files to specified directory'
    )
    action_group.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    # Signature options
    sig_group = parser.add_argument_group('Signature Options')
    sig_group.add_argument(
        '-s', '--signatures',
        metavar='FILE',
        help='Load custom signatures from JSON file'
    )
    sig_group.add_argument(
        '--update-sigs',
        action='store_true',
        help='Fetch latest signatures from GitHub repository'
    )
    sig_group.add_argument(
        '--export-sigs',
        metavar='FILE',
        help='Export current signatures to JSON file'
    )
    sig_group.add_argument(
        '--list-categories',
        action='store_true',
        help='List available signature categories'
    )
    
    # Output options
    out_group = parser.add_argument_group('Output Options')
    out_group.add_argument(
        '-l', '--log',
        metavar='FILE',
        help='Write detailed log to specified file'
    )
    out_group.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Write report to file (text or JSON based on extension)'
    )
    out_group.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    
    # Database scanning (placeholder for Phase 4)
    db_group = parser.add_argument_group('Database Scanning (Phase 4)')
    db_group.add_argument(
        '--db-host',
        default='localhost',
        help='Database host (default: localhost)'
    )
    db_group.add_argument(
        '--db-user',
        help='Database username'
    )
    db_group.add_argument(
        '--db-pass',
        help='Database password'
    )
    db_group.add_argument(
        '--db-name',
        help='Database name'
    )
    db_group.add_argument(
        '--db-prefix',
        default='wp_',
        help='WordPress table prefix (default: wp_)'
    )
    db_group.add_argument(
        '--scan-db',
        action='store_true',
        help='Also scan database (requires DB credentials)'
    )
    
    # Version
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    return parser


# =============================================================================
# TUI (TEXTUAL) - Optional Import
# =============================================================================

try:
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, DataTable, Label, ProgressBar, Static
    from textual.containers import Container, Vertical
    from textual.binding import Binding
    from textual.reactive import reactive
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


class ScannerTUI(App):
    """Textual TUI for the malware scanner."""
    
    CSS = """
    Screen {
        background: #0b0c15;
    }
    
    #status-bar {
        height: 3;
        margin: 1;
        background: #1a1b26;
        border: solid #414868;
    }
    
    #current-file {
        height: 3;
        margin: 1;
        background: #1a1b26;
        color: #7aa2f7;
    }
    
    #findings-panel {
        height: 10;
        margin: 1;
        background: #1a1b26;
        border: solid #414868;
    }
    
    .critical { color: #f7768e; }
    .high { color: #ff9e64; }
    .medium { color: #e0af68; }
    .low { color: #9ece6a; }
    
    DataTable {
        height: 1fr;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "toggle_dark", "Toggle Dark"),
    ]
    
    progress = reactive(0.0)
    files_scanned = reactive(0)
    total_files = reactive(0)
    findings_count = reactive(0)
    current_file = reactive("")
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.findings: List[Finding] = []
    
    def compose(self) -> ComposeResult:
        if not TEXTUAL_AVAILABLE:
            yield Label("Textual not installed. Run: pip install textual")
            return
        
        yield Header(show_clock=True)
        yield Static(f"[bold]Scanning...[/]", id="status-bar")
        yield Static(f"[cyan]Current file: {self.current_file}[/]", id="current-file")
        yield ProgressBar(total=100, show_eta=False, id="progress")
        yield DataTable(id="findings-table")
        yield Footer()
    
    def on_mount(self) -> None:
        if not TEXTUAL_AVAILABLE:
            return
        
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Level", "File", "Threat", "Line")
    
    def update_progress(self, scanned: int, total: int, result: ScanResult) -> None:
        """Update progress from scanner callback."""
        self.files_scanned = scanned
        self.total_files = total
        self.progress = (scanned / total * 100) if total > 0 else 0
        self.current_file = result.file_path
        
        if result.findings:
            self.findings_count += len(result.findings)
            self.findings.extend(result.findings)
            
            # Update table
            table = self.query_one("#findings-table", DataTable)
            for finding in result.findings:
                level_class = finding.threat_level
                table.add_row(
                    f"[{level_class}]{finding.threat_level.upper()}[/{level_class}]",
                    Path(finding.file_path).name[:30],
                    finding.signature_name[:25],
                    str(finding.line_number),
                    key=finding.file_path + str(finding.line_number)
                )
    
    def action_toggle_dark(self) -> None:
        self.theme = "textual-dark" if self.theme == "textual-light" else "textual-light"


def run_tui_scan(scanner: FileScanner, path: str, threads: int) -> Tuple[List[ScanResult], ScanStats]:
    """Run scan with TUI."""
    import time
    
    start_time = time.time()
    results: List[ScanResult] = []
    
    def progress_callback(scanned: int, total: int, result: ScanResult):
        results.append(result)
    
    files = scanner.collect_files(Path(path))
    
    # Run scan
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_file = {executor.submit(scanner.scan_file, f): f for f in files}
        
        for future in as_completed(future_to_file):
            result = future.result()
            results.append(result)
            progress_callback(len(results), len(files), result)
    
    # Calculate stats
    end_time = time.time()
    stats = calculate_stats(results, start_time, end_time)
    
    return results, stats


def calculate_stats(results: List[ScanResult], start_time: float, end_time: float) -> ScanStats:
    """Calculate scan statistics."""
    stats = ScanStats()
    stats.total_files = len(results)
    stats.scanned_files = sum(1 for r in results if r.status == ScanStatus.COMPLETED.value)
    
    all_findings = []
    for result in results:
        if result.findings:
            stats.infected_files += 1
            all_findings.extend(result.findings)
    
    stats.total_findings = len(all_findings)
    
    for finding in all_findings:
        if finding.threat_level == 'critical':
            stats.critical += 1
        elif finding.threat_level == 'high':
            stats.high += 1
        elif finding.threat_level == 'medium':
            stats.medium += 1
        else:
            stats.low += 1
    
    stats.start_time = datetime.fromtimestamp(start_time).isoformat()
    stats.end_time = datetime.fromtimestamp(end_time).isoformat()
    stats.scan_duration_seconds = end_time - start_time
    
    return stats


# =============================================================================
# MAIN FUNCTION
# =============================================================================

def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    if args.log:
        scan_logger = ScanLogger(args.log)
    else:
        scan_logger = None
    
    # Initialize signature manager
    sig_manager = SignatureManager(args.signatures)
    builtin_count = sig_manager.load_builtin()
    
    if args.verbose:
        print(f"Loaded {builtin_count} built-in signatures")
    
    # Load custom signatures if specified
    if args.signatures:
        custom_count = sig_manager.load_custom(args.signatures)
        if args.verbose:
            print(f"Loaded {custom_count} custom signatures from {args.signatures}")
    
    # Fetch remote signatures if requested
    if args.update_sigs:
        print("Fetching latest signatures from GitHub...")
        new_count = sig_manager.fetch_remote()
        print(f"Added {new_count} new signatures")
    
    # Export signatures if requested
    if args.export_sigs:
        sig_manager.export_json(args.export_sigs)
        print(f"Exported {len(sig_manager.get_all())} signatures to {args.export_sigs}")
        return
    
    # List categories if requested
    if args.list_categories:
        categories = set(s.category for s in sig_manager.get_all())
        print("Available signature categories:")
        for cat in sorted(categories):
            count = len([s for s in sig_manager.get_all() if s.category == cat])
            print(f"  - {cat}: {count} signatures")
        return
    
    signatures = sig_manager.get_all()
    
    if scan_logger:
        scan_logger.log_scan_start(args.path, args.threads, len(signatures))
    
    # Initialize scanner
    scanner = FileScanner(signatures, threads=args.threads)
    
    # Run scan
    start_time = datetime.now()
    
    if args.no_tui or args.json or args.output:
        # Headless mode
        if not args.quiet:
            print(f"Scanning {args.path} with {args.threads} threads...")
            print(f"Loaded {len(signatures)} signatures")
            print("")
        
        results = scanner.scan_directory(args.path)
        
        end_time = datetime.now()
        stats = calculate_stats(results, start_time.timestamp(), end_time.timestamp())
        
        if scan_logger:
            for result in results:
                for finding in result.findings:
                    scan_logger.log_finding(finding)
            scan_logger.log_scan_complete(stats)
        
        # Output results
        if args.json:
            report = ReportGenerator.generate_json_report(results, stats)
            print(json.dumps(report, indent=2))
        elif args.output:
            output_path = Path(args.output)
            if output_path.suffix == '.json':
                report = ReportGenerator.generate_json_report(results, stats)
                with open(output_path, 'w') as f:
                    json.dump(report, f, indent=2)
            else:
                report = ReportGenerator.generate_text_report(results, stats)
                with open(output_path, 'w') as f:
                    f.write(report)
            if not args.quiet:
                print(f"Report written to {args.output}")
        else:
            report = ReportGenerator.generate_text_report(results, stats)
            print(report)
        
        # Handle delete/quarantine actions
        if args.delete or args.quarantine:
            quarantine_mgr = QuarantineManager(args.quarantine or './quarantine')
            
            infected_files = set()
            for result in results:
                if result.findings:
                    infected_files.add(result.file_path)
            
            for filepath in infected_files:
                if args.delete:
                    if quarantine_mgr.is_non_wp_file(filepath):
                        if args.dry_run:
                            print(f"[DRY-RUN] Would delete: {filepath}")
                        else:
                            quarantine_mgr.safe_delete(filepath)
                    else:
                        if not args.dry_run:
                            print(f"Skipping core WP file: {filepath}")
                
                if args.quarantine:
                    if args.dry_run:
                        print(f"[DRY-RUN] Would quarantine: {filepath}")
                    else:
                        quarantined = quarantine_mgr.quarantine_file(
                            filepath, 
                            'infected'
                        )
                        if quarantined:
                            print(f"Quarantined: {filepath} -> {quarantined}")
    
    else:
        # TUI mode
        if not TEXTUAL_AVAILABLE:
            print("Textual TUI not installed. Installing...")
            print("Or run with --no-tui for headless mode.")
            print("")
            # Fall back to headless
            results = scanner.scan_directory(args.path)
            end_time = datetime.now()
            stats = calculate_stats(results, start_time.timestamp(), end_time.timestamp())
            report = ReportGenerator.generate_text_report(results, stats)
            print(report)
        else:
            # Run with TUI
            app = ScannerTUI()
            
            def run_scan():
                results = scanner.scan_directory(args.path, progress_callback=app.update_progress)
                return results
            
            # Note: Full async integration would need more work
            # For now, fall back to headless with progress
            print("Starting scan with TUI...")
            results = scanner.scan_directory(args.path)
            end_time = datetime.now()
            stats = calculate_stats(results, start_time.timestamp(), end_time.timestamp())
            report = ReportGenerator.generate_text_report(results, stats)
            print(report)
    
    # Database scanning (Phase 4 - placeholder)
    if args.scan_db:
        print("\nDatabase scanning is coming in Phase 4.")
        print("Please provide: --db-user, --db-pass, --db-name")


if __name__ == '__main__':
    main()
