from datetime import datetime
import sys
import json

class Stats:
    def __init__(self):
        self.total = 0
        self.processed = 0
        self.elite = 0
        self.stable = 0
        self.fast = 0
        self.dead = 0
        self.errors = 0

    def get_progress_pct(self):
        if self.total > 0:
            return (self.processed / self.total) * 100
        return 0

# Global stats instance
stats = Stats()

def log_event(msg, level="INFO"):
    """
    Advanced logging with levels and progress indicators.
    """
    timestamp = datetime.now().strftime('%H:%M:%S')
    pct = stats.get_progress_pct()
    
    # ANSI Colors for terminal
    colors = {
        "INFO": "\033[94m",    # Blue
        "SUCCESS": "\033[92m", # Green
        "WARNING": "\033[93m", # Yellow
        "ERROR": "\033[91m",   # Red
        "CRITICAL": "\033[41m",# Red Background
        "RESET": "\033[0m"
    }
    
    color = colors.get(level, colors["RESET"])
    reset = colors["RESET"]
    
    print(f"[{timestamp}] [{pct:5.1f}%] {color}[{level:8}]{reset} {msg}", flush=True)

def log_node_details(link, parsed_data, status, speed=0.0, ping=0.0):
    """
    Detailed real-time logging for a single node processing.
    Shows protocol details, identity, and test results.
    """
    if not parsed_data:
        log_event(f"Не удалось расшифровать ссылку: {link[:50]}...", "ERROR")
        return

    proto = parsed_data.get('protocol', 'unknown').upper()
    host = parsed_data.get('host', '0.0.0.0')
    port = parsed_data.get('port', '0')
    remark = parsed_data.get('remark', 'No Name')
    
    # Clean up remark for log
    clean_remark = "".join(c for c in str(remark) if c.isprintable())[:20]
    
    summary = f"🌐 {proto} | {host}:{port} | Name: {clean_remark}"
    
    if status == "ELITE":
        log_event(f"{summary} -> ✅ ELITE (Gemini OK) | Speed: {speed} Mbps | Ping: {ping}ms", "SUCCESS")
    elif status == "STABLE":
        log_event(f"{summary} -> 🟢 STABLE | Speed: {speed} Mbps", "SUCCESS")
    elif status == "FAST_NO_GOOGLE":
        log_event(f"{summary} -> ⚡ FAST (No Google) | Speed: {speed} Mbps", "INFO")
    elif status == "DEAD":
        log_event(f"{summary} -> 💀 DEAD / SLOW", "WARNING")
    else:
        log_event(f"{summary} -> ❓ {status}", "INFO")

def log_error_details(link, error, context="CORE"):
    """
    Deep error analysis for debugging crashes or network failures.
    """
    log_event(f"Ошибка в контексте [{context}]: {str(error)}", "ERROR")
    log_event(f"Проблемная ссылка (MD5-Hash): {hash_link(link)}", "DEBUG")

def hash_link(link):
    """Helper for logging links without leaking full strings."""
    import hashlib
    return hashlib.md5(link.encode()).hexdigest()[:8]
