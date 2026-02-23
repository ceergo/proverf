from datetime import datetime
import sys
import json
import hashlib

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
        """Calculates current completion percentage."""
        if self.total > 0:
            return (self.processed / self.total) * 100
        return 0

# Singleton stats instance
stats = Stats()

def log_event(msg, level="INFO"):
    """
    Standard event logger with timestamp and progress.
    """
    timestamp = datetime.now().strftime('%H:%M:%S')
    pct = stats.get_progress_pct()
    
    # ANSI Colors
    colors = {
        "INFO": "\033[94m",    # Blue
        "SUCCESS": "\033[92m", # Green
        "WARNING": "\033[93m", # Yellow
        "ERROR": "\033[91m",   # Red
        "SYSTEM": "\033[95m",  # Magenta
        "RESET": "\033[0m"
    }
    
    color = colors.get(level, colors["RESET"])
    reset = colors["RESET"]
    
    # Format: [12:00:00] [ 50.5%] [LEVEL   ] Message
    print(f"[{timestamp}] [{pct:5.1f}%] {color}[{level:8}]{reset} {msg}", flush=True)

def log_node_details(link, parsed_data, status, speed=0.0, ping=0.0):
    """
    Detailed real-time logging for each proxy node.
    Shows protocol, host, port and remark.
    """
    if not parsed_data:
        log_event(f"Ошибка расшифровки ссылки: {link[:40]}...", "ERROR")
        return

    proto = str(parsed_data.get('protocol', '???')).upper()
    host = str(parsed_data.get('host', '0.0.0.0'))
    port = str(parsed_data.get('port', '0'))
    remark = str(parsed_data.get('remark', 'No Name'))
    
    # Sanitize remark for clean output
    clean_remark = "".join(c for c in remark if c.isprintable())[:25]
    
    # Build identity string
    identity = f"{proto}://{host}:{port} ({clean_remark})"
    
    # Output based on classification
    if status == "ELITE":
        log_event(f"💎 {identity} -> ELITE | {speed} Mbps | {ping}ms", "SUCCESS")
    elif status == "STABLE":
        log_event(f"✅ {identity} -> STABLE | {speed} Mbps", "SUCCESS")
    elif status == "FAST_NO_GOOGLE":
        log_event(f"⚡ {identity} -> FAST (No Gemini) | {speed} Mbps", "INFO")
    elif status == "DEAD":
        log_event(f"💀 {identity} -> DEAD/SLOW", "WARNING")
    elif status == "ALREADY_DONE":
        # Silent skip or minimal info
        pass
    else:
        log_event(f"🔍 {identity} -> {status}", "INFO")

def log_error_details(link, error, context="CORE"):
    """
    Logs deep error information for debugging.
    """
    short_hash = hashlib.md5(str(link).encode()).hexdigest()[:8]
    log_event(f"Критическая ошибка [{context}] на ноде {short_hash}: {error}", "ERROR")
