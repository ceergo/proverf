import os
import json
import hashlib
import re
import base64
import random
import sys
import subprocess
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote

class Stats:
    def __init__(self):
        self.total = 0
        self.processed = 0
        self.elite = 0
        self.stable = 0
        self.fast = 0
        self.dead = 0
        self.errors = 0

stats = Stats()

# --- COLORS ---
C = {
    "BLUE": "\033[94m", "CYAN": "\033[96m", "GREEN": "\033[92m",
    "YELLOW": "\033[93m", "RED": "\033[91m", "END": "\033[0m",
    "BOLD": "\033[1m", "GRAY": "\033[90m"
}

def log_event(message, level="INFO"):
    """Standardized event logger with colors."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = C.get("CYAN")
    if level == "SUCCESS": color = C.get("GREEN")
    elif level == "ERROR": color = C.get("RED")
    elif level == "SYSTEM": color = C.get("BLUE")
    elif level == "WARNING": color = C.get("YELLOW")
    
    print(f"{C['GRAY']}[{timestamp}]{C['END']} {color}{C['BOLD']}[{level}]{C['END']} {message}")

def log_node_details(link, parsed, category, speed=0.0, ping=0.0):
    """Detailed node audit logger."""
    emoji = "💀"
    color = C["RED"]
    
    if category == "ELITE": emoji, color = "💎", C["GREEN"]
    elif category == "STABLE": emoji, color = "✅", C["CYAN"]
    elif category == "FAST_NO_GOOGLE": emoji, color = "⚡", C["YELLOW"]
    elif category == "INVALID_FORMAT": emoji, color = "🧩", C["GRAY"]
    
    remark = parsed.get("remark", "N/A") if parsed else "INVALID"
    ip_info = f"{parsed.get('host')}:{parsed.get('port')}" if parsed else "Unknown"
    
    print(f"{emoji} {color}{category:<15}{C['END']} | {C['BOLD']}{remark:<20}{C['END']} | {ip_info:<25} | {speed:>5} Mbps | {ping:>6} ms")

def log_error_details(link, exception, context="GENERAL"):
    """Error logger with context."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{C['RED']}![{timestamp}] [ERROR:{context}]{C['END']} {str(exception)} | Link: {link[:50]}...")

def log_progress():
    """Outputs current audit progress snapshot."""
    log_event(f"Прогресс: Elite: {stats.elite} | Stable: {stats.stable} | Fast: {stats.fast} | Dead: {stats.dead}", "INFO")

def log_summary():
    """Outputs final audit summary."""
    log_event("="*50, "SYSTEM")
    log_event(f"🏆 АУДИТ ЗАВЕРШЕН", "SUCCESS")
    log_event(f"Elite: {stats.elite} | Stable: {stats.stable} | Fast: {stats.fast} | Dead: {stats.dead} | Errors: {stats.errors}", "SUCCESS")
    log_event("="*50, "SYSTEM")

# --- TECHNICAL WORKSPACE (MOVED FROM MAIN) ---

def kill_process_by_name(name):
    """Terminates zombie processes."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", f"{name}.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["pkill", "-9", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def get_md5(text):
    """Generates unique hash for link deduplication."""
    try:
        if "vmess://" in text:
            normalized = text.strip().split('#')[0]
        else:
            normalized = text.strip().split('#')[0].split('?')[0]
        return hashlib.md5(normalized.encode()).hexdigest()
    except:
        return hashlib.md5(text.strip().encode()).hexdigest()

def manage_cache_lifecycle(config):
    """Wipes dead cache every 72 hours."""
    now = datetime.now()
    if os.path.exists(config.CLEANUP_LOG):
        with open(config.CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    log_event("🧹 Ротация кэша: Очистка списка мертвых нод...", "SYSTEM")
                    if os.path.exists(config.DEAD_CACHE_FILE): 
                        os.remove(config.DEAD_CACHE_FILE)
                    with open(config.CLEANUP_LOG, "w") as f_out: 
                        f_out.write(now.isoformat())
            except: pass
    else:
        with open(config.CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())

def extract_server_identity(link):
    """Extracts IP:Port to prevent redundant server checks."""
    try:
        if "://" not in link: return link
        if link.lower().startswith("vmess://"):
            b64_part = link[8:].split("#")[0]
            b64_part = re.sub(r'[^a-zA-Z0-9+/=]', '', b64_part)
            b64_part += "=" * (-len(b64_part) % 4)
            decoded = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
            data = json.loads(re.search(r'\{.*\}', decoded).group())
            return f"{data.get('add')}:{data.get('port')}"
        match = re.search(r'@([^:/?#]+):(\d+)', link)
        if match: return f"{match.group(1)}:{match.group(2)}"
        parsed = urlparse(link)
        return parsed.netloc or link
    except: return link

def clean_garbage(link, cleanup_pattern):
    """Strips invisible characters and junk from links."""
    if not link: return ""
    link = link.strip()
    protocol_match = re.search(cleanup_pattern, link, re.IGNORECASE)
    if protocol_match: link = link[protocol_match.start():]
    link = "".join(char for char in link if 32 < ord(char) < 127)
    if not link.lower().startswith("vmess://") and "#" in link:
        link = link.split("#", 1)[0]
    return link

def extract_configs_from_text(text, protocol_pattern, cleanup_pattern, depth=0):
    """Deep recursive link extractor."""
    if depth > 1 or not text: return []
    clean_text = text.replace('\\n', '\n').replace('\\r', '\r')
    found_raw = []
    for m in re.finditer(protocol_pattern, clean_text, re.IGNORECASE):
        l = clean_garbage(m.group(0), cleanup_pattern)
        if l: found_raw.append(l)
    if not found_raw and depth == 0:
        try:
            trimmed = clean_text.strip()
            if len(trimmed) > 20 and re.match(r'^[a-zA-Z0-9+/=\s]+$', trimmed):
                padded = trimmed.replace('\n', '').replace('\r', '') + "=" * (-len(trimmed) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                found_raw.extend(extract_configs_from_text(decoded, protocol_pattern, cleanup_pattern, depth + 1))
        except: pass
    return list(set(found_raw))

async def prepare_task_pool(config):
    """Handles reading, extraction, and deduplication of links."""
    total_pool = []
    if os.path.exists(config.TEMP_POOL_FILE):
        log_event("♻️ Восстановление очереди...", "INFO")
        with open(config.TEMP_POOL_FILE, "r") as f: total_pool = json.load(f)
    if not total_pool:
        if not os.path.exists(config.RAW_LINKS_FILE):
            log_event(f"❌ Файл {config.RAW_LINKS_FILE} не найден!", "ERROR"); return []
        with open(config.RAW_LINKS_FILE, "r") as f:
            content = f.read()
            raw_extracted = extract_configs_from_text(content, config.PROTOCOL_PATTERN, config.CLEANUP_PATTERN)
        log_event(f"📖 Загружено из файла: {len(raw_extracted)} нод.", "SUCCESS")
        history = set()
        for path in config.RESULT_FILES.values():
            if os.path.exists(path):
                with open(path) as f: 
                    for line in f: history.add(get_md5(line))
        seen_ips = set()
        for l in raw_extracted:
            h, ip = get_md5(l), extract_server_identity(l)
            if h not in history and ip not in seen_ips:
                total_pool.append(l)
                seen_ips.add(ip)
        log_event(f"🎯 Итого новых нод к проверке: {len(total_pool)}", "SUCCESS")
        random.shuffle(total_pool)
        with open(config.TEMP_POOL_FILE, "w") as f: json.dump(total_pool, f)
    return total_pool

async def save_audit_results(results, config, file_lock):
    """Handles writing audit results to persistent storage."""
    async with file_lock:
        for link, cat, speed, ping in results:
            if cat == "ALREADY_DONE": continue
            h = get_md5(link)
            if cat in ["ERROR", "DEAD", "INVALID_FORMAT"]:
                with open(config.DEAD_CACHE_FILE, "a") as f: f.write(f"{h}\n")
            else:
                target = config.RESULT_FILES.get(cat)
                if target: 
                    with open(target, "a") as f: f.write(f"{link}\n")
