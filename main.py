import os
import json
import subprocess
import hashlib
import time
import asyncio
import re
import sys
import base64
import shutil
from datetime import datetime, timedelta

# --- CONFIGURATION ---
RAW_LINKS_FILE = "raw_links.txt"
DEAD_CACHE_FILE = "dead_cache.txt"
CLEANUP_LOG = "last_cleanup.txt"

# Output files
ELITE_GEMINI = "Elite_Gemini.txt"
STABLE_CHAT = "Stable_Chat.txt"
FAST_NO_GOOGLE = "Fast_NoGoogle.txt"

RESULT_FILES = [ELITE_GEMINI, STABLE_CHAT, FAST_NO_GOOGLE]

# Paths for Binaries (Assumed installed via workflow)
XRAY_PATH = "xray" # If in PATH
LIBRESPEED_PATH = "./librespeed-cli" # Local binary

# Critical Links
GEMINI_CHECK_URL = "https://aistudio.google.com/app"
SPEED_TEST_URL = "http://speedtest.tele2.net/1MB.zip" # Fallback if librespeed fails

def log_event(msg):
    """Real-time logging for GitHub Actions."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def get_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def manage_cache_lifecycle():
    now = datetime.now()
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    log_event("[CLEANUP] 72h cycle! Wiping dead_cache...")
                    if os.path.exists(DEAD_CACHE_FILE): os.remove(DEAD_CACHE_FILE)
                    with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())
            except: pass
    else:
        with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())

def extract_configs_from_text(text):
    pattern = r'(vless|vmess|ss|trojan)://[^\s|#]+(?:#[^\s]*)?'
    found = re.findall(pattern, text, re.IGNORECASE)
    return list(set(found))

def parse_vless_link(link):
    """
    Very basic VLESS parser to extract main components for Xray config.
    In real scenarios, use a robust library or more complex regex.
    """
    try:
        # vless://uuid@host:port?query#name
        pattern = r'vless://([^@]+)@([^:]+):(\d+)\?([^#]+)'
        match = re.match(pattern, link)
        if not match: return None
        
        uuid, host, port, query = match.groups()
        params = dict(re.findall(r'([^&=]+)=([^&]*)', query))
        
        return {
            "uuid": uuid,
            "host": host,
            "port": int(port),
            "sni": params.get("sni", host),
            "path": params.get("path", "/"),
            "security": params.get("security", "none"),
            "type": params.get("type", "tcp")
        }
    except: return None

def generate_xray_config(parsed_link, local_port):
    """Generates a JSON config for Xray-core."""
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed_link["host"],
                    "port": parsed_link["port"],
                    "users": [{"id": parsed_link["uuid"], "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": parsed_link["type"],
                "security": parsed_link["security"],
                "tlsSettings": {"serverName": parsed_link["sni"]} if parsed_link["security"] == "tls" else {},
                "wsSettings": {"path": parsed_link["path"]} if parsed_link["type"] == "ws" else {}
            }
        }]
    }
    return config

async def check_gemini_access(socks_port):
    """Checks if Gemini is accessible via the SOCKS5 tunnel."""
    try:
        # Use socks5h to ensure DNS is resolved through the proxy
        proxy_url = f"socks5h://127.0.0.1:{socks_port}"
        cmd = [
            "curl", "-s", "-L", "-k", "--proxy", proxy_url,
            GEMINI_CHECK_URL, "--connect-timeout", "10", "-m", "15",
            "-w", "%{http_code}"
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        res = stdout.decode().strip()
        
        if res == "200":
            return True, "OK"
        return False, f"HTTP_{res}"
    except Exception as e:
        return False, str(e)

async def measure_speed_librespeed(socks_port):
    """Measures speed using Librespeed CLI via the tunnel."""
    try:
        # Note: Official Librespeed CLI might need specific proxy env or args
        # This is a template call - adjust based on specific CLI version installed
        cmd = [
            LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{socks_port}",
            "--json", "--duration", "5"
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            down = data.get("download", 0) / 1024 / 1024 # Mbps
            ping = data.get("ping", 0)
            return round(down, 2), round(ping, 1)
        return 0, 0
    except:
        return 0, 0

async def audit_single_link(link, local_port):
    proxy_id = get_md5(link)[:8]
    log_event(f"[AUDIT:{proxy_id}] Starting Deep Sieve...")
    
    parsed = parse_vless_link(link)
    if not parsed:
        log_event(f"  [!] Failed to parse VLESS link structure.")
        return link, "DEAD", 0
    
    config = generate_xray_config(parsed, local_port)
    config_path = f"config_{proxy_id}.json"
    with open(config_path, "w") as f:
        json.dump(config, f)
        
    # Start Xray
    try:
        xray_proc = subprocess.Popen(
            [XRAY_PATH, "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(2) # Wait for tunnel to stabilize
        
        # 1. Check Gemini Access
        is_gemini, gemini_msg = await check_gemini_access(local_port)
        log_event(f"  [>] Gemini: {gemini_msg}")
        
        # 2. Measure Speed
        speed, ping = await measure_speed_librespeed(local_port)
        log_event(f"  [>] Speed: {speed} Mbps | Ping: {ping}ms")
        
        # Verdict
        verdict = "DEAD"
        if is_gemini and speed >= 1.0: verdict = "ELITE"
        elif is_gemini and speed >= 0.1: verdict = "STABLE"
        elif speed >= 3.0: verdict = "FAST_NO_GOOGLE"
        
        log_event(f"[AUDIT:{proxy_id}] VERDICT: {verdict}\n")
        
        # Cleanup process
        xray_proc.terminate()
        os.remove(config_path)
        return link, verdict, speed
        
    except Exception as e:
        log_event(f"  [ERROR] Xray Crash: {e}")
        return link, "DEAD", 0

async def main_orchestrator():
    log_event("--- SIERRA X-RAY ORCHESTRATOR ONLINE ---")
    manage_cache_lifecycle()
    
    # Check for binaries
    if not shutil.which(XRAY_PATH):
        log_event("[CRITICAL] Xray binary not found! Ensure it's installed in Workflow.")
        return

    # Load Links
    if not os.path.exists(RAW_LINKS_FILE):
        log_event(f"[ERROR] {RAW_LINKS_FILE} missing.")
        return

    with open(RAW_LINKS_FILE, "r") as f:
        content = f.read()
    
    # Expanding sub links (Simplified for this version)
    links = extract_configs_from_text(content)
    log_event(f"[PARSER] Found {len(links)} candidate nodes.")

    # Load Dead Cache
    dead_cache = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            dead_cache = set(line.strip() for line in f)

    # Filtering
    fresh_links = [l for l in links if get_md5(l) not in dead_cache]
    log_event(f"[PARSER] Processing {len(fresh_links)} fresh nodes.")

    # Audit Loop (Sequential to avoid port conflicts and CPU spikes in Actions)
    base_port = 10808
    for i, link in enumerate(fresh_links):
        res_link, cat, speed = await audit_single_link(link, base_port)
        
        if cat == "DEAD":
            with open(DEAD_CACHE_FILE, "a") as f: f.write(get_md5(res_link) + "\n")
        else:
            target_file = {"ELITE": ELITE_GEMINI, "STABLE": STABLE_CHAT, "FAST_NO_GOOGLE": FAST_NO_GOOGLE}.get(cat)
            with open(target_file, "a") as f:
                f.write(f"{res_link} # [{cat}] {speed}Mbps | {datetime.now().strftime('%d.%m %H:%M')}\n")

    log_event("--- AUDIT COMPLETE ---")

if __name__ == "__main__":
    asyncio.run(main_orchestrator())
