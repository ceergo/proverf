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
from urllib.parse import urlparse, parse_qs, unquote
import aiohttp

# --- CONFIGURATION ---
RAW_LINKS_FILE = "raw_links.txt"
DEAD_CACHE_FILE = "dead_cache.txt"
CLEANUP_LOG = "last_cleanup.txt"

# Output files
ELITE_GEMINI = "Elite_Gemini.txt"
STABLE_CHAT = "Stable_Chat.txt"
FAST_NO_GOOGLE = "Fast_NoGoogle.txt"

RESULT_FILES = [ELITE_GEMINI, STABLE_CHAT, FAST_NO_GOOGLE]

# Paths for Binaries
XRAY_PATH = "xray" 
LIBRESPEED_PATH = "./librespeed-cli" 

# Critical Links
GEMINI_CHECK_URL = "https://aistudio.google.com/app"

def log_event(msg):
    """Real-time logging for GitHub Actions."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def get_md5(text):
    return hashlib.md5(text.strip().encode()).hexdigest()

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
    """Extracts proxy links and handles Base64 decoding if necessary."""
    results = []
    
    # Try decoding as a whole block first
    try:
        decoded = base64.b64decode(text.strip()).decode('utf-8', errors='ignore')
        if "://" in decoded:
            text = decoded
    except:
        pass
        
    pattern = r'(vless|vmess|ss|trojan)://[^\s|#\^]+(?:#[^\s]*)?'
    found = re.findall(pattern, text, re.IGNORECASE)
    results.extend(found)
    
    return list(set(results))

async def fetch_external_subs(urls):
    """Downloads content from external subscription URLs."""
    all_links = []
    async with aiohttp.ClientSession() as session:
        for url in urls:
            url = url.strip()
            if not url.startswith('http'): continue
            log_event(f"[FETCH] Downloading subscription: {url}")
            try:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        found = extract_configs_from_text(content)
                        log_event(f"  [+] Found {len(found)} nodes in sub.")
                        all_links.extend(found)
                    else:
                        log_event(f"  [!] Sub returned status {resp.status}")
            except Exception as e:
                log_event(f"  [!] Failed to fetch sub: {e}")
    return all_links

def parse_proxy_link(link):
    """Advanced parser for VLESS and VMESS protocols."""
    try:
        if link.startswith("vmess://"):
            # VMESS is usually base64 encoded JSON
            b64_data = link.replace("vmess://", "").split("#")[0]
            # Fix padding if needed
            b64_data += "=" * (-len(b64_data) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            return {
                "protocol": "vmess",
                "host": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "sni": data.get("sni") or data.get("host", ""),
                "path": data.get("path", "/"),
                "security": data.get("tls", "none"),
                "type": data.get("net", "tcp"),
                "aid": data.get("aid", 0),
                "remark": data.get("ps", "Unnamed")
            }
            
        elif link.startswith("vless://"):
            parsed = urlparse(link)
            netloc = parsed.netloc
            if "@" not in netloc: return None
            
            # Extract User Info and Host/Port
            user_info, host_port = netloc.split("@")
            uuid = user_info
            
            # Handle cases with or without explicit port
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 443
            
            # Parse Query Params
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            
            return {
                "protocol": "vless",
                "uuid": uuid,
                "host": host,
                "port": port,
                "sni": params.get("sni", ""),
                "path": params.get("path", "/"),
                "security": params.get("security", "none"),
                "type": params.get("type", "tcp"),
                "flow": params.get("flow", ""),
                "pbk": params.get("pbk", ""),
                "sid": params.get("sid", ""),
                "fp": params.get("fp", "chrome")
            }
    except Exception as e:
        return None
    return None

def generate_xray_config(parsed_link, local_port):
    """Generates a specialized JSON config for Xray based on protocol and security."""
    protocol = parsed_link["protocol"]
    
    # Base configuration
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": []
    }

    # Outbound settings
    outbound = {
        "protocol": protocol,
        "settings": {
            "vnext": [{
                "address": parsed_link["host"],
                "port": parsed_link["port"],
                "users": []
            }]
        },
        "streamSettings": {
            "network": parsed_link["type"],
            "security": parsed_link["security"]
        }
    }

    # Protocol-specific User object
    user = {"id": parsed_link["uuid"]}
    if protocol == "vless":
        user["encryption"] = "none"
        if parsed_link.get("flow"):
            user["flow"] = parsed_link["flow"]
    elif protocol == "vmess":
        user["alterId"] = parsed_link.get("aid", 0)
        user["security"] = "auto"
    
    outbound["settings"]["vnext"][0]["users"].append(user)

    # Stream Settings (Transport & Security)
    ss = outbound["streamSettings"]
    
    # 1. Transport Logic
    if parsed_link["type"] == "ws":
        ss["wsSettings"] = {"path": parsed_link["path"]}
    elif parsed_link["type"] == "grpc":
        ss["grpcSettings"] = {"serviceName": parsed_link.get("path", "")}

    # 2. Security Logic (Reality / TLS)
    if parsed_link["security"] == "reality":
        ss["realitySettings"] = {
            "show": False,
            "fingerprint": parsed_link.get("fp", "chrome"),
            "serverName": parsed_link.get("sni", ""),
            "publicKey": parsed_link.get("pbk", ""),
            "shortId": parsed_link.get("sid", ""),
            "spiderX": ""
        }
    elif parsed_link["security"] == "tls":
        ss["tlsSettings"] = {
            "serverName": parsed_link.get("sni", ""),
            "allowInsecure": True,
            "fingerprint": parsed_link.get("fp", "chrome")
        }

    config["outbounds"].append(outbound)
    return config

async def check_gemini_access(socks_port):
    try:
        proxy_url = f"socks5h://127.0.0.1:{socks_port}"
        cmd = [
            "curl", "-s", "-L", "-k", "--proxy", proxy_url,
            GEMINI_CHECK_URL, "--connect-timeout", "10", "-m", "15",
            "-w", "%{http_code}"
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        res = stdout.decode().strip()
        return (True, "OK") if "200" in res else (False, f"HTTP_{res}")
    except:
        return False, "Error"

async def measure_speed_librespeed(socks_port):
    try:
        cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{socks_port}", "--json", "--duration", "5"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            return round(data.get("download", 0) / 1024 / 1024, 2), round(data.get("ping", 0), 1)
        return 0, 0
    except:
        return 0, 0

async def audit_single_link(link, local_port):
    proxy_id = get_md5(link)[:8]
    parsed = parse_proxy_link(link)
    if not parsed: 
        return link, "DEAD", 0
    
    config = generate_xray_config(parsed, local_port)
    config_path = f"config_{proxy_id}.json"
    with open(config_path, "w") as f: json.dump(config, f)
        
    try:
        xray_proc = subprocess.Popen([XRAY_PATH, "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(2)
        
        is_gemini, g_msg = await check_gemini_access(local_port)
        speed, ping = await measure_speed_librespeed(local_port)
        
        verdict = "DEAD"
        if is_gemini and speed >= 1.0: verdict = "ELITE"
        elif is_gemini: verdict = "STABLE"
        elif speed >= 3.0: verdict = "FAST_NO_GOOGLE"
        
        log_event(f"[{proxy_id}] {verdict} | {speed}Mbps | {g_msg} | {parsed['protocol'].upper()}")
        
        xray_proc.terminate()
        os.remove(config_path)
        return link, verdict, speed
    except:
        if 'xray_proc' in locals(): xray_proc.terminate()
        return link, "DEAD", 0

async def main_orchestrator():
    log_event("--- SIERRA X-RAY ORCHESTRATOR ONLINE ---")
    manage_cache_lifecycle()
    
    if not os.path.exists(RAW_LINKS_FILE):
        log_event("[ERROR] raw_links.txt missing.")
        return

    with open(RAW_LINKS_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    
    sub_urls = [l for l in lines if l.startswith('http')]
    direct_configs = [l for l in lines if '://' in l and not l.startswith('http')]
    
    fetched_links = await fetch_external_subs(sub_urls)
    total_candidates = list(set(direct_configs + fetched_links))
    
    log_event(f"[PARSER] Total candidate nodes after extraction: {len(total_candidates)}")

    dead_cache = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line: dead_cache.add(line)
        log_event(f"[CACHE] Loaded {len(dead_cache)} dead hashes.")

    fresh_links = []
    for l in total_candidates:
        link_hash = get_md5(l)
        if link_hash not in dead_cache:
            fresh_links.append(l)
        else:
            # Optional debug: log_event(f"  [-] Skipping cached: {link_hash}")
            pass

    log_event(f"[PARSER] Processing {len(fresh_links)} fresh nodes.")

    base_port = 10808
    for link in fresh_links:
        res_link, cat, speed = await audit_single_link(link, base_port)
        if cat == "DEAD":
            with open(DEAD_CACHE_FILE, "a") as f: f.write(get_md5(res_link) + "\n")
        else:
            fname = {"ELITE": ELITE_GEMINI, "STABLE": STABLE_CHAT, "FAST_NO_GOOGLE": FAST_NO_GOOGLE}.get(cat)
            with open(fname, "a") as f:
                f.write(f"{res_link} # [{cat}] {speed}Mbps | {datetime.now().strftime('%d.%m %H:%M')}\n")

    log_event("--- AUDIT COMPLETE ---")

if __name__ == "__main__":
    asyncio.run(main_orchestrator())
