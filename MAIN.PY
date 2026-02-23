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
import random
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
import aiohttp

# --- INITIALIZE CONFIG ---
CONFIG_PATH = "CONFIG.JSON"
XRAY_TEMPLATE_PATH = "TEMPLATES/XRAY_BASE.JSON"

def load_config():
    if not os.path.exists(CONFIG_PATH):
        print(f"CRITICAL ERROR: {CONFIG_PATH} not found!")
        sys.exit(1)
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

CFG = load_config()

# Helper accessors
FILES = CFG["FILES"]
BINS = CFG["BINARIES"]
NET = CFG["NETWORK"]
LIMITS = CFG["THRESHOLDS"]
URLS = CFG["URLS"]

def log_event(msg):
    """Real-time logging with timestamps."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def kill_process_by_name(name):
    """Forcefully kills processes by name."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", f"{name}.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["pkill", "-9", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

def get_md5(text):
    """Generates unique hash for a node link."""
    try:
        if "vmess://" in text:
            normalized = text.strip().split('#')[0]
        else:
            normalized = text.strip().split('#')[0].split('?')[0]
        return hashlib.md5(normalized.encode()).hexdigest()
    except:
        return hashlib.md5(text.strip().encode()).hexdigest()

def manage_cache_lifecycle():
    """Cleans the dead nodes cache based on interval in config."""
    now = datetime.now()
    log_file = FILES["CLEANUP_LOG"]
    dead_file = FILES["DEAD_CACHE"]
    
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    log_event("🧹 72h Cycle: Purging dead nodes cache...")
                    if os.path.exists(dead_file): os.remove(dead_file)
                    with open(log_file, "w") as f_out: f_out.write(now.isoformat())
            except: pass
    else:
        with open(log_file, "w") as f_out: f_out.write(now.isoformat())

def extract_server_identity(link):
    """Identifies the server by Host:Port."""
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
        return urlparse(link).netloc or link
    except: return link

def clean_garbage(link):
    """Strictly cleans proxy links."""
    if not link: return ""
    protocol_match = re.search(r'(vless|vmess|trojan|ss|hy2)://', link, re.IGNORECASE)
    if protocol_match: link = link[protocol_match.start():]
    link = "".join(link.split())
    if "#" in link: link = link.split("#")[0]
    link = "".join(char for char in link if 31 < ord(char) < 127)
    return link

def extract_configs_from_text(text, depth=0):
    """Recursively extracts proxy links from text."""
    if depth > 1: return []
    pattern = r'(vless|vmess|trojan|ss|hy2)://[^\s"\'<>|]+'
    text = text.replace('\\n', ' ').replace('\\r', ' ').replace(',', ' ').replace('|', ' ')
    found_raw = []
    for m in re.finditer(pattern, text, re.IGNORECASE):
        link = clean_garbage(m.group(0).rstrip('.,;)]}>'))
        if '@' in link or link.startswith('vmess://'): found_raw.append(link)
    
    if not found_raw and len(text.strip()) > 50 and depth == 0:
        try:
            for chunk in re.findall(r'[a-zA-Z0-9+/]{50,}=*', text):
                padded = chunk + "=" * (-len(chunk) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if any(p in decoded.lower() for p in ['vless://', 'vmess://', 'trojan://']):
                    found_raw.extend(extract_configs_from_text(decoded, depth + 1))
        except: pass
    return list(set(found_raw))

async def fetch_external_subs(urls):
    """Asynchronously fetches content from subscription URLs."""
    all_links = []
    timeout = aiohttp.ClientTimeout(total=NET["TIMEOUT_SUB"], connect=10, sock_read=15)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        for url in urls:
            if not url.strip().startswith('http'): continue
            try:
                async with session.get(url.strip(), allow_redirects=True) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        all_links.extend(extract_configs_from_text(content))
            except: pass
    return all_links

def parse_proxy_link(link):
    """Universal parser for proxy protocols."""
    try:
        if link.lower().startswith("vmess://"):
            b64_part = re.sub(r'[^a-zA-Z0-9+/=]', '', link[8:].split("#")[0])
            b64_part += "=" * (-len(b64_part) % 4)
            data = json.loads(re.search(r'\{.*\}', base64.b64decode(b64_part).decode('utf-8', errors='ignore')).group())
            return {
                "protocol": "vmess", "host": data.get("add"), "port": int(data.get("port", 443)),
                "uuid": data.get("id"), "sni": data.get("sni") or data.get("host", ""),
                "path": data.get("path", "/"), "security": data.get("tls", "none") or "none",
                "type": data.get("net", "tcp"), "ps": data.get("ps", "VMESS")
            }
        elif any(link.lower().startswith(p) for p in ["vless://", "trojan://", "hy2://"]):
            parsed = urlparse(link)
            user_info, host_port = parsed.netloc.split("@")
            host, port = host_port.split(":") if ":" in host_port else (host_port, 443)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            return {
                "protocol": parsed.scheme.lower(), "uuid": user_info, "host": host, "port": int(port),
                "sni": params.get("sni", host), "path": unquote(params.get("path", "/")),
                "security": params.get("security", "none"), "type": params.get("type", "tcp"),
                "flow": params.get("flow", ""), "pbk": params.get("pbk", ""), "sid": params.get("sid", ""), "fp": params.get("fp", "chrome")
            }
        elif link.lower().startswith("ss://"):
            # Simplified SS parsing for brevity
            return {"protocol": "shadowsocks", "security": "none", "type": "tcp"}
    except: return None

def generate_xray_config(parsed_link, local_port):
    """Generates Xray config using a base template."""
    if not os.path.exists(XRAY_TEMPLATE_PATH):
        # Fallback if template missing
        return {"log": {"loglevel": "none"}, "inbounds": [{"port": local_port, "protocol": "socks"}]}
    
    with open(XRAY_TEMPLATE_PATH, "r") as f:
        config = json.load(f)
    
    config["inbounds"][0]["port"] = local_port
    protocol = parsed_link["protocol"]
    
    if protocol == "hy2":
        out = {"tag": "proxy", "protocol": "hysteria2", "settings": {"server": parsed_link["host"], "port": parsed_link["port"], "auth": parsed_link["uuid"]},
               "streamSettings": {"network": "udp", "security": "tls", "tlsSettings": {"serverName": parsed_link.get("sni", parsed_link["host"]), "allowInsecure": True}}}
    else:
        out = {"tag": "proxy", "protocol": protocol, "settings": {}, "streamSettings": {"network": parsed_link.get("type", "tcp"), "security": parsed_link.get("security", "none")}}
        if protocol in ["vless", "vmess"]:
            user = {"id": parsed_link["uuid"], "encryption": "none"} if protocol == "vless" else {"id": parsed_link["uuid"], "alterId": 0}
            out["settings"]["vnext"] = [{"address": parsed_link["host"], "port": parsed_link["port"], "users": [user]}]
        elif protocol == "trojan":
            out["settings"]["servers"] = [{"address": parsed_link["host"], "port": parsed_link["port"], "password": parsed_link["uuid"]}]
        
        ss = out["streamSettings"]
        if ss["network"] == "ws": ss["wsSettings"] = {"path": parsed_link["path"]}
        elif ss["network"] == "grpc": ss["grpcSettings"] = {"serviceName": parsed_link.get("path", "")}
        if ss["security"] == "reality":
            ss["realitySettings"] = {"show": False, "fingerprint": parsed_link.get("fp", "chrome"), "serverName": parsed_link.get("sni", ""), "publicKey": parsed_link.get("pbk", ""), "shortId": parsed_link.get("sid", "")}
        elif ss["security"] == "tls":
            ss["tlsSettings"] = {"serverName": parsed_link.get("sni", ""), "allowInsecure": True}
            
    config["outbounds"].insert(0, out)
    return config

async def check_gemini_access(socks_port):
    """Checks Gemini accessibility."""
    try:
        cmd = ["curl", "-s", "-L", "-k", "--proxy", f"socks5h://127.0.0.1:{socks_port}", URLS["GEMINI_CHECK"], "--connect-timeout", "10", "-m", "15", "-w", "%{http_code}"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        res = stdout.decode().strip()
        return ("200" in res or "302" in res), res
    except: return False, "ERR"

async def measure_speed_librespeed(socks_port):
    """Measures speed using Librespeed CLI."""
    try:
        if not os.path.exists(BINS["LIBRESPEED"]): return 0.0, 0.0
        cmd = [BINS["LIBRESPEED"], "--proxy", f"socks5://127.0.0.1:{socks_port}", "--json", "--duration", "15"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                return round(data.get("download", 0) / 1024 / 1024, 2), round(data.get("ping", 0), 1)
        except:
            if proc: proc.kill()
        return 0.0, 0.0
    except: return 0.0, 0.0

async def audit_single_link(link, local_port, semaphore):
    """Audit cycle for a single node."""
    async with semaphore:
        link_md5 = get_md5(link)
        parsed = parse_proxy_link(link)
        if not parsed: return link, "DEAD", 0
        
        config_path = f"CFG_{link_md5[:5]}_{local_port}.JSON"
        with open(config_path, "w") as f: json.dump(generate_xray_config(parsed, local_port), f)
        
        xray_proc = None
        try:
            xray_proc = subprocess.Popen([BINS["XRAY"], "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(NET["XRAY_WAIT"]) 
            
            is_gemini, _ = await check_gemini_access(local_port)
            speed, _ = await measure_speed_librespeed(local_port)
            
            cat = "DEAD"
            if is_gemini and speed >= LIMITS["SPEED_ELITE"]: cat = "ELITE"
            elif is_gemini or speed > LIMITS["SPEED_STABLE"]: cat = "STABLE"
            elif speed >= LIMITS["SPEED_FAST"]: cat = "FAST"
            
            log_event(f"Node {link_md5[:6]} -> {cat} ({speed} Mbps)")
            return link, cat, speed
        except Exception: return link, "ERROR", 0
        finally:
            if xray_proc:
                xray_proc.kill()
                xray_proc.wait()
            if os.path.exists(config_path): os.remove(config_path)

async def main_orchestrator():
    """Main Orchestrator Logic."""
    lock = FILES["LOCK_FILE"]
    if os.path.exists(lock) and time.time() - os.path.getmtime(lock) < 600:
        print("🚫 System locked.")
        sys.exit(0)
    
    with open(lock, "w") as f: f.write(str(os.getpid()))
    
    try:
        kill_process_by_name("xray")
        manage_cache_lifecycle()
        
        candidates = []
        if os.path.exists(FILES["TEMP_POOL"]):
            with open(FILES["TEMP_POOL"], "r") as f: candidates = json.load(f)
            
        if not candidates:
            if not os.path.exists(FILES["RAW_LINKS"]): return
            with open(FILES["RAW_LINKS"], "r") as f: raw_content = f.read()
            
            subs = [l.strip() for l in raw_content.split() if l.startswith('http')]
            fetched = await fetch_external_subs(subs)
            pool = list(set(extract_configs_from_text(raw_content) + fetched))
            
            dead_cache = set()
            if os.path.exists(FILES["DEAD_CACHE"]):
                with open(FILES["DEAD_CACHE"], "r") as f: dead_cache = {l.strip() for l in f}
            
            seen_ips = set()
            for l in pool:
                l_md5, l_ip = get_md5(l), extract_server_identity(l)
                if l_md5 not in dead_cache and l_ip not in seen_ips:
                    candidates.append(l)
                    seen_ips.add(l_ip)
            
            with open(FILES["TEMP_POOL"], "w") as f: json.dump(candidates, f)

        log_event(f"🔍 Candidates for audit: {len(candidates)}")
        if not candidates: return

        semaphore = asyncio.Semaphore(NET["MAX_CONCURRENT"])
        for i in range(0, len(candidates), NET["BATCH_SIZE"]):
            batch = candidates[i : i + NET["BATCH_SIZE"]]
            tasks = [audit_single_link(l, NET["BASE_PORT"] + (idx % NET["MAX_CONCURRENT"]), semaphore) for idx, l in enumerate(batch)]
            results = await asyncio.gather(*tasks)
            
            for link, cat, _ in results:
                if cat in ["DEAD", "ERROR"]:
                    with open(FILES["DEAD_CACHE"], "a") as f: f.write(get_md5(link) + "\n")
                elif cat in FILES["RESULTS"]:
                    with open(FILES["RESULTS"][cat], "a") as f: f.write(f"{link}\n")
            
            with open(FILES["TEMP_POOL"], "w") as f: json.dump(candidates[i+NET["BATCH_SIZE"]:], f)

        if os.path.exists(FILES["TEMP_POOL"]): os.remove(FILES["TEMP_POOL"])
        log_event("🏁 Audit Finished.")
        
    finally:
        if os.path.exists(lock): os.remove(lock)

if __name__ == "__main__":
    asyncio.run(main_orchestrator())
