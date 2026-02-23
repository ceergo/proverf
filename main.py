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

# Browser Emulation Headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

def log_event(msg):
    """
    Real-time logging for GitHub Actions with timestamps.
    """
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def get_md5(text):
    """
    Generates MD5 hash for a string to identify unique nodes.
    """
    return hashlib.md5(text.strip().encode()).hexdigest()

def manage_cache_lifecycle():
    """
    Manages the 72-hour cleanup cycle for the dead nodes cache.
    """
    now = datetime.now()
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    log_event("[CLEANUP] 72h cycle reached! Wiping dead_cache...")
                    if os.path.exists(DEAD_CACHE_FILE): 
                        os.remove(DEAD_CACHE_FILE)
                    with open(CLEANUP_LOG, "w") as f_out: 
                        f_out.write(now.isoformat())
            except Exception as e:
                log_event(f"[CLEANUP ERROR] {e}")
    else:
        with open(CLEANUP_LOG, "w") as f_out: 
            f_out.write(now.isoformat())

def extract_server_identity(node_string):
    """
    Industrial logic: Extracts Host:Port to prevent testing duplicates.
    Example: vless://uuid@1.2.3.4:443 -> 1.2.3.4:443
    """
    # Look for the pattern @host:port
    match = re.search(r'@([^:/]+):(\d+)', node_string)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    return node_string

def extract_configs_from_text(text):
    """
    Industrial recursive extraction logic.
    Identifies boundaries, decodes deep Base64, and deduplicates by Host:Port.
    """
    patterns = {
        'vless': r'vless://[^\s"\'<>|]+',
        'vmess': r'vmess://[^\s"\'<>|]+',
        'trojan': r'trojan://[^\s"\'<>|]+',
        'ss': r'ss://[^\s"\'<>|]+',
        'hy2': r'hy2://[^\s"\'<>|]+'
    }
    
    found_raw = []
    
    # 1. Clean invisible characters and HTML
    text = re.sub(r'<[^>]+>', ' ', text)
    text = text.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '')

    # 2. Direct extraction with industrial patterns
    for proto, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            # Clean trailing junk
            found_raw.append(m.rstrip('.,;)]}>'))

    # 3. Industrial Base64 block detection (looking for long enough blocks)
    b64_blocks = re.findall(r'[a-zA-Z0-9+/=\-_]{50,}', text)
    for block in b64_blocks:
        try:
            # Normalize for standard b64
            clean_b64 = block.replace('-', '+').replace('_', '/')
            clean_b64 += "=" * (-len(clean_b64) % 4)
            
            decoded = base64.b64decode(clean_b64).decode('utf-8', errors='ignore')
            
            # If protocol found inside, run extraction on decoded content
            if any(p in decoded.lower() for p in patterns.keys()):
                # Call internal logic for the decoded piece
                inner_configs = extract_configs_from_text(decoded)
                found_raw.extend(inner_configs)
        except:
            continue

    # 4. Deduplication based on Identity (Host:Port)
    unique_nodes = {}
    for node in found_raw:
        identity = extract_server_identity(node)
        # We prefer the first one found or we could add logic for "longest" string
        if identity not in unique_nodes:
            unique_nodes[identity] = node
            
    return list(unique_nodes.values())

async def fetch_external_subs(urls):
    """
    Downloads subscription content with browser emulation and error handling.
    """
    all_links = []
    timeout = aiohttp.ClientTimeout(total=45)
    
    async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout) as session:
        for url in urls:
            url = url.strip()
            if not url.startswith('http'): 
                continue
            
            log_event(f"[FETCH] Downloading: {url}")
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        found = extract_configs_from_text(content)
                        log_event(f"  [+] Extracted {len(found)} unique nodes from this source.")
                        all_links.extend(found)
                    else:
                        log_event(f"  [!] HTTP Error {resp.status} for source.")
            except Exception as e:
                log_event(f"  [!] Fetch failed: {str(e)[:50]}")
    return all_links

def parse_proxy_link(link):
    """
    Advanced parser for VLESS and VMESS protocols.
    """
    try:
        # Handle VMESS
        if link.lower().startswith("vmess://"):
            parts = link[8:].split("#")
            b64_part = parts[0].strip()
            remark = parts[1] if len(parts) > 1 else "Unnamed"
            
            b64_part = re.sub(r'\s+', '', b64_part)
            b64_part += "=" * (-len(b64_part) % 4)
            
            decoded_str = base64.b64decode(b64_part).decode('utf-8', errors='ignore').strip()
            
            json_match = re.search(r'\{.*\}', decoded_str, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                return None

            return {
                "protocol": "vmess",
                "host": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "sni": data.get("sni") or data.get("host", ""),
                "path": data.get("path", "/"),
                "security": data.get("tls", "none") if data.get("tls") != "" else "none",
                "type": data.get("net", "tcp"),
                "aid": data.get("aid", 0),
                "remark": data.get("ps", remark)
            }
            
        # Handle VLESS
        elif link.lower().startswith("vless://"):
            parsed = urlparse(link)
            netloc = parsed.netloc
            if "@" not in netloc: 
                return None
            
            user_info, host_port = netloc.split("@")
            uuid = user_info
            
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 443
            
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            
            return {
                "protocol": "vless",
                "uuid": uuid,
                "host": host,
                "port": port,
                "sni": params.get("sni", ""),
                "path": unquote(params.get("path", "/")),
                "security": params.get("security", "none"),
                "type": params.get("type", "tcp"),
                "flow": params.get("flow", ""),
                "pbk": params.get("pbk", ""),
                "sid": params.get("sid", ""),
                "fp": params.get("fp", "chrome")
            }
    except:
        return None
    return None

def generate_xray_config(parsed_link, local_port):
    """
    Generates a production-ready JSON config for Xray core.
    """
    protocol = parsed_link["protocol"]
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

    user = {"id": parsed_link["uuid"]}
    if protocol == "vless":
        user["encryption"] = "none"
        if parsed_link.get("flow"):
            user["flow"] = parsed_link["flow"]
    elif protocol == "vmess":
        user["alterId"] = parsed_link.get("aid", 0)
        user["security"] = "auto"
    
    outbound["settings"]["vnext"][0]["users"].append(user)
    ss = outbound["streamSettings"]
    
    if parsed_link["type"] == "ws":
        ss["wsSettings"] = {"path": parsed_link["path"]}
    elif parsed_link["type"] == "grpc":
        ss["grpcSettings"] = {"serviceName": parsed_link.get("path", "")}

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
    """
    Verifies if Google AI Studio (Gemini) is accessible via the proxy.
    """
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
        return (True, "OK") if "200" in res or "302" in res else (False, f"HTTP_{res}")
    except Exception as e:
        return False, f"Error: {str(e)[:20]}"

async def measure_speed_librespeed(socks_port):
    """
    Measures download speed and ping using the librespeed-cli.
    """
    try:
        if not os.path.exists(LIBRESPEED_PATH):
            return 0.0, 0.0
            
        cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{socks_port}", "--json", "--duration", "5"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            down_mbps = round(data.get("download", 0) / 1024 / 1024, 2)
            ping_ms = round(data.get("ping", 0), 1)
            return down_mbps, ping_ms
        return 0.0, 0.0
    except:
        return 0.0, 0.0

async def audit_single_link(link, local_port):
    """
    Complete audit cycle for a single node.
    """
    proxy_id = get_md5(link)[:8]
    parsed = parse_proxy_link(link)
    
    if not parsed: 
        return link, "DEAD", 0
    
    config = generate_xray_config(parsed, local_port)
    config_path = f"config_{proxy_id}.json"
    
    with open(config_path, "w") as f: 
        json.dump(config, f)
        
    xray_proc = None
    try:
        xray_proc = subprocess.Popen(
            [XRAY_PATH, "-c", config_path], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(3.0) # Slightly more wait for stability
        
        is_gemini, g_msg = await check_gemini_access(local_port)
        speed, ping = await measure_speed_librespeed(local_port)
        
        verdict = "DEAD"
        if is_gemini and speed >= 1.0: 
            verdict = "ELITE"
        elif is_gemini: 
            verdict = "STABLE"
        elif speed >= 2.5: 
            verdict = "FAST_NO_GOOGLE"
        
        log_event(f"[{proxy_id}] {verdict} | {speed}Mbps | {g_msg} | {parsed['protocol'].upper()}")
        
        xray_proc.terminate()
        xray_proc.wait()
        if os.path.exists(config_path): os.remove(config_path)
        
        return link, verdict, speed
        
    except Exception:
        if xray_proc: 
            xray_proc.terminate()
            xray_proc.wait()
        if os.path.exists(config_path): os.remove(config_path)
        return link, "DEAD", 0

async def main_orchestrator():
    """
    The main engine: loads sources, downloads content, filters cache, and audits nodes.
    """
    log_event("--- SIERRA X-RAY ORCHESTRATOR ONLINE ---")
    manage_cache_lifecycle()
    
    if not os.path.exists(RAW_LINKS_FILE):
        log_event(f"[ERROR] {RAW_LINKS_FILE} missing.")
        return

    with open(RAW_LINKS_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    
    sub_urls = [l for l in lines if l.startswith('http')]
    direct_configs = [l for l in lines if '://' in l and not l.startswith('http')]
    
    fetched_links = await fetch_external_subs(sub_urls)
    
    # Use industrial extractor on any raw text input as well
    processed_direct = []
    for raw_text in direct_configs:
        processed_direct.extend(extract_configs_from_text(raw_text))

    # Combine and final industrial deduplication
    raw_candidates = extract_configs_from_text("\n".join(fetched_links + processed_direct))
    log_event(f"[PARSER] Total unique nodes found: {len(raw_candidates)}")

    dead_cache = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            for line in f:
                h = line.strip()
                if h: dead_cache.add(h)
        log_event(f"[CACHE] Loaded {len(dead_cache)} dead hashes.")

    fresh_links = []
    for l in raw_candidates:
        link_hash = get_md5(l)
        if link_hash not in dead_cache:
            fresh_links.append(l)

    log_event(f"[PARSER] Filtering complete. {len(fresh_links)} unique fresh nodes to test.")

    base_port = 10808
    for rf in RESULT_FILES:
        if not os.path.exists(rf):
            with open(rf, "w") as f: pass

    # Robust Loop with logging
    for i, link in enumerate(fresh_links):
        log_event(f"[PROGRESS] Testing node {i+1}/{len(fresh_links)}...")
        try:
            res_link, cat, speed = await audit_single_link(link, base_port)
            
            if cat == "DEAD":
                with open(DEAD_CACHE_FILE, "a") as f: 
                    f.write(get_md5(res_link) + "\n")
            else:
                fname = {
                    "ELITE": ELITE_GEMINI, 
                    "STABLE": STABLE_CHAT, 
                    "FAST_NO_GOOGLE": FAST_NO_GOOGLE
                }.get(cat)
                
                if fname:
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

# Browser Emulation Headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

def log_event(msg):
    """
    Real-time logging for GitHub Actions with timestamps.
    """
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def get_md5(text):
    """
    Generates MD5 hash for a string to identify unique nodes.
    """
    return hashlib.md5(text.strip().encode()).hexdigest()

def manage_cache_lifecycle():
    """
    Manages the 72-hour cleanup cycle for the dead nodes cache.
    """
    now = datetime.now()
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    log_event("[CLEANUP] 72h cycle reached! Wiping dead_cache...")
                    if os.path.exists(DEAD_CACHE_FILE): 
                        os.remove(DEAD_CACHE_FILE)
                    with open(CLEANUP_LOG, "w") as f_out: 
                        f_out.write(now.isoformat())
            except Exception as e:
                log_event(f"[CLEANUP ERROR] {e}")
    else:
        with open(CLEANUP_LOG, "w") as f_out: 
            f_out.write(now.isoformat())

def extract_server_identity(node_string):
    """
    Industrial logic: Extracts Host:Port to prevent testing duplicates.
    Example: vless://uuid@1.2.3.4:443 -> 1.2.3.4:443
    """
    match = re.search(r'@([^:/]+):(\d+)', node_string)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    return node_string

def extract_configs_from_text(text):
    """
    Industrial recursive extraction logic.
    Identifies boundaries, decodes deep Base64, and deduplicates by Host:Port.
    """
    patterns = {
        'vless': r'vless://[^\s"\'<>|]+',
        'vmess': r'vmess://[^\s"\'<>|]+',
        'trojan': r'trojan://[^\s"\'<>|]+',
        'ss': r'ss://[^\s"\'<>|]+',
        'hy2': r'hy2://[^\s"\'<>|]+'
    }
    
    found_raw = []
    
    # Clean invisible characters and HTML
    text = re.sub(r'<[^>]+>', ' ', text)
    text = text.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '')

    # Direct extraction
    for proto, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            found_raw.append(m.rstrip('.,;)]}>'))

    # Industrial Base64 block detection
    b64_blocks = re.findall(r'[a-zA-Z0-9+/=\-_]{50,}', text)
    for block in b64_blocks:
        try:
            clean_b64 = block.replace('-', '+').replace('_', '/')
            clean_b64 += "=" * (-len(clean_b64) % 4)
            decoded = base64.b64decode(clean_b64).decode('utf-8', errors='ignore')
            
            if any(p in decoded.lower() for p in patterns.keys()):
                inner_configs = extract_configs_from_text(decoded)
                found_raw.extend(inner_configs)
        except:
            continue

    # Deduplication based on Identity (Host:Port)
    unique_nodes = {}
    for node in found_raw:
        identity = extract_server_identity(node)
        if identity not in unique_nodes:
            unique_nodes[identity] = node
            
    return list(unique_nodes.values())

async def fetch_external_subs(urls):
    """
    Downloads subscription content with browser emulation.
    """
    all_links = []
    timeout = aiohttp.ClientTimeout(total=60)
    
    async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout) as session:
        for url in urls:
            url = url.strip()
            if not url.startswith('http'): 
                continue
            
            log_event(f"[FETCH] Downloading: {url}")
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        found = extract_configs_from_text(content)
                        log_event(f"  [+] Extracted {len(found)} unique nodes.")
                        all_links.extend(found)
                    else:
                        log_event(f"  [!] HTTP Error {resp.status}")
            except Exception as e:
                log_event(f"  [!] Fetch failed: {str(e)[:50]}")
    return all_links

def parse_proxy_link(link):
    """
    Unified Industrial Parser for VLESS, VMESS, Trojan, Shadowsocks, and Hysteria2.
    """
    try:
        # 1. VMESS
        if link.lower().startswith("vmess://"):
            b64_part = link[8:].split("#")[0]
            b64_part = re.sub(r'\s+', '', b64_part)
            b64_part += "=" * (-len(b64_part) % 4)
            decoded_str = base64.b64decode(b64_part).decode('utf-8', errors='ignore').strip()
            data = json.loads(re.search(r'\{.*\}', decoded_str, re.DOTALL).group())
            return {
                "protocol": "vmess", "host": data.get("add"), "port": int(data.get("port", 443)),
                "uuid": data.get("id"), "sni": data.get("sni") or data.get("host", ""),
                "path": data.get("path", "/"), "security": data.get("tls", "none") if data.get("tls") != "" else "none",
                "type": data.get("net", "tcp"), "aid": data.get("aid", 0)
            }
            
        # 2. VLESS / Trojan / Hysteria2
        elif any(link.lower().startswith(p) for p in ["vless://", "trojan://", "hy2://"]):
            parsed = urlparse(link)
            proto = parsed.scheme.lower()
            netloc = parsed.netloc
            if "@" not in netloc: return None
            
            auth, host_port = netloc.split("@")
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host, port = host_port, 443
            
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            
            res = {
                "protocol": proto, "host": host, "port": port, "uuid": auth,
                "sni": params.get("sni", host), "path": unquote(params.get("path", "/")),
                "security": params.get("security", "none"), "type": params.get("type", "tcp")
            }
            if proto == "vless":
                res.update({
                    "flow": params.get("flow", ""), "pbk": params.get("pbk", ""), 
                    "sid": params.get("sid", ""), "fp": params.get("fp", "chrome")
                })
            return res

        # 3. Shadowsocks (SS)
        elif link.lower().startswith("ss://"):
            content = link[5:].split("#")[0]
            if "@" in content:
                b64_auth, host_port = content.split("@")
                b64_auth += "=" * (-len(b64_auth) % 4)
                auth_decoded = base64.b64decode(b64_auth).decode('utf-8')
                method, password = auth_decoded.split(":")
                host, port = host_port.split(":")
            else:
                content += "=" * (-len(content) % 4)
                decoded = base64.b64decode(content).decode('utf-8')
                auth, host_port = decoded.split("@")
                method, password = auth.split(":")
                host, port = host_port.split(":")
            
            return {
                "protocol": "shadowsocks", "host": host, "port": int(port),
                "method": method, "password": password, "security": "none"
            }
    except:
        return None
    return None

def generate_xray_config(parsed_link, local_port):
    """
    Generates a production-ready JSON config for Xray core for all 5 protocols.
    """
    proto = parsed_link["protocol"]
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": []
    }

    outbound = {"protocol": proto, "settings": {}, "streamSettings": {}}
    
    # Protocol Settings
    if proto in ["vless", "vmess", "trojan"]:
        outbound["settings"]["vnext"] = [{
            "address": parsed_link["host"], 
            "port": parsed_link["port"], 
            "users": [{"id": parsed_link["uuid"]}]
        }]
        if proto == "vless":
            outbound["settings"]["vnext"][0]["users"][0]["encryption"] = "none"
            if parsed_link.get("flow"): outbound["settings"]["vnext"][0]["users"][0]["flow"] = parsed_link["flow"]
        elif proto == "vmess":
            outbound["settings"]["vnext"][0]["users"][0]["security"] = "auto"
        elif proto == "trojan":
            outbound["settings"]["servers"] = [{"address": parsed_link["host"], "port": parsed_link["port"], "password": parsed_link["uuid"]}]
            del outbound["settings"]["vnext"]

    elif proto == "shadowsocks":
        outbound["settings"]["servers"] = [{"address": parsed_link["host"], "port": parsed_link["port"], "method": parsed_link["method"], "password": parsed_link["password"]}]

    elif proto == "hy2":
        outbound["protocol"] = "hysteria2"
        outbound["settings"]["server"] = parsed_link["host"]
        outbound["settings"]["port"] = parsed_link["port"]
        outbound["settings"]["auth"] = parsed_link["uuid"]

    # Stream Settings
    ss = outbound["streamSettings"]
    ss["network"] = parsed_link.get("type", "tcp")
    ss["security"] = parsed_link.get("security", "none")
    
    if parsed_link.get("type") == "ws":
        ss["wsSettings"] = {"path": parsed_link["path"]}
    elif parsed_link.get("type") == "grpc":
        ss["grpcSettings"] = {"serviceName": parsed_link.get("path", "")}

    if ss["security"] == "reality":
        ss["realitySettings"] = {
            "show": False, "fingerprint": parsed_link.get("fp", "chrome"), 
            "serverName": parsed_link.get("sni", ""), "publicKey": parsed_link.get("pbk", ""), 
            "shortId": parsed_link.get("sid", "")
        }
    elif ss["security"] == "tls":
        ss["tlsSettings"] = {"serverName": parsed_link.get("sni", ""), "allowInsecure": True}

    config["outbounds"].append(outbound)
    return config

async def check_gemini_access(socks_port):
    """
    Verifies if Google AI Studio (Gemini) is accessible via the proxy.
    """
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
        # 200 or 302 means page is reachable/redirecting (OK)
        return (True, "OK") if "200" in res or "302" in res else (False, f"HTTP_{res}")
    except Exception as e:
        return False, "Error"

async def measure_speed_librespeed(socks_port):
    """
    Measures speed and ping via librespeed-cli.
    """
    try:
        if not os.path.exists(LIBRESPEED_PATH):
            return 0.0, 0.0
        cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{socks_port}", "--json", "--duration", "5"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            down_mbps = round(data.get("download", 0) / 1024 / 1024, 2)
            ping_ms = round(data.get("ping", 0), 1)
            return down_mbps, ping_ms
        return 0.0, 0.0
    except:
        return 0.0, 0.0

async def audit_single_link(link, local_port):
    """
    Complete audit cycle for a single node.
    """
    proxy_id = get_md5(link)[:8]
    parsed = parse_proxy_link(link)
    if not parsed: 
        return link, "DEAD", 0
    
    config = generate_xray_config(parsed, local_port)
    config_path = f"config_{proxy_id}.json"
    
    with open(config_path, "w") as f: 
        json.dump(config, f)
        
    xray_proc = None
    try:
        # Start Xray
        xray_proc = subprocess.Popen(
            [XRAY_PATH, "-c", config_path], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(4.0) # Wait for core startup
        
        # Run checks
        is_gemini, g_msg = await check_gemini_access(local_port)
        speed, ping = await measure_speed_librespeed(local_port)
        
        verdict = "DEAD"
        if is_gemini and speed >= 1.0: 
            verdict = "ELITE"
        elif is_gemini: 
            verdict = "STABLE"
        elif speed >= 2.5: 
            verdict = "FAST_NO_GOOGLE"
        
        log_event(f"[{proxy_id}] {verdict} | {speed}Mbps | {g_msg} | {parsed['protocol'].upper()}")
        
        # Cleanup
        xray_proc.terminate()
        xray_proc.wait()
        if os.path.exists(config_path): os.remove(config_path)
        
        return link, verdict, speed
        
    except Exception:
        if xray_proc: 
            xray_proc.terminate()
            xray_proc.wait()
        if os.path.exists(config_path): os.remove(config_path)
        return link, "DEAD", 0

async def main_orchestrator():
    """
    The main engine: loads sources, audits nodes, saves results.
    """
    log_event("--- SIERRA X-RAY ORCHESTRATOR ONLINE ---")
    manage_cache_lifecycle()
    
    if not os.path.exists(RAW_LINKS_FILE):
        log_event(f"[ERROR] {RAW_LINKS_FILE} not found.")
        return

    # 1. Load Sources
    with open(RAW_LINKS_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    
    sub_urls = [l for l in lines if l.startswith('http')]
    direct_configs = [l for l in lines if '://' in l and not l.startswith('http')]
    
    # 2. Extract Nodes
    fetched_links = await fetch_external_subs(sub_urls)
    raw_candidates = extract_configs_from_text("\n".join(fetched_links + direct_configs))
    log_event(f"[PARSER] Total unique nodes found: {len(raw_candidates)}")

    # 3. Load Cache
    dead_cache = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            for line in f:
                h = line.strip()
                if h: dead_cache.add(h)

    # 4. Filter
    fresh_links = [l for l in raw_candidates if get_md5(l) not in dead_cache]
    log_event(f"[PARSER] Filtering complete. {len(fresh_links)} fresh nodes to test.")

    # 5. Result File Init
    for rf in RESULT_FILES:
        if not os.path.exists(rf):
            with open(rf, "w") as f: pass

    # 6. Audit Loop
    base_port = 10808
    for i, link in enumerate(fresh_links):
        log_event(f"[PROGRESS] Testing node {i+1}/{len(fresh_links)}...")
        try:
            res_link, cat, speed = await audit_single_link(link, base_port)
            
            if cat == "DEAD":
                with open(DEAD_CACHE_FILE, "a") as f: 
                    f.write(get_md5(res_link) + "\n")
            else:
                fname = {
                    "ELITE": ELITE_GEMINI, 
                    "STABLE": STABLE_CHAT, 
                    "FAST_NO_GOOGLE": FAST_NO_GOOGLE
                }.get(cat)
                
                if fname:
                    with open(fname, "a") as f:
                        f.write(f"{res_link} # [{cat}] {speed}Mbps | {datetime.now().strftime('%d.%m %H:%M')}\n")
        except Exception as e:
            log_event(f"[CRITICAL ERROR] Skipping node: {e}")
            continue

    log_event("--- AUDIT COMPLETE ---")

if __name__ == "__main__":
    # Ensure binaries are executable
    try:
        for p in [LIBRESPEED_PATH, XRAY_PATH]:
            if os.path.exists(p): os.chmod(p, 0o755)
    except:
        pass
        
    asyncio.run(main_orchestrator())      with open(fname, "a") as f:
                        f.write(f"{res_link} # [{cat}] {speed}Mbps | {datetime.now().strftime('%d.%m %H:%M')}\n")
        except Exception as e:
            log_event(f"[CRITICAL LOOP ERROR] {e}")
            continue

    log_event("--- AUDIT COMPLETE ---")

if __name__ == "__main__":
    try:
        if os.path.exists(LIBRESPEED_PATH):
            os.chmod(LIBRESPEED_PATH, 0o755)
        if os.path.exists(XRAY_PATH):
            os.chmod(XRAY_PATH, 0o755)
    except:
        pass
        
    asyncio.run(main_orchestrator())
