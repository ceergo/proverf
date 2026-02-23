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

# Concurrency & Networking
MAX_CONCURRENT_TESTS = 5  # Number of parallel Xray instances
BATCH_SIZE = 10           # Process nodes in batches to avoid task accumulation
BASE_PORT = 10800         # Starting port for local SOCKS5 proxies

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
    
    # 1. Clean invisible characters and HTML
    text = re.sub(r'<[^>]+>', ' ', text)
    text = text.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '')

    # 2. Direct extraction with industrial patterns
    for proto, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            found_raw.append(m.rstrip('.,;)]}>'))

    # 3. Industrial Base64 block detection
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

    # 4. Deduplication based on Identity (Host:Port)
    unique_nodes = {}
    for node in found_raw:
        identity = extract_server_identity(node)
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
    Advanced parser for VLESS, VMESS, Trojan, SS and Hy2 protocols.
    """
    try:
        # 1. Handle VMESS
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
            
        # 2. Handle VLESS, Trojan and Hysteria2 (URL-based)
        elif any(link.lower().startswith(p) for p in ["vless://", "trojan://", "hy2://"]):
            parsed = urlparse(link)
            proto = parsed.scheme.lower()
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
                port = 443 if proto != "hy2" else 443
            
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            
            return {
                "protocol": proto,
                "uuid": uuid,
                "host": host,
                "port": port,
                "sni": params.get("sni", host),
                "path": unquote(params.get("path", "/")),
                "security": params.get("security", "none"),
                "type": params.get("type", "tcp"),
                "flow": params.get("flow", ""),
                "pbk": params.get("pbk", ""),
                "sid": params.get("sid", ""),
                "fp": params.get("fp", "chrome")
            }

        # 3. Handle Shadowsocks (SS)
        elif link.lower().startswith("ss://"):
            parts = link[5:].split("#")
            main_part = parts[0]
            remark = unquote(parts[1]) if len(parts) > 1 else "SS-Node"
            
            if "@" in main_part:
                user_info, host_port = main_part.split("@")
                if ":" in user_info:
                    method, password = user_info.split(":")
                else:
                    user_info += "=" * (-len(user_info) % 4)
                    decoded_auth = base64.b64decode(user_info).decode('utf-8')
                    method, password = decoded_auth.split(":")
                
                host, port = host_port.split(":")
            else:
                main_part += "=" * (-len(main_part) % 4)
                decoded = base64.b64decode(main_part).decode('utf-8')
                user_info, host_port = decoded.split("@")
                method, password = user_info.split(":")
                host, port = host_port.split(":")

            return {
                "protocol": "shadowsocks",
                "host": host,
                "port": int(port),
                "method": method,
                "password": password,
                "remark": remark,
                "security": "none",
                "type": "tcp"
            }
            
    except Exception:
        return None
    return None

def generate_xray_config(parsed_link, local_port):
    """
    Generates a production-ready JSON config for Xray core for all 5 protocols.
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

    if protocol == "hy2":
        config["outbounds"].append({
            "protocol": "hysteria2",
            "settings": {
                "server": parsed_link["host"],
                "port": parsed_link["port"],
                "auth": parsed_link["uuid"]
            },
            "streamSettings": {
                "network": "udp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": parsed_link.get("sni", parsed_link["host"]),
                    "allowInsecure": True
                }
            }
        })
        return config

    outbound = {
        "protocol": protocol,
        "settings": {},
        "streamSettings": {
            "network": parsed_link.get("type", "tcp"),
            "security": parsed_link.get("security", "none")
        }
    }

    if protocol in ["vless", "vmess"]:
        user = {"id": parsed_link["uuid"]}
        if protocol == "vless":
            user["encryption"] = "none"
            if parsed_link.get("flow"):
                user["flow"] = parsed_link["flow"]
        else:
            user["alterId"] = parsed_link.get("aid", 0)
            user["security"] = "auto"

        outbound["settings"]["vnext"] = [{
            "address": parsed_link["host"],
            "port": parsed_link["port"],
            "users": [user]
        }]
    
    elif protocol == "trojan":
        outbound["settings"]["servers"] = [{
            "address": parsed_link["host"],
            "port": parsed_link["port"],
            "password": parsed_link["uuid"]
        }]
    
    elif protocol == "shadowsocks":
        outbound["settings"]["servers"] = [{
            "address": parsed_link["host"],
            "port": parsed_link["port"],
            "method": parsed_link["method"],
            "password": parsed_link["password"]
        }]

    ss = outbound["streamSettings"]
    if ss["network"] == "ws":
        ss["wsSettings"] = {"path": parsed_link["path"]}
    elif ss["network"] == "grpc":
        ss["grpcSettings"] = {"serviceName": parsed_link.get("path", "")}

    if ss["security"] == "reality":
        ss["realitySettings"] = {
            "show": False,
            "fingerprint": parsed_link.get("fp", "chrome"),
            "serverName": parsed_link.get("sni", ""),
            "publicKey": parsed_link.get("pbk", ""),
            "shortId": parsed_link.get("sid", ""),
            "spiderX": ""
        }
    elif ss["security"] == "tls":
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

async def audit_single_link(link, local_port, semaphore):
    """
    Complete audit cycle for a single node with concurrency control and robust cleanup.
    """
    async with semaphore:
        await asyncio.sleep(random.uniform(0.5, 2.0))
        
        proxy_id = get_md5(link)[:8]
        parsed = parse_proxy_link(link)
        
        if not parsed: 
            return link, "DEAD", 0
        
        config = generate_xray_config(parsed, local_port)
        config_path = f"config_{proxy_id}_{local_port}.json"
        
        with open(config_path, "w") as f: 
            json.dump(config, f)
            
        xray_proc = None
        try:
            # Launch Xray core as a subprocess
            xray_proc = subprocess.Popen(
                [XRAY_PATH, "-c", config_path], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            
            # Allow time for initialization
            await asyncio.sleep(4.0)
            
            # Step 1: Gemini Check
            is_gemini, g_msg = await check_gemini_access(local_port)
            
            # Step 2: Speed Check
            speed, ping = await measure_speed_librespeed(local_port)
            
            # Step 3: Categorization
            verdict = "DEAD"
            if is_gemini and speed >= 1.0: 
                verdict = "ELITE"
            elif is_gemini: 
                verdict = "STABLE"
            elif speed >= 2.5: 
                verdict = "FAST_NO_GOOGLE"
            
            log_event(f"[{proxy_id}|Port:{local_port}] {verdict} | {speed}Mbps | {g_msg} | {parsed['protocol'].upper()}")
            return link, verdict, speed
            
        except Exception as e:
            log_event(f"[{proxy_id}] Task error: {e}")
            return link, "DEAD", 0
        finally:
            # GURANTEED CLEANUP: Kill Xray and remove config file
            if xray_proc:
                try:
                    xray_proc.kill()
                    xray_proc.wait(timeout=2)
                except:
                    pass
            if os.path.exists(config_path):
                try:
                    os.remove(config_path)
                except:
                    pass

async def main_orchestrator():
    """
    The main engine with BATCH PROCESSING to prevent GitHub Actions timeout/cancellation.
    """
    log_event("--- SIERRA X-RAY BATCH ORCHESTRATOR ONLINE ---")
    manage_cache_lifecycle()
    
    if not os.path.exists(RAW_LINKS_FILE):
        log_event(f"[ERROR] {RAW_LINKS_FILE} missing.")
        return

    with open(RAW_LINKS_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    
    sub_urls = [l for l in lines if l.startswith('http')]
    direct_configs = [l for l in lines if '://' in l and not l.startswith('http')]
    
    fetched_links = await fetch_external_subs(sub_urls)
    
    processed_direct = []
    for raw_text in direct_configs:
        processed_direct.extend(extract_configs_from_text(raw_text))

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

    log_event(f"[PARSER] Filtering complete. {len(fresh_links)} fresh nodes to test.")

    for rf in RESULT_FILES:
        if not os.path.exists(rf):
            with open(rf, "w") as f: pass

    # Batch Processing Logic
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
    total_nodes = len(fresh_links)
    
    for i in range(0, total_nodes, BATCH_SIZE):
        batch = fresh_links[i : i + BATCH_SIZE]
        log_event(f"[SYSTEM] Processing batch {i//BATCH_SIZE + 1} ({i+1}-{min(i+BATCH_SIZE, total_nodes)} of {total_nodes})")
        
        tasks = []
        for j, link in enumerate(batch):
            assigned_port = BASE_PORT + (j % MAX_CONCURRENT_TESTS)
            tasks.append(audit_single_link(link, assigned_port, semaphore))
        
        # Execute current batch
        batch_results = await asyncio.gather(*tasks)
        
        # Save batch results immediately to avoid data loss on crash
        for res_link, cat, speed in batch_results:
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

    log_event("--- SIERRA AUDIT COMPLETE ---")

if __name__ == "__main__":
    try:
        if os.path.exists(LIBRESPEED_PATH):
            os.chmod(LIBRESPEED_PATH, 0o755)
        if os.path.exists(XRAY_PATH):
            os.chmod(XRAY_PATH, 0o755)
    except Exception as e:
        log_event(f"[BIN-WARN] Chmod failed: {e}")
        
    asyncio.run(main_orchestrator())
