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

def extract_configs_from_text(text):
    """
    Advanced recursive extraction. 
    Handles: Mixed plain text, pure Base64, and Base64 wrapped in garbage/HTML.
    Cleans invisible characters and standardizes output.
    """
    found_links = set()
    
    def find_raw_links(s):
        # Match standard proxy protocols: vless, vmess, ss, trojan
        pat = r'(vless|vmess|ss|trojan)://[^\s|#\^]+(?:#[^\s]*)?'
        return re.findall(pat, s, re.IGNORECASE)

    # 1. Clean HTML tags and invisible Unicode characters
    text = re.sub(r'<[^>]+>', ' ', text)
    # Remove Zero Width Space and other invisible junk
    text = text.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '')
    
    # 2. Extract any direct links from the text
    for link in find_raw_links(text):
        found_links.add(link.strip())

    # 3. Aggressive Base64 extraction
    # Look for strings that look like Base64 (alphanumeric + some symbols)
    # and are long enough to be a config list (at least 32 chars).
    potential_blocks = re.findall(r'[a-zA-Z0-9+/=\s\n\r]{32,}', text)
    
    for block in potential_blocks:
        # Crucial: Remove ALL whitespace that breaks b64decode
        clean_block = re.sub(r'\s+', '', block)
        
        # Base64 strings must have a length multiple of 4
        missing_padding = len(clean_block) % 4
        if missing_padding:
            clean_block += '=' * (4 - missing_padding)
            
        try:
            decoded_bytes = base64.b64decode(clean_block)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
            
            # If the decoded content has protocol markers, we process it
            if any(proto in decoded.lower() for proto in ["vless://", "vmess://", "ss://", "trojan://"]):
                # Recursive call to find links inside the decoded content
                for link in find_raw_links(decoded):
                    found_links.add(link.strip())
                
                # Check for nested Base64 (common in some subscription aggregators)
                # Only go deeper if we haven't found a massive amount of links yet
                if len(found_links) < 100:
                    nested = extract_configs_from_text(decoded)
                    for n_link in nested:
                        found_links.add(n_link)
        except:
            continue

    return list(found_links)

async def fetch_external_subs(urls):
    """
    Downloads subscription content with browser emulation and error handling.
    """
    all_links = []
    timeout = aiohttp.ClientTimeout(total=30) # Increased timeout for large 5000+ lists
    
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
                        log_event(f"  [+] Extracted {len(found)} nodes.")
                        all_links.extend(found)
                    else:
                        log_event(f"  [!] HTTP Error {resp.status} for {url[:40]}...")
            except Exception as e:
                log_event(f"  [!] Fetch failed for {url[:40]}... -> {str(e)[:50]}")
    return all_links

def parse_proxy_link(link):
    """
    Advanced parser for VLESS and VMESS protocols.
    Includes aggressive JSON cleaning for pretty-printed VMESS configs.
    """
    try:
        # Handle VMESS
        if link.lower().startswith("vmess://"):
            b64_part = link[8:].split("#")[0].strip()
            # Clean all whitespace from the Base64 string
            b64_part = re.sub(r'\s+', '', b64_part)
            # Fix padding
            b64_part += "=" * (-len(b64_part) % 4)
            
            decoded_str = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
            # Clean JSON string from potential junk before parsing
            decoded_str = decoded_str.strip()
            # Handle cases where JSON might be wrapped in more junk
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
                "remark": data.get("ps", "Unnamed")
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
    except Exception as e:
        # Silent fail for individual link parsing
        return None
    return None

def generate_xray_config(parsed_link, local_port):
    """
    Generates a production-ready JSON config for Xray core.
    Supports Reality, TLS, WebSocket, and gRPC.
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
    
    # Network specific settings
    if parsed_link["type"] == "ws":
        ss["wsSettings"] = {"path": parsed_link["path"]}
    elif parsed_link["type"] == "grpc":
        ss["grpcSettings"] = {"serviceName": parsed_link.get("path", "")}

    # Security specific settings
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
        # Using curl for a reliable SOCKS5h check
        cmd = [
            "curl", "-s", "-L", "-k", "--proxy", proxy_url,
            GEMINI_CHECK_URL, "--connect-timeout", "10", "-m", "15",
            "-w", "%{http_code}"
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        res = stdout.decode().strip()
        # Look for 200 OK or 302 Redirect (often happens with auth gates)
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
        # Start Xray Core
        xray_proc = subprocess.Popen(
            [XRAY_PATH, "-c", config_path], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        # Give Xray time to establish connection
        await asyncio.sleep(2.5)
        
        # Test Gemini Access
        is_gemini, g_msg = await check_gemini_access(local_port)
        
        # Test Speed (only if Gemini works or for Fast category)
        speed, ping = await measure_speed_librespeed(local_port)
        
        # Logic for classification
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
        
    except Exception as e:
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
    
    # 1. Read sources from raw_links.txt
    if not os.path.exists(RAW_LINKS_FILE):
        log_event(f"[ERROR] {RAW_LINKS_FILE} missing.")
        return

    with open(RAW_LINKS_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    
    sub_urls = [l for l in lines if l.startswith('http')]
    direct_configs = [l for l in lines if '://' in l and not l.startswith('http')]
    
    # 2. Fetch external subscriptions
    fetched_links = await fetch_external_subs(sub_urls)
    
    # 3. Deduplication and Initial Cleanup
    raw_candidates = list(set(direct_configs + fetched_links))
    log_event(f"[PARSER] Raw candidates found: {len(raw_candidates)}")

    # 4. Filter against Dead Cache
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

    # 5. Execute Audit
    # We use a fixed port for simplicity, but could be dynamic for parallel testing
    base_port = 10808
    
    # Clear result files from previous run if needed or just append
    # Here we append to maintain history if requested, but usually, we start fresh
    for rf in RESULT_FILES:
        if not os.path.exists(rf):
            with open(rf, "w") as f: pass

    for link in fresh_links:
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

    log_event("--- AUDIT COMPLETE ---")

if __name__ == "__main__":
    # Ensure binary execution permissions (specific to Linux environments like GitHub Actions)
    try:
        if os.path.exists(LIBRESPEED_PATH):
            os.chmod(LIBRESPEED_PATH, 0o755)
        if os.path.exists(XRAY_PATH):
            os.chmod(XRAY_PATH, 0o755)
    except:
        pass
        
    asyncio.run(main_orchestrator())
