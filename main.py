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
    Advanced recursive extraction with "Smart Boundary Detection".
    Finds links even if they are concatenated or hidden in deep Base64.
    """
    found_links = set()
    
    def find_raw_links(s):
        # Improved regex with positive lookahead to stop before the next protocol or specific delimiters
        # This prevents "eating" multiple links into one string
        pattern = r'(vless|vmess|ss|trojan)://(?:(?!(vless|vmess|ss|trojan)://)[^\s"\'<>|])+?'
        # After extraction, we trim common trailing characters that shouldn't be there
        raw_matches = re.finditer(pattern, s, re.IGNORECASE)
        results = []
        for match in raw_matches:
            link = match.group(0)
            # Clean trailing junk like dots, commas or brackets that might be captured
            link = link.rstrip('.,;)]}>')
            results.append(link)
        return results

    # 1. Pre-cleaning
    # Remove HTML tags but keep content
    text = re.sub(r'<[^>]+>', ' ', text)
    # Remove Zero Width Space and invisible junk
    text = text.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '')
    
    # 2. Extract direct links
    for link in find_raw_links(text):
        if link.strip():
            found_links.add(link.strip())

    # 3. Recursive Base64 Extraction
    # Look for Base64 blocks. URL-safe Base64 uses '-' and '_'
    potential_blocks = re.findall(r'[a-zA-Z0-9+/=\-_]{32,}', text)
    
    for block in potential_blocks:
        clean_block = block.strip()
        # Fix padding for standard b64decode
        clean_block = clean_block.replace('-', '+').replace('_', '/')
        missing_padding = len(clean_block) % 4
        if missing_padding:
            clean_block += '=' * (4 - missing_padding)
            
        try:
            decoded_bytes = base64.b64decode(clean_block)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
            
            # If the decoded content contains protocol markers, process it
            if any(proto in decoded.lower() for proto in ["vless://", "vmess://", "ss://", "trojan://"]):
                for link in find_raw_links(decoded):
                    found_links.add(link.strip())
                
                # Recursive depth check to prevent infinite loops (Max 3 levels)
                # We use a simplified check here
                if "://" in decoded:
                    # Search again in the decoded result
                    inner_links = find_raw_links(decoded)
                    for i_link in inner_links:
                        found_links.add(i_link)
        except:
            continue

    return list(found_links)

async def fetch_external_subs(urls):
    """
    Downloads subscription content with browser emulation and error handling.
    """
    all_links = []
    timeout = aiohttp.ClientTimeout(total=45) # Increased for 5000+ nodes
    
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
                        log_event(f"  [+] Extracted {len(found)} nodes from this source.")
                        all_links.extend(found)
                    else:
                        log_event(f"  [!] HTTP Error {resp.status} for source.")
            except Exception as e:
                log_event(f"  [!] Fetch failed: {str(e)[:50]}")
    return all_links

def parse_proxy_link(link):
    """
    Advanced parser for VLESS and VMESS protocols.
    Includes aggressive JSON cleaning for pretty-printed VMESS configs.
    """
    try:
        # Handle VMESS
        if link.lower().startswith("vmess://"):
            parts = link[8:].split("#")
            b64_part = parts[0].strip()
            remark = parts[1] if len(parts) > 1 else "Unnamed"
            
            # Clean all whitespace from the Base64 string
            b64_part = re.sub(r'\s+', '', b64_part)
            # Fix padding
            b64_part += "=" * (-len(b64_part) % 4)
            
            decoded_str = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
            decoded_str = decoded_str.strip()
            
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
        await asyncio.sleep(2.5)
        
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
    raw_candidates = list(set(direct_configs + fetched_links))
    log_event(f"[PARSER] Raw candidates found: {len(raw_candidates)}")

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
    try:
        if os.path.exists(LIBRESPEED_PATH):
            os.chmod(LIBRESPEED_PATH, 0o755)
        if os.path.exists(XRAY_PATH):
            os.chmod(XRAY_PATH, 0o755)
    except:
        pass
        
    asyncio.run(main_orchestrator())
