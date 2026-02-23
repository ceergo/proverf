import os
import json
import subprocess
import hashlib
import time
import asyncio
import re
import sys
import base64
import random
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
import aiohttp

# --- INTERNAL IMPORTS ---
from config import Config
from logger import stats, log_event, log_node_details, log_error_details

# Global lock for file operations
file_lock = asyncio.Lock()

# --- UTILS ---
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
        # Normalize: remove remarks and parameters for cleaner hashing
        if "vmess://" in text:
            normalized = text.strip().split('#')[0]
        else:
            normalized = text.strip().split('#')[0].split('?')[0]
        return hashlib.md5(normalized.encode()).hexdigest()
    except:
        return hashlib.md5(text.strip().encode()).hexdigest()

def manage_cache_lifecycle():
    """Wipes dead cache every 72 hours."""
    now = datetime.now()
    if os.path.exists(Config.CLEANUP_LOG):
        with open(Config.CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    log_event("🧹 Ротация кэша: Очистка списка мертвых нод...", "SYSTEM")
                    if os.path.exists(Config.DEAD_CACHE_FILE): 
                        os.remove(Config.DEAD_CACHE_FILE)
                    with open(Config.CLEANUP_LOG, "w") as f_out: 
                        f_out.write(now.isoformat())
            except: pass
    else:
        with open(Config.CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())

# --- DATA PARSING & EXTRACTION ---
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

def clean_garbage(link):
    """Strips invisible characters and junk from links."""
    if not link: return ""
    link = link.strip()
    protocol_match = re.search(Config.CLEANUP_PATTERN, link, re.IGNORECASE)
    if protocol_match: link = link[protocol_match.start():]
    link = "".join(char for char in link if 32 < ord(char) < 127)
    if not link.lower().startswith("vmess://") and "#" in link:
        link = link.split("#", 1)[0]
    return link

def extract_configs_from_text(text, depth=0):
    """Deep recursive link extractor (Regex + Base64)."""
    if depth > 1 or not text: return []
    clean_text = text.replace('\\n', '\n').replace('\\r', '\r')
    found_raw = []
    
    for m in re.finditer(Config.PROTOCOL_PATTERN, clean_text, re.IGNORECASE):
        l = clean_garbage(m.group(0))
        if l: found_raw.append(l)

    if not found_raw and depth == 0:
        try:
            trimmed = clean_text.strip()
            if len(trimmed) > 20 and re.match(r'^[a-zA-Z0-9+/=\s]+$', trimmed):
                padded = trimmed.replace('\n', '').replace('\r', '') + "=" * (-len(trimmed) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                found_raw.extend(extract_configs_from_text(decoded, depth + 1))
        except: pass
    return list(set(found_raw))

def parse_proxy_link(link):
    """Converts raw URI to structured dict for Xray."""
    try:
        if link.lower().startswith("vmess://"):
            b64 = re.sub(r'[^a-zA-Z0-9+/=]', '', link[8:].split("#")[0])
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(re.search(r'\{.*\}', base64.b64decode(b64).decode('utf-8', errors='ignore')).group())
            return {
                "protocol": "vmess", "host": data.get("add"), "port": int(data.get("port", 443)),
                "uuid": data.get("id"), "sni": data.get("sni") or data.get("host", ""),
                "path": data.get("path", "/"), "security": data.get("tls", "none") or "none",
                "type": data.get("net", "tcp"), "aid": data.get("aid", 0), "remark": data.get("ps", "VMESS")
            }
        elif any(link.lower().startswith(p) for p in ["vless://", "trojan://", "hy2://"]):
            parsed = urlparse(link)
            proto = parsed.scheme.lower()
            user_info, host_port = parsed.netloc.split("@")
            host, port = host_port.split(":") if ":" in host_port else (host_port, 443)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            return {
                "protocol": proto, "uuid": user_info, "host": host, "port": int(port),
                "sni": params.get("sni", host), "path": unquote(params.get("path", "/")),
                "security": params.get("security", "none"), "type": params.get("type", "tcp"),
                "fp": params.get("fp", "chrome"), "remark": unquote(parsed.fragment or proto.upper()),
                "pbk": params.get("pbk", ""), "sid": params.get("sid", "")
            }
        elif link.lower().startswith("ss://"):
            parts = link[5:].split("#")
            main, remark = parts[0], (unquote(parts[1]) if len(parts) > 1 else "SS")
            if "@" in main:
                auth, hp = main.split("@")
                method_pass = base64.b64decode(auth + "="*(-len(auth)%4)).decode()
                m, p = method_pass.split(":") if ":" in method_pass else (method_pass, "")
                h, prt = hp.split(":")
            else:
                decoded = base64.b64decode(main + "="*(-len(main)%4)).decode()
                auth, hp = decoded.split("@")
                m, p = auth.split(":")
                h, prt = hp.split(":")
            return {"protocol": "shadowsocks", "host": h, "port": int(prt), "method": m, "password": p, "security": "none", "type": "tcp", "remark": remark}
    except: return None

# --- TESTING ENGINE ---
def generate_xray_config(parsed, local_port):
    """Xray JSON config factory."""
    proto = parsed["protocol"]
    config = {
        "log": {"loglevel": "none"},
        "dns": {"servers": ["8.8.8.8"], "queryStrategy": "UseIPv4"},
        "inbounds": [{
            "port": local_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    }
    
    if proto == "hy2":
        proxy = {"tag": "proxy", "protocol": "hysteria2", "settings": {"server": parsed["host"], "port": parsed["port"], "auth": parsed["uuid"]},
                 "streamSettings": {"network": "udp", "security": "tls", "tlsSettings": {"serverName": parsed.get("sni", parsed["host"]), "allowInsecure": True}}}
    else:
        proxy = {"tag": "proxy", "protocol": proto, "settings": {}, "streamSettings": {"network": parsed.get("type", "tcp"), "security": parsed.get("security", "none")}}
        user = {"id": parsed["uuid"], "encryption": "none"} if proto == "vless" else {"id": parsed["uuid"], "alterId": 0}
        if proto in ["vless", "vmess"]:
            proxy["settings"]["vnext"] = [{"address": parsed["host"], "port": parsed["port"], "users": [user]}]
        elif proto == "trojan":
            proxy["settings"]["servers"] = [{"address": parsed["host"], "port": parsed["port"], "password": parsed["uuid"]}]
        elif proto == "shadowsocks":
            proxy["settings"]["servers"] = [{"address": parsed["host"], "port": parsed["port"], "method": parsed["method"], "password": parsed["password"]}]
        
        ss = proxy["streamSettings"]
        if ss["network"] == "ws": ss["wsSettings"] = {"path": parsed["path"]}
        elif ss["network"] == "grpc": ss["grpcSettings"] = {"serviceName": parsed.get("path", "")}
        if ss["security"] == "reality":
            ss["realitySettings"] = {"show": False, "fingerprint": parsed.get("fp", "chrome"), "serverName": parsed.get("sni", ""), "publicKey": parsed.get("pbk", ""), "shortId": parsed.get("sid", "")}
        elif ss["security"] == "tls":
            ss["tlsSettings"] = {"serverName": parsed.get("sni", ""), "allowInsecure": True}

    config["outbounds"].insert(0, proxy)
    return config

async def check_gemini_access(socks_port):
    """Tests if Gemini AI Studio is reachable."""
    try:
        cmd = ["curl", "-s", "-L", "-k", "--proxy", f"socks5h://127.0.0.1:{socks_port}", Config.GEMINI_CHECK_URL, "--connect-timeout", "10", "-m", "15", "-w", "%{http_code}"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        res = stdout.decode().strip()
        return ("200" in res or "302" in res), res
    except: return False, "ERR"

async def measure_speed_librespeed(socks_port):
    """Measures download speed via Librespeed CLI."""
    try:
        if not os.path.exists(Config.LIBRESPEED_PATH): return 0.0, 0.0
        cmd = [Config.LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{socks_port}", "--json", "--duration", "7"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=18)
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            return round(data.get("download", 0) / 1024 / 1024, 2), round(data.get("ping", 0), 1)
    except: pass
    return 0.0, 0.0

async def audit_single_link(link, local_port, semaphore):
    """Full lifecycle check for a single proxy link."""
    async with semaphore:
        l_hash = get_md5(link)
        
        # 1. Skip if already in results
        async with file_lock:
            for path in Config.RESULT_FILES.values():
                if os.path.exists(path) and l_hash in open(path).read():
                    stats.processed += 1
                    return link, "ALREADY_DONE", 0, 0

        # 2. Parse link
        parsed = parse_proxy_link(link)
        if not parsed:
            stats.processed += 1; stats.dead += 1
            log_node_details(link, None, "INVALID_FORMAT")
            return link, "INVALID_FORMAT", 0, 0
        
        config_path = f"cfg_{l_hash[:6]}_{local_port}.json"
        with open(config_path, "w") as f: json.dump(generate_xray_config(parsed, local_port), f)
        
        xray_proc = None
        try:
            xray_proc = subprocess.Popen([Config.XRAY_PATH, "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(4) # Wait for bootstrap
            
            is_gemini, gemini_code = await check_gemini_access(local_port)
            speed, ping = 0.0, 0.0
            
            if is_gemini or (gemini_code not in ["ERR", "000"]):
                speed, ping = await measure_speed_librespeed(local_port)
            
            # Classification
            cat = "DEAD"
            if is_gemini and speed >= 0.8: cat = "ELITE"; stats.elite += 1
            elif is_gemini or (0.1 < speed < 1.0): cat = "STABLE"; stats.stable += 1
            elif speed >= 1.0: cat = "FAST_NO_GOOGLE"; stats.fast += 1
            else: stats.dead += 1
            
            log_node_details(link, parsed, cat, speed, ping)
            return link, cat, speed, ping
            
        except Exception as e:
            stats.errors += 1
            log_error_details(link, e, context="AUDIT")
            return link, "ERROR", 0, 0
        finally:
            stats.processed += 1
            if xray_proc:
                try: 
                    xray_proc.terminate()
                    if xray_proc.poll() is None: xray_proc.kill()
                except: pass
            if os.path.exists(config_path): os.remove(config_path)

# --- MAIN FLOW ---
async def main_orchestrator():
    """Main entry point: reads raw_links.txt and audits content."""
    if os.path.exists(Config.LOCK_FILE):
        if time.time() - os.path.getmtime(Config.LOCK_FILE) < 1200:
            print("🚫 Бот уже запущен."); sys.exit(0)
    
    with open(Config.LOCK_FILE, "w") as f: f.write(str(os.getpid()))
    
    try:
        log_event("🚀 СТАРТ: Режим локального аудита (raw_links.txt)", "SYSTEM")
        kill_process_by_name("xray")
        manage_cache_lifecycle()

        total_pool = []
        if os.path.exists(Config.TEMP_POOL_FILE):
            log_event("♻️ Восстановление очереди...", "INFO")
            with open(Config.TEMP_POOL_FILE, "r") as f: total_pool = json.load(f)

        if not total_pool:
            if not os.path.exists(Config.RAW_LINKS_FILE):
                log_event(f"❌ Файл {Config.RAW_LINKS_FILE} не найден!", "ERROR"); return
            
            with open(Config.RAW_LINKS_FILE, "r") as f:
                content = f.read()
                raw_extracted = extract_configs_from_text(content)
            
            log_event(f"📖 Загружено из файла: {len(raw_extracted)} нод.", "SUCCESS")
            
            # Filter duplicates and history
            history = set()
            for path in Config.RESULT_FILES.values():
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
            with open(Config.TEMP_POOL_FILE, "w") as f: json.dump(total_pool, f)

        # Apply dead cache filter
        dead_cache = set()
        if os.path.exists(Config.DEAD_CACHE_FILE):
            with open(Config.DEAD_CACHE_FILE) as f: dead_cache = {line.strip() for line in f}
        
        active_nodes = [l for l in total_pool if get_md5(l) not in dead_cache]
        stats.total = len(active_nodes)
        
        if not active_nodes:
            log_event("📭 Очередь пуста. Новых нод нет.", "INFO")
            if os.path.exists(Config.TEMP_POOL_FILE): os.remove(Config.TEMP_POOL_FILE)
            return

        log_event(f"🏁 Запуск аудита {stats.total} нод...", "SYSTEM")
        semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_TESTS)
        
        for i in range(0, len(active_nodes), Config.BATCH_SIZE):
            batch = active_nodes[i : i + Config.BATCH_SIZE]
            tasks = [audit_single_link(l, Config.BASE_PORT + (idx % Config.PORT_RANGE), semaphore) for idx, l in enumerate(batch)]
            results = await asyncio.gather(*tasks)
            
            async with file_lock:
                for link, cat, speed, ping in results:
                    if cat == "ALREADY_DONE": continue
                    h = get_md5(link)
                    if cat in ["ERROR", "DEAD", "INVALID_FORMAT"]:
                        with open(Config.DEAD_CACHE_FILE, "a") as f: f.write(f"{h}\n")
                    else:
                        target = Config.RESULT_FILES.get(cat)
                        if target: 
                            with open(target, "a") as f: f.write(f"{link}\n")
            
            # Update snapshot
            with open(Config.TEMP_POOL_FILE, "w") as f: json.dump(active_nodes[i + Config.BATCH_SIZE:], f)
            log_event(f"Прогресс: Elite: {stats.elite} | Stable: {stats.stable} | Dead: {stats.dead}", "INFO")

        log_event(f"🏆 Готово! Найдено Elite: {stats.elite}, Stable: {stats.stable}", "SUCCESS")
        if os.path.exists(Config.TEMP_POOL_FILE): os.remove(Config.TEMP_POOL_FILE)
    finally:
        if os.path.exists(Config.LOCK_FILE): os.remove(Config.LOCK_FILE)

if __name__ == "__main__":
    try:
        asyncio.run(main_orchestrator())
    except KeyboardInterrupt: pass
    except Exception as e:
        log_error_details("MAIN", e, "CRITICAL")
        if os.path.exists(Config.LOCK_FILE): os.remove(Config.LOCK_FILE)
        sys.exit(1)
