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
MAX_CONCURRENT_TESTS = 5  
BATCH_SIZE = 10           
BASE_PORT = 10800         

# Browser Emulation Headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

def log_event(msg):
    """
    Real-time logging with timestamps.
    """
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def get_md5(text):
    """
    Generates MD5 hash for unique identification.
    Normalization: cuts off tails (# and ?) to ensure same node = same MD5.
    """
    try:
        # For VMESS we cut only after #, for others we cut after # or ?
        if "vmess://" in text:
            normalized = text.strip().split('#')[0]
        else:
            normalized = text.strip().split('#')[0].split('?')[0]
        return hashlib.md5(normalized.encode()).hexdigest()
    except:
        return hashlib.md5(text.strip().encode()).hexdigest()

def manage_cache_lifecycle():
    """
    72-hour cleanup cycle for dead nodes.
    """
    now = datetime.now()
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    log_event("🧹 Цикл 72 часа: Очищаем базу мертвых ссылок...")
                    if os.path.exists(DEAD_CACHE_FILE): 
                        os.remove(DEAD_CACHE_FILE)
                    with open(CLEANUP_LOG, "w") as f_out: 
                        f_out.write(now.isoformat())
            except Exception:
                pass
    else:
        with open(CLEANUP_LOG, "w") as f_out: 
            f_out.write(now.isoformat())

def extract_server_identity(link):
    """
    Identifies server by Host:Port to prevent redundant testing.
    """
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
        if match:
            return f"{match.group(1)}:{match.group(2)}"
            
        parsed = urlparse(link)
        return parsed.netloc or link
    except:
        return link

def clean_garbage(link):
    """
    Strict cleaning for ALL proxy protocols.
    Removes country codes (#RU), emojis, and ensures MD5 consistency.
    """
    if not link:
        return ""
    
    # 1. Find protocol start
    protocol_match = re.search(r'(vless|vmess|trojan|ss|hy2)://', link, re.IGNORECASE)
    if protocol_match:
        link = link[protocol_match.start():]
    
    # 2. Remove whitespace
    link = "".join(link.split())
    
    # 3. Cut off trailing remarks/names (the # suffix)
    if "#" in link:
        link = link.split("#")[0]
    
    # 4. Strict ASCII filter
    link = "".join(char for char in link if 31 < ord(char) < 127)
    
    return link

def extract_configs_from_text(text, depth=0):
    """
    Extracts proxy links with a recursion limit and applies clean_garbage immediately.
    """
    if depth > 1: return []
    
    pattern = r'(vless|vmess|trojan|ss|hy2)://[^\s"\'<>|]+'
    text = text.replace('\\n', ' ').replace('\\r', ' ').replace(',', ' ').replace('|', ' ')
    
    found_raw = []
    matches = re.finditer(pattern, text, re.IGNORECASE)
    for m in matches:
        link = m.group(0).rstrip('.,;)]}>')
        link = clean_garbage(link)
        if '@' in link or link.startswith('vmess://'):
            found_raw.append(link)

    if not found_raw and len(text.strip()) > 50 and depth == 0:
        try:
            potential_b64 = re.findall(r'[a-zA-Z0-9+/]{50,}=*', text)
            for chunk in potential_b64:
                padded = chunk + "=" * (-len(chunk) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if any(p in decoded.lower() for p in ['vless://', 'vmess://', 'trojan://']):
                    found_raw.extend(extract_configs_from_text(decoded, depth + 1))
        except:
            pass

    return list(set(found_raw))

async def fetch_external_subs(urls):
    """
    Downloads subscription content and extracts clean links.
    """
    all_links = []
    timeout = aiohttp.ClientTimeout(total=45)
    async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout) as session:
        for url in urls:
            url = url.strip()
            if not url.startswith('http'): continue
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        found = extract_configs_from_text(content)
                        all_links.extend(found)
            except Exception:
                pass
    return all_links

def parse_proxy_link(link):
    """
    Universal parser for all supported protocols.
    """
    try:
        if link.lower().startswith("vmess://"):
            b64_part = link[8:].split("#")[0]
            b64_part = re.sub(r'[^a-zA-Z0-9+/=]', '', b64_part)
            b64_part += "=" * (-len(b64_part) % 4)
            decoded_str = base64.b64decode(b64_part).decode('utf-8', errors='ignore').strip()
            json_match = re.search(r'\{.*\}', decoded_str, re.DOTALL)
            if not json_match: return None
            data = json.loads(json_match.group())
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
                "flow": params.get("flow", ""), "pbk": params.get("pbk", ""), "sid": params.get("sid", ""), "fp": params.get("fp", "chrome")
            }
        elif link.lower().startswith("ss://"):
            parts = link[5:].split("#")
            main = parts[0]
            if "@" in main:
                auth, hp = main.split("@")
                method, password = (base64.b64decode(auth + "="*(-len(auth)%4)).decode()).split(":") if ":" not in auth else auth.split(":")
                h, p = hp.split(":")
            else:
                decoded = base64.b64decode(main + "="*(-len(main)%4)).decode()
                auth, hp = decoded.split("@")
                method, password = auth.split(":")
                h, p = hp.split(":")
            return {"protocol": "shadowsocks", "host": h, "port": int(p), "method": method, "password": password, "security": "none", "type": "tcp"}
    except Exception: 
        return None

def generate_xray_config(parsed_link, local_port):
    """
    Xray config with optimized DNS and routing for testing.
    """
    protocol = parsed_link["protocol"]
    config = {
        "log": {"loglevel": "none"},
        "dns": {
            "servers": ["8.8.8.8", "1.1.1.1", "localhost"],
            "queryStrategy": "UseIPv4"
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "outboundTag": "proxy", "network": "udp,tcp"},
                {"type": "field", "outboundTag": "direct", "domain": ["localhost"]}
            ]
        },
        "inbounds": [{
            "port": local_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}]
    }

    if protocol == "hy2":
        out = {"tag": "proxy", "protocol": "hysteria2", "settings": {"server": parsed_link["host"], "port": parsed_link["port"], "auth": parsed_link["uuid"]},
               "streamSettings": {"network": "udp", "security": "tls", "tlsSettings": {"serverName": parsed_link.get("sni", parsed_link["host"]), "allowInsecure": True}}}
    else:
        out = {"tag": "proxy", "protocol": protocol, "settings": {}, "streamSettings": {"network": parsed_link.get("type", "tcp"), "security": parsed_link.get("security", "none")}}
        if protocol in ["vless", "vmess"]:
            user = {"id": parsed_link["uuid"], "encryption": "none"} if protocol == "vless" else {"id": parsed_link["uuid"], "alterId": 0, "security": "auto"}
            out["settings"]["vnext"] = [{"address": parsed_link["host"], "port": parsed_link["port"], "users": [user]}]
        elif protocol == "trojan":
            out["settings"]["servers"] = [{"address": parsed_link["host"], "port": parsed_link["port"], "password": parsed_link["uuid"]}]
        elif protocol == "shadowsocks":
            out["settings"]["servers"] = [{"address": parsed_link["host"], "port": parsed_link["port"], "method": parsed_link["method"], "password": parsed_link["password"]}]
        
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
    """
    Check if Google AI Studio is accessible via proxy.
    """
    try:
        cmd = ["curl", "-s", "-L", "-k", "--proxy", f"socks5h://127.0.0.1:{socks_port}", GEMINI_CHECK_URL, "--connect-timeout", "10", "-m", "15", "-w", "%{http_code}"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        res = stdout.decode().strip()
        
        if "200" in res or "302" in res: return True, "ДОСТУПНО ✅"
        if "403" in res: return False, "БЛОК 🛑"
        return False, f"ОТВЕТ: {res[:3]}"
    except: return False, "ОШИБКА ❌"

async def measure_speed_librespeed(socks_port):
    """
    Speed test with extended timeout for slow but working nodes.
    """
    try:
        cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{socks_port}", "--json", "--duration", "15"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                val = round(data.get("download", 0) / 1024 / 1024, 2)
                return val, round(data.get("ping", 0), 1)
        except asyncio.TimeoutError:
            if proc: proc.kill()
            return 0.0, 0.0
        return 0.0, 0.0
    except Exception: return 0.0, 0.0

async def audit_single_link(link, local_port, semaphore):
    """
    Full audit cycle with classification and Atomic Double-Check to prevent recursion.
    """
    async with semaphore:
        # ATOMIC DOUBLE-CHECK: Проверяем файлы прямо перед запуском теста
        # Если нода уже была записана другим потоком из этой же пачки - пропускаем.
        link_md5 = get_md5(link)
        already_done = False
        for rf in RESULT_FILES:
            if os.path.exists(rf):
                with open(rf, "r") as f:
                    if link_md5 in [get_md5(line) for line in f]:
                        already_done = True
                        break
        
        if already_done:
            return link, "ALREADY_DONE", 0

        proxy_id = link_md5[:6]
        report = [f"\n🚀 ТЕСТИРУЮ: {link}"]
        
        parsed = parse_proxy_link(link)
        if not parsed: 
            report.append("  └─ ❌ ОШИБКА ПАРСИНГА")
            print("\n".join(report), flush=True)
            return link, "DEAD", 0
        
        config_path = f"cfg_{proxy_id}_{local_port}.json"
        with open(config_path, "w") as f: json.dump(generate_xray_config(parsed, local_port), f)
            
        xray_proc = None
        try:
            xray_proc = subprocess.Popen([XRAY_PATH, "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(6.5) 
            
            is_gemini, g_msg = await check_gemini_access(local_port)
            speed, ping = await measure_speed_librespeed(local_port)
            
            verdict = "МЕРТВАЯ 💀"
            emoji = "💀"
            
            if is_gemini and speed >= 0.8:
                verdict = "ELITE ⭐"
                emoji = "⭐"
            elif is_gemini:
                verdict = "STABLE 🟢" 
                emoji = "🟢"
            elif speed >= 1.0:
                verdict = "FAST (No Google) ⚡"
                emoji = "⚡"
            elif speed > 0.02:
                verdict = "STABLE 🟢"
                emoji = "🟢"
            
            report.append(f"  └─ {emoji} СТАТУС: {verdict} | СКОРОСТЬ: {speed} Mbps | GEMINI: {g_msg}")
            print("\n".join(report), flush=True)
            
            final_cat = "DEAD"
            if "ELITE" in verdict: final_cat = "ELITE"
            elif "STABLE" in verdict: final_cat = "STABLE"
            elif "FAST" in verdict: final_cat = "FAST_NO_GOOGLE"
            
            return link, final_cat, speed
        except Exception as e: 
            report.append(f"  └─ 💀 СТАТУС: МЕРТВАЯ 💀 (ERROR: {str(e)[:20]})")
            print("\n".join(report), flush=True)
            return link, "DEAD", 0
        finally:
            if xray_proc:
                xray_proc.kill()
                xray_proc.wait()
            if os.path.exists(config_path): os.remove(config_path)

async def main_orchestrator():
    """
    Main loop with Atomic Filtering and Batch protection.
    """
    log_event("⚡ СИСТЕМА SIERRA: ATOMIC DEDUPLICATION ⚡")
    manage_cache_lifecycle()
    
    if not os.path.exists(RAW_LINKS_FILE): 
        print(f"❌ Файл {RAW_LINKS_FILE} не найден.")
        return

    # 1. Загружаем базу MD5 из файлов (нормализованно)
    existing_hashes = set()
    for rf in RESULT_FILES:
        if os.path.exists(rf):
            with open(rf, "r") as f:
                for line in f:
                    if "://" in line:
                        existing_hashes.add(get_md5(line))

    # 2. Читаем RAW и собираем подписки
    with open(RAW_LINKS_FILE, "r") as f:
        content = f.read()
    
    raw_found = extract_configs_from_text(content)
    sub_urls = [l.strip() for l in content.split() if l.startswith('http')]
    
    print(f"🔗 Сбор из {len(sub_urls)} источников...", flush=True)
    fetched = await fetch_external_subs(sub_urls)
    
    # 3. Единый Пул с первичной очисткой
    total_pool = raw_found + fetched
    unique_candidates = []
    seen_md5 = set(existing_hashes)
    seen_ips = set()
    
    # Жесткий фильтр перед нарезкой на пачки
    for link in total_pool:
        l_clean = clean_garbage(link)
        l_md5 = get_md5(l_clean)
        l_ip = extract_server_identity(l_clean)
        
        if l_md5 not in seen_md5 and l_ip not in seen_ips:
            seen_md5.add(l_md5)
            seen_ips.add(l_ip)
            unique_candidates.append(l_clean)

    print(f"\n💎 В ПУЛЕ: {len(total_pool)} ссылок.")
    print(f"🆕 К ПРОВЕРКЕ (УНИКАЛЬНЫХ): {len(unique_candidates)}")

    # 4. Dead Cache Filter
    dead_cache = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            dead_cache = {l.strip() for l in f if l.strip()}

    fresh = [l for l in unique_candidates if get_md5(l) not in dead_cache]
    
    if not fresh:
        log_event("✅ Новых нод нет. Завершаю.")
        sys.exit(0)

    # Инициализируем файлы
    for rf in RESULT_FILES:
        if not os.path.exists(rf): open(rf, "w").close()

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
    
    # 5. Тестирование пачками
    for i in range(0, len(fresh), BATCH_SIZE):
        batch = fresh[i : i + BATCH_SIZE]
        log_event(f"📦 ПАЧКА #{i//BATCH_SIZE + 1} ({len(batch)} нод)...")
        tasks = [audit_single_link(l, BASE_PORT + (idx % MAX_CONCURRENT_TESTS), semaphore) for idx, l in enumerate(batch)]
        results = await asyncio.gather(*tasks)
        
        # Сразу записываем результаты каждой пачки, чтобы Atomic Check в других потоках их видел
        for link, cat, speed in results:
            if cat == "ALREADY_DONE": continue
            
            l_md5 = get_md5(link)
            if cat == "DEAD":
                with open(DEAD_CACHE_FILE, "a") as f:
                    f.write(l_md5 + "\n")
            else:
                target = {"ELITE": ELITE_GEMINI, "STABLE": STABLE_CHAT, "FAST_NO_GOOGLE": FAST_NO_GOOGLE}.get(cat)
                if target:
                    # Последняя проверка перед физической записью
                    with open(target, "a") as f:
                        f.write(f"{link}\n")

    log_event("🏁 ВСЁ ПРОВЕРЕНО.")
    sys.exit(0) 

if __name__ == "__main__":
    try:
        asyncio.run(main_orchestrator())
    except SystemExit:
        pass 
    except Exception as e:
        log_event(f"🔴 КРИТИКАЛ: {e}")
        sys.exit(1)
