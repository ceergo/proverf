import os
import json
import subprocess
import time
import asyncio
import sys
import re
import aiohttp
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

# --- INTERNAL IMPORTS ---
from config import Config
from logger import (
    stats, log_event, log_node_details, log_error_details, 
    log_progress, log_summary, kill_process_by_name, get_md5,
    manage_cache_lifecycle, save_audit_results
)

# Global lock for file operations
file_lock = asyncio.Lock()

# --- DATA PARSING ---
def parse_proxy_link(link):
    """Converts raw URI to structured dict for Xray."""
    try:
        import base64
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
            import base64
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

# --- EXTERNAL POOL EXPANDER ---
async def fetch_remote_links(url):
    """Downloads content from remote URL and extracts proxy links."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    # Basic extraction for common proxy protocols
                    found = re.findall(r'(vmess|vless|trojan|ss|hy2)://[^\s\"\'<>]+', text)
                    return found
    except Exception as e:
        log_event(f"⚠️ Ошибка загрузки по ссылке {url}: {e}", "ERROR")
    return []

async def prepare_task_pool_advanced(config):
    """Reads raw_links.txt, follows http links, AND reads existing results to re-verify them."""
    pool = set()
    
    # 1. Загрузка из raw_links.txt (локальные и удаленные)
    if os.path.exists(config.RAW_LINKS_FILE):
        with open(config.RAW_LINKS_FILE, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        log_event("♻️ Анализ входных данных и развертывание ссылок...", "INFO")
        for entry in lines:
            if entry.startswith("http"):
                remote_links = await fetch_remote_links(entry)
                for rl in remote_links: pool.add(rl)
            elif any(entry.startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://", "hy2://"]):
                pool.add(entry)

    # 2. Загрузка существующих "элиток" и "стабильных" для перепроверки
    log_event("🔍 Сбор ранее найденных нод для перепроверки...", "INFO")
    for category, filename in config.RESULT_FILES.items():
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                current_nodes = [line.strip() for line in f if line.strip()]
                for cn in current_nodes: pool.add(cn)
            
    # Save a copy of the full pool for debugging
    with open(config.TEMP_POOL_FILE, "w") as f:
        json.dump(list(pool), f)
        
    log_event(f"📖 Итого в очереди на аудит: {len(pool)} нод.", "SUCCESS")
    return list(pool)

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
    """Full lifecycle check for a single proxy link. Forced re-check enabled."""
    async with semaphore:
        l_hash = get_md5(link)
        parsed = parse_proxy_link(link)
        if not parsed:
            stats.processed += 1; stats.dead += 1
            return link, "INVALID_FORMAT", 0, 0
            
        config_path = f"cfg_{l_hash[:6]}_{local_port}.json"
        with open(config_path, "w") as f: json.dump(generate_xray_config(parsed, local_port), f)
        
        xray_proc = None
        try:
            xray_proc = subprocess.Popen([Config.XRAY_PATH, "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(4)
            
            is_gemini, gemini_code = await check_gemini_access(local_port)
            speed, ping = 0.0, 0.0
            
            if is_gemini or (gemini_code not in ["ERR", "000"]):
                speed, ping = await measure_speed_librespeed(local_port)
            
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
    """Main entry point: orchestrates the overall audit process."""
    if os.path.exists(Config.LOCK_FILE):
        if time.time() - os.path.getmtime(Config.LOCK_FILE) < 1200:
            print(f"🚫 [{datetime.now().strftime('%H:%M:%S')}] Бот уже запущен.")
            sys.exit(0)
            
    with open(Config.LOCK_FILE, "w") as f: f.write(str(os.getpid()))
    
    try:
        kill_process_by_name("xray")
        manage_cache_lifecycle(Config)
        
        # 1. Формируем пул (новые + старые из файлов)
        total_pool = await prepare_task_pool_advanced(Config)
            
        if not total_pool: 
            log_event(f"🛑 Пул задач пуст. Проверьте {Config.RAW_LINKS_FILE}.", "ERROR")
            return

        # 2. Очищаем файлы перед началом полной перезаписи
        log_event("🧹 Подготовка к перезаписи актуальных баз...", "SYSTEM")
        for f_path in Config.RESULT_FILES.values():
            if os.path.exists(f_path): open(f_path, 'w').close()

        dead_cache = set()
        if os.path.exists(Config.DEAD_CACHE_FILE):
            with open(Config.DEAD_CACHE_FILE) as f: dead_cache = {line.strip() for line in f}
        
        # Фильтруем только по кэшу мертвых (который живет 72 часа)
        active_nodes = [l for l in total_pool if get_md5(l) not in dead_cache]
        stats.total = len(active_nodes)
        
        if not active_nodes:
            log_event("📭 Все ноды в кэше мертвых. Ничего не осталось на проверку.", "INFO")
            return
            
        semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_TESTS)
        
        # 3. Аудит батчами
        for i in range(0, len(active_nodes), Config.BATCH_SIZE):
            batch = active_nodes[i : i + Config.BATCH_SIZE]
            tasks = [audit_single_link(l, Config.BASE_PORT + (idx % Config.PORT_RANGE), semaphore) for idx, l in enumerate(batch)]
            results = await asyncio.gather(*tasks)
            
            # Сохраняем результаты (функция сохранит их в нужные файлы)
            await save_audit_results(results, Config, file_lock)
            log_progress()
            
        log_summary()
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
