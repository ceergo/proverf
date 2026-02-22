import json
import os
import time
import subprocess
import hashlib

# --- CONFIGURATION ---
INPUT_FILE = "raw_links.txt"   
CACHE_FILE = "dead_cache.txt"   
CLEANUP_LOG = "last_cleanup.txt"

# Sorting thresholds
MAX_PING = 300       # Max ping for Stable Reserve (ms)
ELITE_PING = 150     # Max ping for Elite (ms)
SPEED_MIN = 3.0      # Min speed for Speed Master (Mbps)

def get_md5(text):
    """Генерирует уникальный ID для ссылки."""
    return hashlib.md5(text.encode()).hexdigest()

def manage_cache_lifecycle():
    """Очистка кэша раз в 72 часа."""
    now = time.time()
    three_days = 259200 
    
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try: last_clean = float(f.read().strip())
            except: last_clean = 0
    else:
        last_clean = 0
        
    if now - last_clean > three_days:
        print("[System] 72h Cleanup triggered.")
        if os.path.exists(CACHE_FILE): os.remove(CACHE_FILE)
        for f in ["Elite_Gemini.txt", "Speed_Master.txt", "Stable_Reserve.txt"]:
            if os.path.exists(f): open(f, 'w').close()
        with open(CLEANUP_LOG, "w") as f:
            f.write(str(now))

def load_and_filter_input():
    """Загрузка и фильтрация ссылок."""
    if not os.path.exists(INPUT_FILE):
        return []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = list(set(line.strip() for line in f if line.strip()))
    dead_pool = set()
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            dead_pool = set(line.strip() for line in f if line.strip())
    return [l for l in links if get_md5(l) not in dead_pool]

def execute_lite_benchmark():
    """Запуск теста."""
    links = load_and_filter_input()
    if not links: return []
    with open("temp_batch.txt", "w") as f:
        f.write("\n".join(links))
    print(f"[System] Testing {len(links)} links...")
    subprocess.run(["./lite-speedtest", "-f", "temp_batch.txt", "-p", "https://gemini.google.com", "-o", "json"], capture_output=True)
    if os.path.exists("result.json"):
        with open("result.json", "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def triple_tier_classifier():
    """Классификация по результатам."""
    nodes = execute_lite_benchmark()
    elite, speed, stable, dead = [], [], [], []
    for node in nodes:
        link, ping, mbps = node.get("link"), node.get("ping", 0), node.get("speed", 0)
        gemini_ok = node.get("google_check", False)
        node_id = get_md5(link)
        if ping >= MAX_PING or ping == 0:
            dead.append(node_id)
            continue
        if ping < ELITE_PING and gemini_ok: elite.append(link)
        elif ping < 200 and mbps > SPEED_MIN: speed.append(link)
        elif ping < MAX_PING: stable.append(link)
    with open("Elite_Gemini.txt", "w") as f: f.write("\n".join(elite))
    with open("Speed_Master.txt", "w") as f: f.write("\n".join(speed))
    with open("Stable_Reserve.txt", "w") as f: f.write("\n".join(stable))
    if dead:
        with open(CACHE_FILE, "a") as f: f.write("\n".join(dead) + "\n")
    print(f"Done! Elite: {len(elite)}, Speed: {len(speed)}, Stable: {len(stable)}")

if __name__ == "__main__":
    manage_cache_lifecycle()
    triple_tier_classifier()
