import asyncio
import re
import time
import aiohttp
from aiohttp_socks import ProxyConnector

# --- CONFIGURATION (Boss, you can edit these limits here) ---
LIMIT_FAST = 200     # Elite/Gemini limit in ms
LIMIT_BRAVE = 300    # General working limit in ms
TIMEOUT_TOTAL = 5    # Total connection timeout in seconds

CHECK_URL_GEMINI = "https://gemini.google.com/app"
CHECK_URL_GENERIC = "https://www.google.com"

SOURCE_FILE = "my_stable_configs.txt"

# Output Files
FILES = {
    "fast": "sub_fast.txt",   # Gemini + < 200ms
    "elite": "sub_elite.txt", # YouTube/Streaming + < 200ms
    "brave": "sub_brave.txt", # Working + < 300ms
    "cis": "sub_cis.txt",     # Kazakhstan/Belarus (Any speed)
    "raw": "sub_raw.txt"      # Archive for working but slow
}

# State management
processed_urls = set()
stats = {"fast": 0, "elite": 0, "brave": 0, "cis": 0, "raw": 0, "failed": 0}

async def check_proxy(proxy_url, test_url):
    """
    Universal checker using ProxyConnector.
    Measures Latency and Status Code.
    """
    start_time = time.perf_counter()
    try:
        # Auto-detect protocol from string
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            # We use HEAD for speed and to avoid heavy data usage
            async with session.head(test_url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_TOTAL), allow_redirects=True) as resp:
                if resp.status < 400:
                    latency = (time.perf_counter() - start_time) * 1000
                    return latency
    except Exception:
        return None
    return None

async def process_single_config(line, semaphore):
    """
    Logic for a single proxy config line.
    """
    line = line.strip()
    if not line or "#" not in line:
        return

    async with semaphore:
        # 1. Parse Country Code from Remark [XX]
        match = re.search(r'\[([A-Z]{2})\]', line)
        country_code = match.group(1) if match else "XX"

        # 2. CIS Mode (KZ/BY) - Speed doesn't matter, only access
        if country_code in ["KZ", "BY"]:
            lat = await check_proxy(line, CHECK_URL_GENERIC)
            if lat:
                save_result("cis", line)
                return

        # 3. Stage I: Speed Test (General Access)
        # We do 2 attempts to get a stable average
        latencies = []
        for _ in range(2):
            l = await check_proxy(line, CHECK_URL_GENERIC)
            if l: latencies.append(l)
        
        if not latencies:
            stats["failed"] += 1
            return
            
        avg_lat = sum(latencies) / len(latencies)

        # 4. Strict Filtering Logic
        if avg_lat > LIMIT_BRAVE:
            save_result("raw", line)
            return

        # 5. Stage II: Gemini Check (For fast proxies)
        # Check if Google allows this IP to access Gemini
        is_gemini_ok = await check_proxy(line, CHECK_URL_GEMINI)

        # 6. Final Distribution (Unique)
        if is_gemini_ok and avg_lat <= LIMIT_FAST:
            save_result("fast", line)
        elif avg_lat <= LIMIT_FAST:
            save_result("elite", line)
        elif avg_lat <= LIMIT_BRAVE:
            save_result("brave", line)
        else:
            save_result("raw", line)

def save_result(category, data):
    """Safe write to file and update stats."""
    stats[category] += 1
    with open(FILES[category], "a", encoding="utf-8") as f:
        f.write(data + "\n")

async def main():
    # Clean up previous results
    for path in FILES.values():
        with open(path, "w", encoding="utf-8") as f:
            f.truncate(0)

    try:
        with open(SOURCE_FILE, "r", encoding="utf-8") as f:
            configs = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"❌ Error: {SOURCE_FILE} not found!")
        return

    print(f"🚀 Starting Level 2 Check for {len(configs)} configs...")
    print(f"⚙️ Limits: Fast <{LIMIT_FAST}ms, Brave <{LIMIT_BRAVE}ms")

    # Limit concurrent tasks to 50 to avoid local port exhaustion
    semaphore = asyncio.Semaphore(50)
    tasks = [process_single_config(cfg, semaphore) for cfg in configs]
    
    await asyncio.gather(*tasks)

    # Output final summary
    print("\n" + "="*30)
    print("📊 FINAL STATISTICS:")
    for cat, count in stats.items():
        print(f" - {cat.upper()}: {count}")
    print("="*30)
    print("✅ Done! Files updated.")

if __name__ == "__main__":
    asyncio.run(main())
