import re

class Config:
    # Files
    RAW_LINKS_FILE = "raw_links.txt"
    DEAD_CACHE_FILE = "dead_cache.txt"
    CLEANUP_LOG = "last_cleanup.txt"
    TEMP_POOL_FILE = "temp_pool.json" 
    LOCK_FILE = "bot.lock" 

    # Output files
    RESULT_FILES = {
        "ELITE": "Elite_Gemini.txt",
        "STABLE": "Stable_Chat.txt",
        "FAST_NO_GOOGLE": "Fast_NoGoogle.txt"
    }

    # Binaries
    XRAY_PATH = "xray" 
    LIBRESPEED_PATH = "./librespeed-cli" 

    # URLs
    GEMINI_CHECK_URL = "https://aistudio.google.com/app"

    # High Load Parameters
    MAX_CONCURRENT_TESTS = 15
    BATCH_SIZE = 30
    BASE_PORT = 11000
    PORT_RANGE = 100

    # Patterns
    PROTOCOL_PATTERN = r'(vless|vmess|trojan|ss|hy2)://[^\s"\'<>|]+'
    CLEANUP_PATTERN = r'(vless|vmess|trojan|ss|hy2)://'

    # HTTP Settings
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
