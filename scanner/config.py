import os


SCAN_TIMEOUT = int(os.getenv("AEGIS_SCAN_TIMEOUT", "30000"))
MAX_FILE_SIZE = int(os.getenv("AEGIS_MAX_FILE_SIZE", "52428800"))
WORKERS = int(os.getenv("AEGIS_WORKERS", "2"))
CLAMAV_DB_PATH = os.getenv("CLAMAV_DB_PATH", "/var/lib/clamav")
FRESHCLAM_INTERVAL = int(os.getenv("FRESHCLAM_INTERVAL", "21600"))
CLAMD_SOCKET = os.getenv("CLAMD_SOCKET", "localhost:3310")
TRIVY_CACHE_DIR = os.getenv("TRIVY_CACHE_DIR", "/root/.cache/trivy")
