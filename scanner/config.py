import os


SCAN_TIMEOUT = int(os.getenv("AEGIS_SCAN_TIMEOUT", "30000"))
MAX_FILE_SIZE = int(os.getenv("AEGIS_MAX_FILE_SIZE", "52428800"))
WORKERS = int(os.getenv("AEGIS_WORKERS", "2"))
CLAMAV_DB_PATH = os.getenv("CLAMAV_DB_PATH", "/var/lib/clamav")
FRESHCLAM_INTERVAL = int(os.getenv("FRESHCLAM_INTERVAL", "21600"))
_clamd_socket = os.getenv("CLAMD_SOCKET", "localhost:3310")
CLAMD_HOST, CLAMD_PORT = _clamd_socket.rsplit(":", 1)
CLAMD_PORT = int(CLAMD_PORT)
TRIVY_CACHE_DIR = os.getenv("TRIVY_CACHE_DIR", "/root/.cache/trivy")
