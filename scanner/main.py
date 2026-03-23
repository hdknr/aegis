import shutil
import socket
import time
from itertools import chain
from pathlib import Path

from fastapi import FastAPI

from scanner.config import CLAMAV_DB_PATH, CLAMD_SOCKET, TRIVY_CACHE_DIR
from scanner.models import ComponentStatus, HealthResponse, OverallStatus

app = FastAPI(title="Aegis Blade", description="Security scanning engine")

_trivy_available: ComponentStatus | None = None


@app.on_event("startup")
async def _cache_trivy_check():
    global _trivy_available
    _trivy_available = ComponentStatus.ready if shutil.which("trivy") else ComponentStatus.unavailable


def _check_clamd() -> ComponentStatus:
    try:
        host, port = CLAMD_SOCKET.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=2):
            return ComponentStatus.ready
    except (ConnectionRefusedError, TimeoutError, OSError, ValueError):
        return ComponentStatus.unavailable


def _clamav_db_age_hours() -> float | None:
    db_path = Path(CLAMAV_DB_PATH)
    try:
        db_files = list(chain(db_path.glob("*.cvd"), db_path.glob("*.cld")))
    except OSError:
        return None
    if not db_files:
        return None
    try:
        newest = max(f.stat().st_mtime for f in db_files)
    except FileNotFoundError:
        return None
    return round((time.time() - newest) / 3600, 1)


def _trivy_db_age_hours() -> float | None:
    metadata = Path(TRIVY_CACHE_DIR) / "db" / "metadata.json"
    try:
        mtime = metadata.stat().st_mtime
    except (FileNotFoundError, OSError):
        return None
    return round((time.time() - mtime) / 3600, 1)


# sync def — FastAPI runs sync endpoints in a threadpool,
# avoiding blocking the event loop on socket.create_connection.
@app.get("/health", response_model=HealthResponse)
def health():
    clamav_status = _check_clamd()
    trivy_status = _trivy_available or ComponentStatus.unavailable

    if clamav_status == ComponentStatus.ready and trivy_status == ComponentStatus.ready:
        overall = OverallStatus.healthy
    else:
        overall = OverallStatus.degraded

    return HealthResponse(
        status=overall,
        clamav=clamav_status,
        trivy=trivy_status,
        clamav_db_age_hours=_clamav_db_age_hours(),
        trivy_db_age_hours=_trivy_db_age_hours(),
    )
