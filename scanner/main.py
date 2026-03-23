import shutil
import socket
import tempfile
import time
from itertools import chain
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from scanner.config import CLAMAV_DB_PATH, CLAMD_HOST, CLAMD_PORT, MAX_FILE_SIZE, TRIVY_CACHE_DIR
from scanner.models import ComponentStatus, HealthResponse, OverallStatus, ScanResponse
from scanner.scanners import aggregate_verdict
from scanner.scanners import clamav as clamav_scanner
from scanner.scanners import trivy as trivy_scanner

app = FastAPI(title="Aegis Blade", description="Security scanning engine")

_trivy_available: ComponentStatus | None = None


@app.on_event("startup")
async def _cache_trivy_check():
    global _trivy_available
    _trivy_available = ComponentStatus.ready if shutil.which("trivy") else ComponentStatus.unavailable


def _check_clamd() -> ComponentStatus:
    try:
        with socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=2):
            return ComponentStatus.ready
    except (ConnectionRefusedError, TimeoutError, OSError):
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


@app.post("/scan", response_model=ScanResponse)
def scan(
    file: UploadFile = File(...),
    content_type: str = Form(...),
    source_url: str = Form(...),
    request_id: str = Form(...),
):
    # Check file size
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(0)
    if size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File size {size} exceeds limit {MAX_FILE_SIZE}")

    start = time.monotonic()
    tmp_path = None
    try:
        # Write to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".scan") as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = Path(tmp.name)

        # Run scans
        clamav_verdict, clamav_detail = clamav_scanner.scan(tmp_path)
        trivy_verdict, trivy_detail = trivy_scanner.scan(tmp_path)

        verdict = aggregate_verdict(clamav_verdict, trivy_verdict)
        duration = int((time.monotonic() - start) * 1000)

        return ScanResponse(
            request_id=request_id,
            verdict=verdict,
            details=[clamav_detail, trivy_detail],
            scan_duration_ms=duration,
        )
    finally:
        if tmp_path:
            tmp_path.unlink(missing_ok=True)
