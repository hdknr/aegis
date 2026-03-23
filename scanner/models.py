from enum import Enum

from pydantic import BaseModel


class Verdict(str, Enum):
    allow = "allow"
    block = "block"
    warn = "warn"


class ComponentStatus(str, Enum):
    ready = "ready"
    unavailable = "unavailable"


class OverallStatus(str, Enum):
    healthy = "healthy"
    degraded = "degraded"


class ScanRequest(BaseModel):
    content_type: str
    source_url: str
    request_id: str


class ScanDetail(BaseModel):
    scanner: str
    result: str
    threat: str | None = None
    vulnerabilities: list[dict] | None = None


class ScanResponse(BaseModel):
    request_id: str
    verdict: Verdict
    details: list[ScanDetail]
    scan_duration_ms: int


class HealthResponse(BaseModel):
    status: OverallStatus
    clamav: ComponentStatus
    trivy: ComponentStatus
    clamav_db_age_hours: float | None = None
    trivy_db_age_hours: float | None = None
