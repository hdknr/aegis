import pytest
from pydantic import ValidationError

from scanner.models import (
    ComponentStatus,
    HealthResponse,
    OverallStatus,
    ScanDetail,
    ScanRequest,
    ScanResponse,
    Verdict,
)


class TestVerdict:
    def test_values(self):
        assert Verdict.allow == "allow"
        assert Verdict.block == "block"
        assert Verdict.warn == "warn"

    def test_invalid_value(self):
        with pytest.raises(ValueError):
            Verdict("invalid")


class TestScanRequest:
    def test_valid(self):
        req = ScanRequest(
            content_type="application/octet-stream",
            source_url="https://example.com/file.bin",
            request_id="req_001",
        )
        assert req.content_type == "application/octet-stream"
        assert req.request_id == "req_001"

    def test_missing_field(self):
        with pytest.raises(ValidationError):
            ScanRequest(content_type="text/plain", source_url="https://example.com")


class TestScanDetail:
    def test_minimal(self):
        detail = ScanDetail(scanner="clamav", result="OK")
        assert detail.threat is None
        assert detail.vulnerabilities is None

    def test_with_threat(self):
        detail = ScanDetail(scanner="clamav", result="INFECTED", threat="Win.Trojan.Agent")
        assert detail.threat == "Win.Trojan.Agent"

    def test_with_vulnerabilities(self):
        detail = ScanDetail(
            scanner="trivy",
            result="CRITICAL",
            vulnerabilities=[{"id": "CVE-2024-12345", "severity": "CRITICAL"}],
        )
        assert len(detail.vulnerabilities) == 1


class TestScanResponse:
    def test_allow(self):
        resp = ScanResponse(
            request_id="req_001",
            verdict=Verdict.allow,
            details=[ScanDetail(scanner="clamav", result="OK")],
            scan_duration_ms=150,
        )
        assert resp.verdict == Verdict.allow
        assert resp.scan_duration_ms == 150

    def test_block(self):
        resp = ScanResponse(
            request_id="req_002",
            verdict=Verdict.block,
            details=[
                ScanDetail(scanner="clamav", result="INFECTED", threat="Eicar-Signature"),
            ],
            scan_duration_ms=500,
        )
        assert resp.verdict == Verdict.block
        assert resp.details[0].threat == "Eicar-Signature"

    def test_invalid_verdict(self):
        with pytest.raises(ValidationError):
            ScanResponse(
                request_id="req_003",
                verdict="invalid",
                details=[],
                scan_duration_ms=0,
            )


class TestStatusEnums:
    def test_component_status_values(self):
        assert ComponentStatus.ready == "ready"
        assert ComponentStatus.unavailable == "unavailable"

    def test_overall_status_values(self):
        assert OverallStatus.healthy == "healthy"
        assert OverallStatus.degraded == "degraded"

    def test_invalid_component_status(self):
        with pytest.raises(ValueError):
            ComponentStatus("broken")


class TestHealthResponse:
    def test_healthy(self):
        resp = HealthResponse(
            status=OverallStatus.healthy,
            clamav=ComponentStatus.ready,
            trivy=ComponentStatus.ready,
            clamav_db_age_hours=2.5,
            trivy_db_age_hours=18.0,
        )
        assert resp.status == OverallStatus.healthy
        assert resp.clamav_db_age_hours == 2.5

    def test_degraded(self):
        resp = HealthResponse(
            status=OverallStatus.degraded,
            clamav=ComponentStatus.unavailable,
            trivy=ComponentStatus.ready,
        )
        assert resp.clamav_db_age_hours is None

    def test_missing_optional(self):
        resp = HealthResponse(
            status=OverallStatus.degraded,
            clamav=ComponentStatus.unavailable,
            trivy=ComponentStatus.unavailable,
        )
        assert resp.clamav_db_age_hours is None
        assert resp.trivy_db_age_hours is None

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            HealthResponse(status="broken", clamav="ready", trivy="ready")
