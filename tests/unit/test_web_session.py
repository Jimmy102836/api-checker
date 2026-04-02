"""Unit tests for web session management."""

import tempfile
from pathlib import Path

import pytest

from api_relay_audit.web.session import (
    SessionManager,
    AuditStatus,
    AuditJob,
)


class TestSessionManager:
    def test_create_job(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            session_id = sm.create_job(
                endpoint_url="https://example.com/v1",
                api_key="test-key-12345",
                model="claude-opus-4-6",
            )
            assert len(session_id) == 8
            job = sm.get_job(session_id)
            assert job is not None
            assert job.endpoint_url == "https://example.com/v1"
            assert job.model == "claude-opus-4-6"
            assert job.status == AuditStatus.PENDING

    def test_update_job_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            session_id = sm.create_job("https://example.com/v1", "key", "model")
            sm.update_job_status(session_id, AuditStatus.RUNNING, "Testing...")
            job = sm.get_job(session_id)
            assert job.status == AuditStatus.RUNNING
            assert job.progress_message == "Testing..."

    def test_set_job_result(self):
        from api_relay_audit.engine.result import AuditResult, DetectorResult, RiskLevel

        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            session_id = sm.create_job("https://example.com/v1", "key", "model")

            result = AuditResult(
                target_url="https://example.com/v1",
                target_name="Test",
                model="model",
                timestamp="2026-04-02T10:00:00Z",
                duration_seconds=10.0,
                detected_format="openai",
                detector_results=[],
                overall_risk=RiskLevel.LOW,
            )

            sm.set_job_result(session_id, result)
            job = sm.get_job(session_id)
            assert job.status == AuditStatus.COMPLETED
            assert job.result is result
            assert sm.get_report(session_id) is result

    def test_set_job_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            session_id = sm.create_job("https://example.com/v1", "key", "model")
            sm.set_job_error(session_id, "Connection refused")
            job = sm.get_job(session_id)
            assert job.status == AuditStatus.FAILED
            assert job.error == "Connection refused"

    def test_list_reports(self):
        from api_relay_audit.engine.result import AuditResult, RiskLevel

        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))

            for i in range(3):
                sid = sm.create_job(f"https://example{i}.com/v1", f"key{i}", "model")
                result = AuditResult(
                    target_url=f"https://example{i}.com/v1",
                    target_name=f"Test {i}",
                    model="model",
                    timestamp=f"2026-04-02T{10+i:02d}:00:00Z",
                    duration_seconds=10.0 + i,
                    detected_format="openai",
                    detector_results=[],
                    overall_risk=RiskLevel.LOW,
                )
                sm.set_job_result(sid, result)

            reports = sm.list_reports()
            assert len(reports) == 3

    def test_session_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            assert sm.get_job("nonexistent") is None
            assert sm.get_report("nonexistent") is None

    def test_mask_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            assert sm._mask_key("short") == "***"
            assert sm._mask_key("abcdefghijklmnop") == "abcd...mnop"

    def test_concurrent_key_tracking(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            # Create two jobs with different keys
            sid1 = sm.create_job("https://a.com/v1", "key-a", "model")
            sid2 = sm.create_job("https://b.com/v1", "key-b", "model")
            # Both should be in pending state
            assert sm.get_job(sid1).status == AuditStatus.PENDING
            assert sm.get_job(sid2).status == AuditStatus.PENDING

    def test_cleanup_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sm = SessionManager(report_dir=Path(tmpdir))
            sm.create_job("https://example.com/v1", "secret-key-12345", "model")
            # Cleanup should not raise
            sm.cleanup_key("secret-key-12345")
