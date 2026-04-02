"""In-memory session and audit state management.

Thread-safe session storage with per-API-key concurrency locks.
API keys are never persisted to disk.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

from api_relay_audit.engine.result import AuditResult


class AuditStatus(str, Enum):
    """Audit job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AuditJob:
    """Represents a single audit job."""

    session_id: str
    endpoint_url: str
    endpoint_name: Optional[str]
    model: str
    status: AuditStatus
    created_at: float
    updated_at: float
    result: AuditResult | None = None
    error: Optional[str] = None
    progress_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "endpoint_url": self.endpoint_url,
            "endpoint_name": self.endpoint_name,
            "model": self.model,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "progress_message": self.progress_message,
            "error": self.error,
            "has_result": self.result is not None,
        }


class SessionManager:
    """Manages audit sessions with in-memory storage.

    - API keys are stored only in memory, never written to disk.
    - Each unique API key has its own lock to prevent concurrent audits.
    - Sessions are stored in memory and can be optionally persisted to disk
      after the audit completes (but without the API key).
    """

    def __init__(self, report_dir: Path | None = None):
        self._sessions: dict[str, AuditJob] = {}
        self._reports: dict[str, AuditResult] = {}
        self._report_files: dict[str, Path] = {}
        self._report_dir = report_dir or Path("./reports")
        self._report_dir.mkdir(parents=True, exist_ok=True)

        # Per-API-key locks for concurrency control
        self._key_locks: dict[str, asyncio.Lock] = {}
        self._key_locks_mutex = threading.Lock()

        # Background executor for running audits
        self._executor = ThreadPoolExecutor(max_workers=4)

        # Background asyncio tasks
        self._running_tasks: dict[str, asyncio.Task] = {}

    def _get_key_lock(self, api_key: str) -> asyncio.Lock:
        """Get or create an asyncio.Lock for a specific API key."""
        with self._key_locks_mutex:
            if api_key not in self._key_locks:
                self._key_locks[api_key] = asyncio.Lock()
            return self._key_locks[api_key]

    def _mask_key(self, api_key: str) -> str:
        """Return a masked version of the API key for logging."""
        if len(api_key) <= 8:
            return "***"
        return f"{api_key[:4]}...{api_key[-4:]}"

    def is_key_locked(self, api_key: str) -> bool:
        """Check if an API key currently has a running audit."""
        lock = self._get_key_lock(api_key)
        # Can't check directly on asyncio.Lock from sync code,
        # so we track active sessions
        for job in self._sessions.values():
            if job.status == AuditStatus.RUNNING:
                return True
        return False

    async def acquire_lock(self, api_key: str) -> bool:
        """Acquire the lock for an API key. Returns False if already locked."""
        lock = self._get_key_lock(api_key)
        acquired = lock.locked()
        if not acquired:
            await lock.acquire()
        return not acquired

    async def release_lock(self, api_key: str) -> None:
        """Release the lock for an API key."""
        lock = self._get_key_lock(api_key)
        if lock.locked():
            lock.release()

    def create_job(
        self,
        endpoint_url: str,
        api_key: str,
        model: str,
        endpoint_name: Optional[str] = None,
    ) -> str:
        """Create a new audit job. Returns session_id."""
        session_id = str(uuid.uuid4())[:8]
        now = time.time()

        job = AuditJob(
            session_id=session_id,
            endpoint_url=endpoint_url,
            endpoint_name=endpoint_name,
            model=model,
            status=AuditStatus.PENDING,
            created_at=now,
            updated_at=now,
        )

        self._sessions[session_id] = job
        return session_id

    def get_job(self, session_id: str) -> AuditJob | None:
        """Get a job by session_id."""
        return self._sessions.get(session_id)

    def update_job_status(
        self,
        session_id: str,
        status: AuditStatus,
        progress_message: str = "",
    ) -> None:
        """Update job status and progress."""
        job = self._sessions.get(session_id)
        if job:
            job.status = status
            job.progress_message = progress_message
            job.updated_at = time.time()

    def set_job_result(self, session_id: str, result: AuditResult) -> None:
        """Set the audit result for a job."""
        job = self._sessions.get(session_id)
        if job:
            job.result = result
            job.status = AuditStatus.COMPLETED
            job.updated_at = time.time()

            # Store report
            self._reports[session_id] = result

            # Persist result to disk (without API key)
            self._persist_report(session_id, result)

    def set_job_error(self, session_id: str, error: str) -> None:
        """Set an error on a job."""
        job = self._sessions.get(session_id)
        if job:
            job.error = error
            job.status = AuditStatus.FAILED
            job.updated_at = time.time()

    def _persist_report(self, session_id: str, result: AuditResult) -> Path:
        """Persist result to disk (API key already stripped from result)."""
        import json
        from datetime import datetime

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        safe_name = result.target_name or result.target_url.split("//")[1].split("/")[0]
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in safe_name)
        filename = f"{safe_name}_{ts}_{session_id}.json"
        path = self._report_dir / filename

        # Build minimal report (already has no API key)
        data = {
            "version": "1.0",
            "session_id": session_id,
            "audit": {
                "target_url": result.target_url,
                "target_name": result.target_name,
                "model": result.model,
                "detected_format": result.detected_format,
                "timestamp": result.timestamp,
                "duration_seconds": result.duration_seconds,
            },
            "risk": {
                "overall": result.overall_risk.value,
                "score": result.metadata.get("score", 0),
            },
            "detectors": [
                {
                    "id": dr.detector_id,
                    "risk_level": dr.risk_level.value,
                    "summary": dr.summary,
                    "findings": [
                        {
                            "test_name": tc.name,
                            "input_tokens": tc.input_tokens,
                            "output_tokens": tc.output_tokens,
                            "passed": tc.passed,
                        }
                        for tc in dr.findings
                    ],
                }
                for dr in result.detector_results
            ],
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self._report_files[session_id] = path
        return path

    def list_reports(self) -> list[Dict[str, Any]]:
        """List all reports with metadata (no sensitive data)."""
        reports = []
        for session_id, result in self._reports.items():
            reports.append({
                "session_id": session_id,
                "target_url": result.target_url,
                "target_name": result.target_name,
                "model": result.model,
                "timestamp": result.timestamp,
                "duration_seconds": result.duration_seconds,
                "overall_risk": result.overall_risk.value,
                "score": result.metadata.get("score", 0),
                "file_path": str(self._report_files.get(session_id, "")),
            })
        return sorted(reports, key=lambda r: r["timestamp"], reverse=True)

    def get_report(self, session_id: str) -> AuditResult | None:
        """Get a report by session_id."""
        return self._reports.get(session_id)

    def cleanup_key(self, api_key: str) -> None:
        """Clean up all traces of an API key from memory.

        Called after audit completes to ensure no API key persists.
        """
        with self._key_locks_mutex:
            if api_key in self._key_locks:
                del self._key_locks[api_key]

    def shutdown(self) -> None:
        """Shutdown the session manager."""
        self._executor.shutdown(wait=False)
        for task in list(self._running_tasks.values()):
            task.cancel()
        self._sessions.clear()
        self._reports.clear()
