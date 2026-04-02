"""FastAPI web service for API Relay Audit.

Run with: uvicorn api_relay_audit.web.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

logger = logging.getLogger(__name__)

# Rate limiter using client IP
limiter = Limiter(key_func=get_remote_address)


# ─────────────────────────────────────────
# Pydantic request/response models
# ─────────────────────────────────────────


class AuditStartRequest(BaseModel):
    """Request body for starting an audit."""

    endpoint_url: HttpUrl = Field(..., description="Target API relay URL")
    token: str = Field(..., min_length=4, description="API key/token (in-memory only)")
    model: str = Field(default="claude-opus-4-6", description="Model name")
    endpoint_name: Optional[str] = Field(default=None, description="Display name")
    skip_detectors: list[str] = Field(
        default_factory=list,
        description="Detector IDs to skip (e.g. ['context_truncation', 'semantic_truncation'])"
    )


class AuditStartResponse(BaseModel):
    """Response after starting an audit."""

    session_id: str
    status: str
    message: str


class AuditStatusResponse(BaseModel):
    """Response for audit status query."""

    session_id: str
    endpoint_url: str
    endpoint_name: Optional[str]
    model: str
    status: str
    progress_message: str
    error: Optional[str]
    has_result: bool
    created_at: float
    updated_at: float


class ReportListItem(BaseModel):
    """Item in the reports list."""

    session_id: str
    target_url: str
    target_name: Optional[str]
    model: str
    timestamp: str
    duration_seconds: float
    overall_risk: str
    score: int
    file_path: str


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    error_code: Optional[str] = None


# ─────────────────────────────────────────
# Application state and lifespan
# ─────────────────────────────────────────

# Global session manager (in-memory, per-process)
from api_relay_audit.web.session import SessionManager, AuditStatus

_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        report_dir = Path("./reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        _session_manager = SessionManager(report_dir=report_dir)
    return _session_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    # Startup
    logger.info("Starting API Relay Audit web service")
    yield
    # Shutdown
    logger.info("Shutting down API Relay Audit web service")
    sm = get_session_manager()
    sm.shutdown()


# ─────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────

app = FastAPI(
    title="API Relay Audit",
    description="Security auditing tool for AI API relay/proxy services",
    version="1.0.0",
    lifespan=lifespan,
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Serve frontend UI at root
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import pathlib

_static_path = pathlib.Path(__file__).parent / "static"

@app.get("/")
async def root():
    return FileResponse(str(_static_path / "index.html"))

app.mount("/static", StaticFiles(directory=str(_static_path)), name="static")

# Content API (for dynamic site content)
_CONTENT_FILE = Path(__file__).parent.parent.parent.parent / "content.yaml"
_default_content = {
    "site": {"title": "API Checker", "subtitle": "中转 API 安全审计平台", "description": "检测中转 API 服务是否存在提示词注入、上下文截断、指令覆盖、数据窃取等作恶行为"},
    "landing": {"title": "🛡️ API Checker", "subtitle": "检测中转 API 是否在暗中作恶"},
    "messages": {"safe": "✅ 安全", "medium": "⚠️ 中等", "high": "🔴 高风险", "critical": "☠️ 极危险"},
    "footer": "API Checker · 开源安全审计工具",
}
@app.get("/api/content")
async def get_content():
    if _CONTENT_FILE.exists():
        import yaml
        with open(_CONTENT_FILE) as f:
            return yaml.safe_load(f) or _default_content
    return _default_content

# Admin pages (login, dashboard, content management)
from api_relay_audit.web.admin_pages import router as admin_router
app.include_router(admin_router)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────
# Security helpers
# ─────────────────────────────────────────

# Track API keys with active sessions (for concurrent audit limiting)
_active_api_keys: dict[str, str] = {}  # api_key_hash -> session_id
_key_mutex = asyncio.Lock()


async def check_api_key_concurrent_limit(token: str) -> bool:
    """Check if this API key already has a running audit.

    Returns True if allowed (no concurrent audit), False if locked.
    """
    token_hash = hash(token)
    async with _key_mutex:
        if token_hash in _active_api_keys:
            return False
        return True


async def register_active_key(token: str, session_id: str) -> None:
    """Register an API key as active."""
    token_hash = hash(token)
    async with _key_mutex:
        _active_api_keys[token_hash] = session_id


async def unregister_active_key(token: str) -> None:
    """Unregister an API key after audit completes."""
    token_hash = hash(token)
    async with _key_mutex:
        _active_api_keys.pop(token_hash, None)


# ─────────────────────────────────────────
# Audit endpoints
# ─────────────────────────────────────────

@app.post(
    "/audit/start",
    response_model=AuditStartResponse,
    responses={
        429: {"model": ErrorResponse, "description": "Concurrent audit limit reached"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
)
@limiter.limit("5/minute")
async def start_audit(
    request: Request,
    body: AuditStartRequest,
    background_tasks: BackgroundTasks,
):
    """Start a new audit job.

    The API key is stored in memory only and is cleaned up after the audit completes.
    Only one audit can run per API key at a time.
    """
    sm = get_session_manager()

    # Check concurrent audit limit
    if not await check_api_key_concurrent_limit(body.token):
        raise HTTPException(
            status_code=429,
            detail={
                "detail": "A concurrent audit is already running for this API key. "
                          "Please wait for it to complete before starting another.",
                "error_code": "CONCURRENT_AUDIT_LIMIT",
            },
        )

    # Create job
    session_id = sm.create_job(
        endpoint_url=str(body.endpoint_url),
        api_key=body.token,
        model=body.model,
        endpoint_name=body.endpoint_name,
    )

    # Register key as active
    await register_active_key(body.token, session_id)

    # Update status
    sm.update_job_status(session_id, AuditStatus.PENDING, "Job queued")
    sm.update_job_status(session_id, AuditStatus.RUNNING, "Starting audit...")

    # Schedule background audit
    background_tasks.add_task(
        _run_audit_background,
        session_id=session_id,
        endpoint_url=str(body.endpoint_url),
        api_key=body.token,
        model=body.model,
        skip_detectors=list(body.skip_detectors),
    )

    return AuditStartResponse(
        session_id=session_id,
        status=AuditStatus.PENDING.value,
        message=f"Audit job started ({len(body.skip_detectors)} detectors skipped). Poll /audit/{{session_id}}/status for progress.",
    )


async def _run_audit_background(
    session_id: str,
    endpoint_url: str,
    api_key: str,
    model: str,
    skip_detectors: list[str] | None = None,
) -> None:
    """Run the audit in a background thread.

    API key is held only in memory and released when done.
    """
    sm = get_session_manager()

    try:
        sm.update_job_status(session_id, AuditStatus.RUNNING, "Probing API format...")

        # Import here to avoid circular deps and keep api_relay_audit import lazy
        from api_relay_audit.config.schema import AppConfig, EndpointConfig, GlobalSettings
        from api_relay_audit.engine.auditor import Auditor
        from api_relay_audit.adapter.auto_adapter import AutoAdapter
        from api_relay_audit.adapter.base import NormalizedRequest

        # Build a minimal config for this single-endpoint audit
        ep_config = EndpointConfig(
            url=endpoint_url,
            token=api_key,  # Only in memory
            name=None,
            format="auto",
            timeout=120,
            enabled=True,
            tags=[],
        )

        cfg = AppConfig(
            settings=GlobalSettings(
                timeout=120,
                max_retries=3,
                model=model,
            ),
            endpoints=[ep_config],
        )

        # Create adapter and probe format
        adapter = AutoAdapter(
            base_url=endpoint_url,
            api_key=api_key,
            timeout=120,
        )

        sm.update_job_status(session_id, AuditStatus.RUNNING, "Detecting API format...")
        try:
            probe_req = NormalizedRequest(
                messages=[{"role": "user", "content": "hi"}],
                model=model,
                max_tokens=5,
            )
            response = adapter.call(probe_req)
            detected_format = adapter.format_name if not response.error else "unknown"
        except Exception as e:
            logger.warning(f"Format probe failed for {session_id}: {e}")
            detected_format = "unknown"

        # Run the full audit
        sm.update_job_status(session_id, AuditStatus.RUNNING, "Running detectors...")

        auditor = Auditor(cfg, Path("./reports"))
        results = auditor.run(skip_detectors=skip_detectors)

        if results:
            result = results[0]
            # Override detected format if we probed it
            if detected_format != "unknown":
                result.detected_format = detected_format
            sm.set_job_result(session_id, result)
            logger.info(f"Audit {session_id} completed successfully")
        else:
            sm.set_job_error(session_id, "No results returned from auditor")

    except Exception as e:
        logger.error(f"Audit {session_id} failed: {e}")
        sm.set_job_error(session_id, str(e))
    finally:
        # CRITICAL: Clean up API key from memory
        await unregister_active_key(api_key)
        sm.cleanup_key(api_key)
        await adapter.close()


@app.get(
    "/audit/{session_id}/status",
    response_model=AuditStatusResponse,
    responses={404: {"model": ErrorResponse, "description": "Session not found"}},
)
@limiter.limit("30/minute")
async def get_audit_status(request: Request, session_id: str):
    """Query the current status of an audit job."""
    sm = get_session_manager()
    job = sm.get_job(session_id)

    if not job:
        raise HTTPException(status_code=404, detail="Session not found")

    return AuditStatusResponse(
        session_id=job.session_id,
        endpoint_url=job.endpoint_url,
        endpoint_name=job.endpoint_name,
        model=job.model,
        status=job.status.value,
        progress_message=job.progress_message,
        error=job.error,
        has_result=job.result is not None,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


@app.get(
    "/audit/{session_id}/result",
    response_model=Dict[str, Any],
    responses={404: {"model": ErrorResponse, "description": "Session or result not found"}},
)
@limiter.limit("30/minute")
async def get_audit_result(request: Request, session_id: str):
    """Get the full audit result (JSON)."""
    sm = get_session_manager()
    job = sm.get_job(session_id)

    if not job:
        raise HTTPException(status_code=404, detail="Session not found")

    if job.result is None:
        raise HTTPException(
            status_code=404,
            detail={
                "detail": f"Audit result not yet available (status: {job.status.value})",
                "error_code": "RESULT_NOT_READY",
            },
        )

    result = job.result
    return {
        "session_id": session_id,
        "version": "1.0",
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
                        "description": tc.description,
                        "input_tokens": tc.input_tokens,
                        "output_tokens": tc.output_tokens,
                        "elapsed_ms": tc.elapsed_ms,
                        "response_text": tc.response_text[:500] if tc.response_text else "",
                        "passed": tc.passed,
                        "details": tc.details,
                    }
                    for tc in dr.findings
                ],
                "raw_data": dr.raw_data,
            }
            for dr in result.detector_results
        ],
        "metadata": result.metadata,
    }


# ─────────────────────────────────────────
# Reports endpoints
# ─────────────────────────────────────────

@app.get(
    "/reports",
    response_model=List[ReportListItem],
)
@limiter.limit("30/minute")
async def list_reports(request: Request):
    """List all completed audit reports."""
    sm = get_session_manager()
    reports = sm.list_reports()
    return [ReportListItem(**r) for r in reports]


@app.get(
    "/reports/{session_id}",
    response_model=Dict[str, Any],
    responses={404: {"model": ErrorResponse, "description": "Report not found"}},
)
@limiter.limit("30/minute")
async def get_report(request: Request, session_id: str):
    """Get a specific report by session_id.

    Same as GET /audit/{session_id}/result but accessed via the reports namespace.
    """
    sm = get_session_manager()
    result = sm.get_report(session_id)

    if not result:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "session_id": session_id,
        "version": "1.0",
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


# ─────────────────────────────────────────
# Health check
# ─────────────────────────────────────────

@app.get("/health")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """Health check endpoint."""
    sm = get_session_manager()
    active = sum(
        1 for j in sm._sessions.values() if j.status == AuditStatus.RUNNING
    )
    return {
        "status": "healthy",
        "version": "1.0.0",
        "active_audits": active,
        "total_sessions": len(sm._sessions),
    }
