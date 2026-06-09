"""
AI Firewall - FastAPI Server
REST API for the AI Firewall with health, analysis, and red-team endpoints.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ai_firewall.models import AnalyzeRequest, FirewallReport, FirewallAction, ThreatLevel
from ai_firewall.orchestrator import FirewallOrchestrator
from ai_firewall.config import config

logger = logging.getLogger("ai_firewall.api")

# ── Global orchestrator (initialized on startup) ─────────────────────────────
orchestrator: FirewallOrchestrator | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the firewall on startup."""
    global orchestrator
    logger.info("🔥 AI Firewall starting up...")
    start = time.perf_counter()
    orchestrator = FirewallOrchestrator()
    elapsed = time.perf_counter() - start
    logger.info(f"🛡️  AI Firewall ready in {elapsed:.2f}s | mode={config.mode}")
    yield
    logger.info("AI Firewall shutting down")


app = FastAPI(
    title="🛡️ AI Firewall",
    description=(
        "Agentic AI Firewall that protects LLMs from prompt injection, "
        "jailbreak attempts, policy violations, and unsafe requests.\n\n"
        "**Architecture:** User → Firewall → LLM\n\n"
        "**Agents:** Retrieval (RAG) → Guard (Classification) → Policy (Decision)"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    mode: str
    vector_db_entries: int
    version: str


class QuickAnalyzeRequest(BaseModel):
    prompt: str


class QuickAnalyzeResponse(BaseModel):
    action: FirewallAction
    threat_level: ThreatLevel
    confidence: float
    explanation: str
    processing_time_ms: float


class RedTeamSummary(BaseModel):
    total_tests: int
    passed: int
    failed: int
    pass_rate: float
    results: list[dict]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Check if the AI Firewall is running and healthy."""
    return HealthResponse(
        status="operational",
        mode=config.mode,
        vector_db_entries=orchestrator.vector_store.index.ntotal if orchestrator else 0,
        version="1.0.0",
    )


@app.post("/analyze", response_model=FirewallReport, tags=["Firewall"])
async def analyze_prompt(request: AnalyzeRequest):
    """
    Run full firewall analysis on a prompt.
    
    Returns a complete FirewallReport with:
    - Retrieval evidence from vector DB
    - Guard Agent threat classification
    - Policy Agent decision
    - Final action (ALLOW / BLOCK / SANITIZE)
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Firewall not initialized")

    try:
        report = orchestrator.analyze(request)
        return report
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/quick", response_model=QuickAnalyzeResponse, tags=["Firewall"])
async def quick_analyze(request: QuickAnalyzeRequest):
    """
    Quick analysis endpoint — returns just the decision without full evidence.
    Useful for real-time integrations.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Firewall not initialized")

    try:
        report = orchestrator.analyze_text(request.prompt)
        return QuickAnalyzeResponse(
            action=report.final_action,
            threat_level=report.threat_level,
            confidence=report.overall_confidence,
            explanation=report.explanation,
            processing_time_ms=report.processing_time_ms,
        )
    except Exception as e:
        logger.error(f"Quick analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/redteam", response_model=RedTeamSummary, tags=["Testing"])
async def run_red_team():
    """
    Execute the full red-team adversarial test suite.
    
    Returns a summary of test results including pass/fail for each attack type.
    Red-team outputs NEVER bypass policies.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Firewall not initialized")

    try:
        results = orchestrator.run_red_team()
        passed = sum(1 for r in results if r.passed)
        total = len(results)

        return RedTeamSummary(
            total_tests=total,
            passed=passed,
            failed=total - passed,
            pass_rate=round(passed / total, 4) if total > 0 else 0.0,
            results=[
                {
                    "test_id": r.test_id,
                    "attack_type": r.attack_type.value,
                    "label": r.label,
                    "expected_action": r.expected_action.value,
                    "actual_action": r.actual_action.value if r.actual_action else None,
                    "actual_threat_level": r.actual_threat_level.value if r.actual_threat_level else None,
                    "passed": r.passed,
                }
                for r in results
            ],
        )
    except Exception as e:
        logger.error(f"Red-team error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats", tags=["System"])
async def get_stats():
    """Get vector database and configuration statistics."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Firewall not initialized")

    return {
        "vector_db": orchestrator.vector_store.stats,
        "config": {
            "mode": config.mode,
            "similarity_threshold": config.similarity_threshold,
            "malicious_threshold": config.malicious_threshold,
            "suspicious_threshold": config.suspicious_threshold,
            "max_prompt_length": config.max_prompt_length,
        },
    }
