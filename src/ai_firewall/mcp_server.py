"""
AI Firewall - MCP Server

Production-ready MCP server that exposes the AI Firewall as a set of
MCP tools for use with Claude Desktop, Cursor, Windsurf, Cline, and
any MCP-compatible client.

Transport: stdio
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from typing import Any

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ai_firewall.threat_scorer import ThreatScorer
from ai_firewall.config import config
from ai_firewall.orchestrator import FirewallOrchestrator

logger = logging.getLogger("ai_firewall.mcp")

VERSION = "1.0.0"
TOOL_TIMEOUT = 120.0
MAX_PROMPT_LENGTH = 10000

mcp_server = Server("ai-firewall")
_orchestrator: FirewallOrchestrator | None = None


def get_orchestrator() -> FirewallOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        logger.info("Initializing AI Firewall orchestrator...")
        start = time.perf_counter()
        _orchestrator = FirewallOrchestrator()
        elapsed = time.perf_counter() - start
        logger.info(f"AI Firewall initialized in {elapsed:.2f}s (mode={config.mode})")
    return _orchestrator


TOOL_DEFINITIONS: list[Tool] = [
    Tool(
        name="analyze_prompt",
        description="""Analyze a prompt for security threats including:
- Prompt Injection: attempts to override/ignore system instructions
- Jailbreak Attempts: DAN, Developer Mode, persona manipulation
- Data Exfiltration: attempts to extract system prompts or hidden data
- Prompt Leakage: attempts to reveal system instructions

Returns threat level, score, action recommendation, matched patterns, and reasoning.""",
        inputSchema={
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "The user prompt to analyze for security threats",
                }
            },
            "required": ["prompt"],
        },
    ),
    Tool(
        name="get_threat_breakdown",
        description="""Return detailed per-signal scoring information for the last analyzed prompt.
Shows the individual contribution of vector similarity, keyword matching, heuristic rules,
and policy weights to the final threat score.""",
        inputSchema={
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Optional prompt to analyze. If omitted, returns breakdown of the last analysis.",
                }
            },
        },
    ),
    Tool(
        name="sanitize_prompt",
        description="""Return a cleaned/sanitized version of a suspicious prompt.
Dangerous elements such as instruction overrides, fake system messages,
and encoded content are removed while preserving legitimate content.""",
        inputSchema={
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "The prompt to sanitize",
                }
            },
            "required": ["prompt"],
        },
    ),
    Tool(
        name="get_firewall_status",
        description="""Return the current status of the AI Firewall including:
- Overall health status
- Vector database size (number of indexed patterns)
- Whether all models are loaded and ready""",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="benchmark_firewall",
        description="""Run the built-in adversarial test suite against the firewall.
Tests include Prompt Injection, Jailbreaks, DAN attacks, Roleplay attacks,
and Prompt Leakage. Returns the number of attacks tested, blocked, and the
overall success rate.""",
        inputSchema={"type": "object", "properties": {}},
    ),
]

_last_prompt: str | None = None
_last_analysis: dict[str, Any] | None = None


@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return TOOL_DEFINITIONS


@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "analyze_prompt":
            result = await _with_timeout(_handle_analyze_prompt(arguments))
        elif name == "get_threat_breakdown":
            result = await _with_timeout(_handle_get_threat_breakdown(arguments))
        elif name == "sanitize_prompt":
            result = await _with_timeout(_handle_sanitize_prompt(arguments))
        elif name == "get_firewall_status":
            result = await _with_timeout(_handle_get_firewall_status(arguments))
        elif name == "benchmark_firewall":
            result = await _with_timeout(_handle_benchmark_firewall(arguments))
        else:
            return [TextContent(type="text", text=_format_error(f"Unknown tool: {name}"))]
        return result
    except asyncio.TimeoutError:
        logger.error(f"Tool '{name}' timed out after {TOOL_TIMEOUT}s")
        return [TextContent(type="text", text=_format_error(f"Tool '{name}' timed out"))]
    except Exception as e:
        logger.error(f"Tool '{name}' failed: {e}", exc_info=True)
        return [TextContent(type="text", text=_format_error(str(e)))]


async def _with_timeout(coro) -> list[TextContent]:
    return await asyncio.wait_for(coro, timeout=TOOL_TIMEOUT)


def _truncate_prompt(prompt: str) -> str:
    if len(prompt) > MAX_PROMPT_LENGTH:
        logger.warning(f"Prompt truncated from {len(prompt)} to {MAX_PROMPT_LENGTH} chars")
        return prompt[:MAX_PROMPT_LENGTH]
    return prompt


async def _handle_analyze_prompt(arguments: dict) -> list[TextContent]:
    raw = arguments.get("prompt", "")
    if not raw or not raw.strip():
        return [TextContent(type="text", text=_format_error("'prompt' parameter is required and must be non-empty"))]

    prompt = _truncate_prompt(raw.strip())
    orchestrator = get_orchestrator()
    report = orchestrator.analyze_text(prompt)

    global _last_prompt, _last_analysis
    _last_prompt = prompt
    _last_analysis = {
        "threat_level": report.threat_level.value,
        "score": report.guard.threat_score,
        "action": report.final_action.value,
        "reason": report.explanation,
        "matched_patterns": (
            [m.keyword for m in report.guard.keyword_matches]
            + [s.rule_name for s in report.guard.heuristic_signals]
        ),
    }

    return [TextContent(type="text", text=_format_json(_last_analysis))]


async def _handle_get_threat_breakdown(arguments: dict) -> list[TextContent]:
    raw = arguments.get("prompt", "")

    orchestrator = get_orchestrator()

    if raw and raw.strip():
        prompt = _truncate_prompt(raw.strip())
        report = orchestrator.analyze_text(prompt)
    elif _last_prompt is None:
        return [TextContent(
            type="text",
            text=_format_json({
                "error": "No previous analysis. Call analyze_prompt first or provide a 'prompt' parameter."
            }),
        )]
    else:
        report = orchestrator.analyze_text(_last_prompt)

    breakdown = ThreatScorer.get_breakdown(report)
    return [TextContent(type="text", text=_format_json(breakdown))]


async def _handle_sanitize_prompt(arguments: dict) -> list[TextContent]:
    raw = arguments.get("prompt", "")
    if not raw or not raw.strip():
        return [TextContent(type="text", text=_format_error("'prompt' parameter is required and must be non-empty"))]

    prompt = _truncate_prompt(raw.strip())
    orchestrator = get_orchestrator()
    report = orchestrator.analyze_text(prompt)

    sanitized = report.policy.sanitized_prompt or prompt
    removed_patterns = report.policy.policy_rules_triggered

    result = {
        "original": prompt,
        "sanitized": sanitized,
        "removed_patterns": removed_patterns,
    }

    return [TextContent(type="text", text=_format_json(result))]


async def _handle_get_firewall_status(arguments: dict) -> list[TextContent]:
    orchestrator = get_orchestrator()
    stats = orchestrator.vector_store.stats

    result = {
        "status": "healthy",
        "vector_db_size": stats["total_entries"],
        "models_loaded": True,
    }

    return [TextContent(type="text", text=_format_json(result))]


async def _handle_benchmark_firewall(arguments: dict) -> list[TextContent]:
    orchestrator = get_orchestrator()
    results = orchestrator.run_red_team()

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    success_rate = round(passed / total * 100, 1) if total > 0 else 0.0

    result = {
        "attacks_tested": total,
        "attacks_blocked": passed,
        "success_rate": success_rate,
    }

    return [TextContent(type="text", text=_format_json(result))]


def _format_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)


def _format_error(message: str) -> str:
    return json.dumps({"error": message})


def _handle_signal(signum, frame):
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


async def main() -> None:
    log_level = getattr(logging, os.environ.get("LOG_LEVEL", config.log_level).upper())
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info(f"Starting AI Firewall MCP server v{VERSION} (stdio transport)")

    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="ai-firewall",
                server_version=VERSION,
                capabilities=mcp_server.get_capabilities(
                    notification_options=mcp_server.notification_options,
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
