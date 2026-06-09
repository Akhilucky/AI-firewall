# Changelog

All notable changes to the AI Firewall MCP server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-06-09

### Added

- **MCP Server** — Production-ready MCP server with stdio transport
  - `analyze_prompt` — Analyze prompts for injection, jailbreaks, exfiltration, leakage
  - `get_threat_breakdown` — Detailed per-signal scoring breakdown
  - `sanitize_prompt` — Clean suspicious prompts while preserving legitimate content
  - `get_firewall_status` — Health check, vector DB stats, model readiness
  - `benchmark_firewall` — Run adversarial test suite and return statistics
- **PyPI Package** — Installable via `pip install ai-firewall-mcp`
  - Entry point: `ai-firewall-mcp` starts the MCP server
  - Supports Python 3.10–3.12
- **Docker Support** — Multi-stage Docker build with compose
  - `docker build -t ai-firewall-mcp .`
  - `docker run ai-firewall-mcp`
- **CI/CD Pipeline** — GitHub Actions for:
  - Automated testing (pytest)
  - Linting (ruff)
  - Package build (wheel)
  - Docker image build
  - PyPI publishing (on tag/release)
- **Client Integration** — Compatible with:
  - Claude Desktop
  - Cursor
  - Windsurf
  - Cline
  - Roo Code
  - OpenHands
  - MCP Inspector
  - Any MCP-compatible client
- **Documentation** — Full README with installation, setup guides, examples
- **`CHANGELOG.md`** — Version tracking

### Changed

- **Package restructuring** — Source moved from `src/` → `src/ai_firewall/` for proper Python packaging
- **Import paths** — All internal imports updated to use `ai_firewall` package name

### Fixed

- None (initial release)

### Security

- Fail-safe defaults: uncertain prompts default to BLOCK
- Three-signal analysis: vector similarity + keyword matching + heuristic rules
- Configurable strict/moderate/permissive modes
