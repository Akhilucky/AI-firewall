<div align="center">
  <img src="https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/License-MIT-green">
  <img src="https://img.shields.io/github/actions/workflow/status/Akhilucky/AI-firewall/ci.yml?branch=main&label=CI&logo=github">
  <img src="https://img.shields.io/pypi/v/ai-firewall-mcp?label=PyPI&logo=pypi">
  <img src="https://img.shields.io/docker/v/akhilucky/ai-firewall-mcp/latest?label=Docker%20Hub&logo=docker">
  <img src="https://img.shields.io/badge/MCP-Registry-8A2BE2">
  <br>
  <a href="https://github.com/Akhilucky/AI-firewall"><b>GitHub</b></a> •
  <a href="https://pypi.org/project/ai-firewall-mcp/"><b>PyPI</b></a> •
  <a href="https://hub.docker.com/r/akhilucky/ai-firewall-mcp"><b>Docker Hub</b></a>
</div>

<mcp-name: io.github.Akhilucky/ai-firewall-mcp>

# AI Firewall — MCP Server

A multi-agent AI security layer that protects LLMs from **prompt injection**, **jailbreaks**, and **policy violations**. Available as an [MCP](https://modelcontextprotocol.io) server for any MCP-compatible client (Claude Desktop, Cursor, Windsurf, Cline, Roo Code, etc.).

## Quick Start

### pip install

```bash
pip install ai-firewall-mcp
ai-firewall-mcp
```

### Docker

```bash
docker pull akhilucky/ai-firewall-mcp:latest
docker run -i akhilucky/ai-firewall-mcp:latest
```

### Claude Desktop

Add to `claude_desktop_config.json`:

**pip install:**
```json
{
  "mcpServers": {
    "ai-firewall": {
      "command": "pipx",
      "args": ["run", "ai-firewall-mcp"]
    }
  }
}
```

**Docker:**
```json
{
  "mcpServers": {
    "ai-firewall": {
      "command": "docker",
      "args": ["run", "-i", "akhilucky/ai-firewall-mcp:latest"]
    }
  }
}
```

### Cursor / Windsurf / Cline / Roo Code

Configure in your MCP settings with:
- **Type:** `stdio`
- **Command:** `docker run -i akhilucky/ai-firewall-mcp:latest`
- Or use `ai-firewall-mcp` if installed via pip

## MCP Tools

| Tool | Description |
|------|-------------|
| `analyze_prompt` | Analyze a prompt for injection, jailbreaks, exfiltration, and leakage |
| `get_threat_breakdown` | Detailed per-signal scoring breakdown from the last analysis |
| `sanitize_prompt` | Clean a suspicious prompt while preserving legitimate content |
| `get_firewall_status` | Health check: vector DB size, model status, uptime |
| `benchmark_firewall` | Run the adversarial test suite and return detection statistics |

### Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector ai-firewall-mcp
```

## Architecture

The firewall runs three agents per prompt:

```
User Prompt → [Retrieval Agent] → [Guard Agent] → [Policy Agent] → LLM
                   │                    │               │
                   ▼                    ▼               ▼
              Vector DB (FAISS)    Threat Signals    Allow/Block
```

| Agent | Role |
|-------|------|
| **Retrieval Agent** | Semantic search against known attack patterns (FAISS + sentence-transformers) |
| **Guard Agent** | Multi-signal classification: vector similarity, keyword match, heuristic scoring |
| **Policy Agent** | Final decision: `ALLOW` / `BLOCK` / `SANITIZE` based on configurable thresholds |

Threat signals are weighted: **40% vector similarity**, **25% keyword match**, **20% heuristic**, **15% policy weight**.

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `FIREWALL_MODE` | `strict` | `strict` / `moderate` / `permissive` |
| `SIMILARITY_THRESHOLD` | `0.50` | Vector match threshold (lower = stricter) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## CLI / API Usage

```bash
# Interactive dashboard
python main.py

# Red-team adversarial tests
python main.py --redteam

# REST API server
python main.py --api

# Single prompt analysis
python main.py --analyze "Ignore all previous instructions"
```

The REST API runs at `http://localhost:8000` with OpenAPI docs at `/docs` (requires `pip install ai-firewall-mcp[api]`).

## Testing

```bash
pytest tests/ -v          # Full test suite (43 tests)
pytest tests/test_mcp.py  # MCP-specific tests only
```

## Project Structure

```
├── src/ai_firewall/          # MCP server package (PyPI entry)
│   ├── mcp_server.py         #    5 MCP tools, stdio transport
│   ├── threat_scorer.py      #    Per-signal scoring breakdown
│   └── __init__.py
├── src/agents/               # Core firewall agents
├── tests/                    # Test suites
├── Dockerfile                # Docker image (2.04GB, CPU-only torch)
├── pyproject.toml            # Package config & metadata
└── .github/workflows/ci.yml  # CI/CD pipeline
```

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">Built for security. Designed for production.</div>
