You are working on a Python project called **ai-firewall-mcp** which implements an AI Firewall exposed via MCP (Model Context Protocol).
Your job is to take this repository from a working codebase → **fully production-ready, publicly releasable open-source project**.
# 🎯 FINAL GOAL
At the end of your work, the project must support:
## 1. PyPI Package
```bash
pip install ai-firewall-mcp
```
and:
```bash
ai-firewall-mcp
```
starts the MCP server.
---
## 2. MCP Registry Compatible Server
Must work with:
* Claude Desktop
* Cursor
* Cline
* Roo Code
* MCP Inspector
* Any MCP client
Must expose tools:
* analyze_prompt
* get_threat_breakdown
* sanitize_prompt
* get_firewall_status
* benchmark_firewall
## 3. Docker Deployment
Must support:
```bash
docker build -t ai-firewall-mcp .
docker run -p 8000:8000 ai-firewall-mcp
```
and run MCP server inside container.
---
## 4. GitHub Release Ready
Must include:
* CI/CD pipeline (GitHub Actions)
* versioned releases
* changelog
* proper tags
* documentation
* example usage
---
# 📦 CONSTRAINTS

* DO NOT modify core firewall logic (retrieval_agent, guard_agent, policy_agent, threat_scorer)
* ONLY modify:

  * packaging
  * MCP wrapper
  * Docker
  * CI/CD
  * documentation
* Must work on Python 3.10–3.12
* Must support clean install from scratch

---

# 🧱 REQUIRED OUTPUTS

## 1. PyPI Packaging Fix

Ensure:

* correct `pyproject.toml`
* setuptools build backend = `setuptools.build_meta`
* src layout working
* entry point:

```toml
[project.scripts]
ai-firewall-mcp = "ai_firewall.mcp_server:main"
```

---

## 2. MCP Server (Production Ready)

Must:

* use stdio transport
* implement async tools
* handle errors safely
* support timeout protection (<100ms where possible)
* expose all firewall functions cleanly

---

## 3. Docker Setup

Create:

### Dockerfile

* Python slim base
* install package
* expose MCP server entrypoint

### docker-compose.yml

Optional but preferred:

* service: ai-firewall-mcp
* restart policy
* environment variables support

---

## 4. GitHub Actions CI/CD

Must include pipeline for:

### CI

* install dependencies
* run tests
* check imports
* run lint (optional)

### Release pipeline

* build wheel
* publish to PyPI (on tag release)
* build Docker image
* push to Docker Hub

---

## 5. Documentation (README.md)

Must include:

### Installation

```bash
pip install ai-firewall-mcp
```

### MCP Setup (Claude Desktop)

JSON config example

### Docker usage

```bash
docker run ai-firewall-mcp
```

### MCP Inspector testing

```bash
npx @modelcontextprotocol/inspector python -m ai_firewall.mcp_server
```

---

## 6. GitHub Release Setup

Must include:

* semantic versioning
* git tags
* CHANGELOG.md
* release notes template

---

## 7. MCP Registry Readiness

Ensure:

* correct package name
* proper entrypoint
* stdio MCP compliance
* no external API dependencies
* deterministic tool responses

---

# 🧪 FINAL VALIDATION (must pass all)

After completion, verify:

```bash
pip install .
python -c "import ai_firewall"
ai-firewall-mcp
```

Docker:

```bash
docker build -t ai-firewall-mcp .
docker run ai-firewall-mcp
```

MCP:

* tools visible in inspector
* tools callable successfully

PyPI readiness:

* `python -m build` works
* wheel installs cleanly

CI:

* GitHub Actions passes on push

---

# 🚫 DO NOT

* Do NOT rewrite firewall logic
* Do NOT introduce external paid APIs
* Do NOT break src layout
* Do NOT hardcode local paths

---

# 📤 OUTPUT REQUIRED

Return:

1. All modified files
2. Dockerfile + compose
3. CI/CD workflow
4. Final architecture summary
5. Exact commands to publish:
   * PyPI
   * Docker Hub
   * GitHub release
   * MCP registry
#  CONTEXT

This project is a **production-grade MCP AI Firewall**, intended to be:

* installable via pip
* runnable via Docker
* usable in Claude Desktop
* published on GitHub as an open-source security tool
* distributed via PyPI + MCP Registry
