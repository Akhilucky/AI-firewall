FROM python:3.12-slim

WORKDIR /app

# CPU-only PyTorch avoids pulling 4GB of CUDA libraries
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir -e .

# Pre-download sentence-transformers model for instant startup
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# MCP registry discovery label
LABEL io.modelcontextprotocol.server.name="io.github.Akhilucky/ai-firewall-mcp"

ENV FIREWALL_MODE=strict
ENV LOG_LEVEL=INFO

ENTRYPOINT ["ai-firewall-mcp"]
