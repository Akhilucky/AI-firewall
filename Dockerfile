FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir -e .

ENV FIREWALL_MODE=strict
ENV LOG_LEVEL=INFO

ENTRYPOINT ["ai-firewall-mcp"]
