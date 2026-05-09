# ── Stage 1: Build C sniffer ─────────────────────────────────────────────────
FROM gcc:12 AS c-builder

WORKDIR /build

# Install libpcap dev headers
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

COPY src/c/ .
RUN gcc -O2 -Wall -Wextra -o sniffer sniffer.c -lpcap

# ── Stage 2: Python runtime ───────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Runtime libpcap (needed for sniffer binary at runtime)
RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*

# Copy compiled sniffer
COPY --from=c-builder /build/sniffer /app/sniffer
RUN chmod +x /app/sniffer

# Python dependencies
COPY src/python/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App source
COPY src/python/ .

# Data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
