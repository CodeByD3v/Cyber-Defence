# Multi-stage build for IDS Attack Detection System
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies (optional: Zeek, tcpreplay for full functionality)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY backend/ /app/backend/
COPY attack-detection-viz.html /app/
COPY model/ /app/model/
COPY Dataset/ /app/Dataset/
COPY zeek-live/ /app/zeek-live/

# Create necessary directories
RUN mkdir -p /app/backend_logs /app/detection_results /app/PCAP /app/zeek-live

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SOC_LISTEN_HOST=0.0.0.0
ENV SOC_LISTEN_PORT=8765

# Expose port
EXPOSE 8765

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/api/health')" || exit 1

# Run the application
CMD ["python", "-m", "backend.server"]
