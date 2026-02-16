# Use an official Python slim image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install minimal system dependencies for building Python packages
# We keep 'curl' because the HEALTHCHECK command below needs it!
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install the core security stack
# FIX: We replaced 'llamafirewall' with 'llm-guard' to match the new shield_api.py
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    llm-guard \
    ollama \
    fastapi \
    uvicorn \
    requests \
    pydantic \
    pyyaml

# Copy the shield_api.py logic into the container
COPY shield_api.py .
COPY config ./config
COPY tests ./tests

# Expose the port where the Inspector API will listen
EXPOSE 5000

# Healthcheck to ensure the API is responsive before the Agent starts
# This is CRITICAL for the "Out of the Box" startup sequence
HEALTHCHECK --interval=30s --timeout=30s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Start the Shield API using Uvicorn
# Workers=1 prevents the M4 Pro from running out of RAM during model loading
CMD ["uvicorn", "shield_api:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "1"]