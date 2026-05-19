FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tshark \
    wireshark-common \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs models

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
# Suppress sklearn feature-name warnings — we pass numpy arrays intentionally
ENV PYTHONWARNINGS="ignore::UserWarning:sklearn"

# Default command
CMD ["python3", "-m", "app.server"]
