FROM trufflesecurity/trufflehog:latest AS trufflehog
FROM python:3.9-slim

COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    xz-utils \
    git \
    ca-certificates \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scanner script
COPY scan.py .

# Start with a shell for debugging
CMD ["/bin/bash"]