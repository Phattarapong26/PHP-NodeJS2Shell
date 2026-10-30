FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for network scanning and latency probes
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and assets
COPY . .

EXPOSE 5050

ENV PORT=5050
ENV PYTHONUNBUFFERED=1
ENV IS_DOCKER=true
ENV DOCKER_CONTAINER=true

CMD ["python", "app.py"]
