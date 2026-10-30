FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for network scanning, latency probes, and PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    iproute2 \
    curl \
    openfortivpn \
    ppp \
    chromium \
    fonts-thai-tlwg \
    fonts-liberation \
    fontconfig \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and assets
COPY . .

# Set up official Thai fonts
RUN mkdir -p /usr/local/share/fonts/sarabun \
 && cp /app/fonts/*.ttf /usr/local/share/fonts/sarabun/ \
 && fc-cache -f

# Ensure empty host network and active hosts files exist as regular files
RUN touch /app/host_network.json /app/active_hosts.txt

EXPOSE 5050

ENV PORT=5050
ENV PYTHONUNBUFFERED=1
ENV IS_DOCKER=true
ENV DOCKER_CONTAINER=true

CMD ["python", "app.py"]
