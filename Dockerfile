# Recon47 Docker Image
# Author: 0xMasruful
FROM python:3.11-slim-bookworm

LABEL maintainer="0xMasruful"
LABEL description="Recon47 - Automated Reconnaissance & Vulnerability Assessment Framework"
LABEL version="1.0.0"

# Install system dependencies + optional security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto \
    nmap \
    dnsutils \
    curl \
    wget \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go (for nuclei)
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz \
    && rm go1.22.0.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Create reports directory
RUN mkdir -p /app/reports

VOLUME ["/app/reports"]
ENTRYPOINT ["recon47"]
CMD ["--help"]
