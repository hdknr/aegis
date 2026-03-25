FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

COPY scanner/clamd.conf /etc/clamav/clamd.conf
RUN mkdir -p /var/lib/clamav && chown clamav:clamav /var/lib/clamav \
    && sed -i 's|^DatabaseMirror.*|DatabaseMirror database.clamav.net|' /etc/clamav/freshclam.conf || true

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY scanner/requirements.txt /tmp/requirements.txt
RUN uv pip install --system --no-cache -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY scanner/ /opt/aegis/scanner/
RUN chmod +x /opt/aegis/scanner/entrypoint.sh

WORKDIR /opt/aegis

EXPOSE 8080

ENTRYPOINT ["/opt/aegis/scanner/entrypoint.sh"]
