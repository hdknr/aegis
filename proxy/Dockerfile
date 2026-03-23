FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY proxy/requirements.txt /tmp/requirements.txt
RUN uv pip install --system --no-cache -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY proxy/ /opt/aegis/proxy/
COPY scanner/models.py /opt/aegis/scanner/models.py
COPY scanner/__init__.py /opt/aegis/scanner/__init__.py
RUN mkdir -p /opt/aegis/rules

WORKDIR /opt/aegis

ENV PYTHONPATH=/opt/aegis

EXPOSE 8080 8081

ENTRYPOINT ["mitmdump", "--script", "/opt/aegis/proxy/aegis_addon.py", "--listen-port", "8080"]
