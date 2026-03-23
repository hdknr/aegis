FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    python3 \
    ca-certificates \
    openssl \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash aegis

COPY worker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV HTTP_PROXY=http://aegis-proxy:8080 \
    HTTPS_PROXY=http://aegis-proxy:8080 \
    NO_PROXY=aegis-scanner,localhost,127.0.0.1

WORKDIR /workspace

EXPOSE 0

ENTRYPOINT ["entrypoint.sh"]
CMD ["bash"]
