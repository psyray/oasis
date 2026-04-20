# Slim Debian base — pin patch version for reproducible builds and clearer security tracking
# Debian 13 (trixie) slim; bump tag when rebuilding for security updates (see Docker Hub debian tags).
FROM debian:13.4-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl \
    python3 python3-pip python3-venv \
    pipx \
    libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libcairo2 \
    libgdk-pixbuf-2.0-0 shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash appuser

WORKDIR /app
COPY --chown=appuser:appuser . /app

USER appuser
ENV PATH="/home/appuser/.local/bin:${PATH}"

RUN pipx install --editable /app

# No ENTRYPOINT: plain `docker run IMAGE bash` overrides CMD without invoking oasis.
# Docker Compose sets entrypoint `oasis` and default command `--help` (see docker-compose.yml).
CMD ["oasis", "--help"]
