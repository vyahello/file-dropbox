FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    FILE_DROPBOX_CONFIG=/app/config/config.json

# Install the package (no dependencies beyond the standard library).
COPY pyproject.toml README.md /build/
COPY src /build/src
RUN pip install --no-cache-dir /build && rm -rf /build

# Unprivileged user. /app/uploads and /app/config are the only writable places,
# and compose.yaml mounts both from the host so nothing lives only in the container.
RUN useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin dropbox \
 && mkdir -p /app/uploads /app/config \
 && chown dropbox:dropbox /app/uploads /app/config

WORKDIR /app
USER dropbox
EXPOSE 47921
CMD ["file-dropbox"]
