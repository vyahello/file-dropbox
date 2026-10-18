FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FILE_DROPBOX_CONFIG=/app/config/config.json

WORKDIR /app

# Unprivileged user. uploads/ and config/ are the only writable places, and
# compose.yaml mounts both from the host so nothing lives only in the container.
RUN useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin dropbox \
 && mkdir -p /app/uploads /app/config \
 && chown dropbox:dropbox /app/uploads /app/config

COPY server.py admin.py security.py manage_token.py ./
COPY static ./static

USER dropbox
EXPOSE 47921
CMD ["python", "server.py"]
