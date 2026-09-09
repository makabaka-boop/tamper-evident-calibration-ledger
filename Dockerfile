FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 ledger && \
    useradd --uid 10001 --gid ledger --create-home --shell /usr/sbin/nologin ledger

WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY scripts ./scripts
RUN python -m pip install --upgrade pip && python -m pip install . && \
    chown -R ledger:ledger /app

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "ledger.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
