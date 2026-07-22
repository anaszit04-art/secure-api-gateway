FROM python:3.13.14-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd \
        --gid 10001 \
        appgroup \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --create-home \
        --shell /usr/sbin/nologin \
        appuser

COPY requirements-runtime.txt ./

RUN python -m pip install \
        --upgrade pip \
    && python -m pip install \
        --requirement requirements-runtime.txt

COPY --chown=10001:10001 gateway ./gateway
COPY --chown=10001:10001 microservices ./microservices

USER 10001:10001

EXPOSE 8000 8001 8002

CMD ["python", "-m", "uvicorn", "gateway.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
