FROM python:3.12.4-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    AGILANG_COMPILER_HOST=0.0.0.0 \
    AGILANG_COMPILER_PORT=8090

WORKDIR /opt/agilang

RUN groupadd --system agilang \
    && useradd --system --gid agilang --home-dir /opt/agilang --shell /usr/sbin/nologin agilang

COPY compiler_distribution/requirements.txt ./compiler_distribution/requirements.txt
RUN pip install --no-cache-dir --requirement compiler_distribution/requirements.txt

COPY --chown=agilang:agilang vendor/agilang ./vendor/agilang
COPY --chown=agilang:agilang compiler_distribution ./compiler_distribution

RUN python compiler_distribution/verify_install.py

USER agilang:agilang
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import json,urllib.request; d=json.load(urllib.request.urlopen('http://127.0.0.1:8090/health',timeout=3)); raise SystemExit(0 if d.get('ok') else 1)"

ENTRYPOINT ["python", "compiler_distribution/compiler_service.py"]
