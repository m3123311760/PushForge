FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PUSHFORGE_LOG_DIR=/app/logs

WORKDIR /app

RUN addgroup --system pushforge && adduser --system --ingroup pushforge pushforge

COPY requirements.txt .
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.txt

COPY app.py gunicorn.conf.py wsgi.py ./
COPY templates ./templates
COPY static ./static

RUN mkdir -p /app/logs && chown -R pushforge:pushforge /app

USER pushforge

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3).read()"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:application"]
