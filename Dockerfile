FROM python:3.12-slim
WORKDIR /app
COPY . /app

RUN apt-get update -y && apt-get install -y --no-install-recommends awscli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir .

RUN addgroup --system appuser \
    && adduser --system --no-create-home --ingroup appuser appuser \
    && chown -R appuser:appuser /app

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/docs')" || exit 1

CMD ["python3", "app.py"]