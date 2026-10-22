FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MOONCHECK_HOST=0.0.0.0 MOONCHECK_PORT=8765 MOONCHECK_DATA_DIR=/app/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m mooncheck && mkdir /app/data && chown mooncheck:mooncheck /app/data
COPY --chown=mooncheck:mooncheck . .
USER mooncheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=3)"
CMD ["python", "run.py"]
