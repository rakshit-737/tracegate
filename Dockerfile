# TRACEGATE API + lineage explorer
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY tracegate ./tracegate
COPY policies ./policies
RUN pip install --no-cache-dir ".[api,crypto,osv,neo4j]" && useradd -r -u 10001 tracegate
USER tracegate
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["uvicorn", "tracegate.api:app", "--host", "0.0.0.0", "--port", "8080"]
