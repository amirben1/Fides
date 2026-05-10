FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY services/orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY services/orchestrator/ ./services/orchestrator/
ENV PYTHONPATH=/app
CMD ["uvicorn", "services.orchestrator.main:app", "--host", "0.0.0.0", "--port", "8000"]
