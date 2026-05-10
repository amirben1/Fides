FROM python:3.12-slim
WORKDIR /app
COPY services/governance/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY services/governance/ ./services/governance/
COPY services/orchestrator/ ./services/orchestrator/
ENV PYTHONPATH=/app
CMD ["python", "-m", "services.governance.main"]
