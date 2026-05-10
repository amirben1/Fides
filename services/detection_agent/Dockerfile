FROM python:3.12-slim
WORKDIR /app
COPY services/detection_agent/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY services/agent_base/ ./services/agent_base/
COPY services/orchestrator/__init__.py ./services/orchestrator/__init__.py
COPY services/orchestrator/auth.py ./services/orchestrator/auth.py
COPY services/detection_agent/ ./services/detection_agent/
ENV PYTHONPATH=/app
CMD ["python", "-m", "services.detection_agent.agent"]
