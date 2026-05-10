FROM python:3.12-slim
WORKDIR /app
COPY services/compliance_agent/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY services/agent_base/ ./services/agent_base/
COPY services/orchestrator/__init__.py ./services/orchestrator/__init__.py
COPY services/orchestrator/auth.py ./services/orchestrator/auth.py
COPY services/compliance_agent/ ./services/compliance_agent/
ENV PYTHONPATH=/app
CMD ["python", "-m", "services.compliance_agent.agent"]
