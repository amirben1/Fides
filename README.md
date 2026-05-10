# Fides — Autonomous Fraud Detection for NORDA Bank

## Quick Start

```bash
cp .env.example .env
# Edit .env with your secrets
docker compose up --build
```

## Services

| Service | Port | Description |
|---|---|---|
| Orchestrator | 8000 | FastAPI — REST API, WebSocket, HITL |
| Dashboard | 3000 | React operator console |
| PostgreSQL | 5432 | Signed audit chain |
| Redis | 6379 | Message bus (Redis Streams) |
| Wazuh | 55000 | SOC SIEM integration |

## Run the Simulator

```bash
pip install httpx
python simulator/simulate.py
```

## Architecture

```
Transaction Feed → Orchestrator → Redis Streams (norda:events)
                                          ↓
                                  Governance Layer
                                  (JWT verify + SHA256 chain + Wazuh)
                                          ↓
                              Redis Streams (norda:decisions)
                                          ↓
                         Orchestrator WebSocket → React Dashboard
```

## Security

- Every inter-service message is JWT-signed (HS256)
- Every decision is SHA256-chained and HMAC-signed by governance
- Human operators can Approve / Reject / Suspend any decision via the HITL queue
- Wazuh SIEM receives all events for SOC monitoring
# Fides
