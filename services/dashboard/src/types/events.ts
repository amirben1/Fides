export type EventType =
  | "TRANSACTION_RECEIVED"
  | "AGENT_OUTPUT"
  | "DECISION_VALIDATED"
  | "HITL_REQUIRED"
  | "HITL_RESOLVED"
  | "AGENT_ERROR"
  | "PROMPT_INJECTION_DETECTED";

export type HITLAction = "APPROVE" | "REJECT" | "SUSPEND";

export interface AgentMessage {
  id: string;
  timestamp: string;
  event_type: EventType;
  agent_id: string;
  agent_version: string;
  correlation_id: string;
  payload: Record<string, unknown>;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  sequence: number;
  agent_id: string;
  agent_version: string;
  correlation_id: string;
  decision_type: string;
  input_hash: string;
  decision: Record<string, unknown>;
  rationale: string;
  previous_hash: string;
  entry_hash: string;
  signature: string;
}

export interface HITLEvent {
  id: string;
  timestamp: string;
  decision_id: string;
  correlation_id: string;
  decision: Record<string, unknown>;
  rationale: string;
  action: HITLAction | null;
  operator_id: string | null;
  resolved_at: string | null;
}

export interface WSMessage {
  type: EventType;
  data: AgentMessage | AuditEntry | HITLEvent;
}
