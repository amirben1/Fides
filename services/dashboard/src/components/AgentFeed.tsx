// src/components/AgentFeed.tsx
import { WSMessage } from "../types/events";

const EVENT_COLORS: Record<string, string> = {
  TRANSACTION_RECEIVED: "text-blue-400",
  AGENT_OUTPUT: "text-green-400",
  DECISION_VALIDATED: "text-emerald-400",
  HITL_REQUIRED: "text-yellow-400",
  HITL_RESOLVED: "text-purple-400",
  AGENT_ERROR: "text-red-400",
  PROMPT_INJECTION_DETECTED: "text-rose-600 font-bold",
};

export function AgentFeed({ messages }: { messages: WSMessage[] }) {
  return (
    <div className="bg-gray-900 rounded-lg p-4 h-96 overflow-y-auto font-mono text-sm">
      <div className="text-gray-500 text-xs mb-2 uppercase tracking-widest">Live Agent Feed</div>
      {messages.length === 0 && (
        <div className="text-gray-600 text-xs">Waiting for events...</div>
      )}
      {messages.map((msg, i) => {
        const data = msg.data as unknown as Record<string, unknown>;
        const timestamp = typeof data.timestamp === "string" ? data.timestamp : new Date().toISOString();
        const agentId = typeof data.agent_id === "string" ? data.agent_id : "";
        const correlationId = typeof data.correlation_id === "string" ? data.correlation_id : "";
        return (
          <div key={i} className="mb-1 border-b border-gray-800 pb-1">
            <span className="text-gray-500 text-xs mr-2">
              {new Date(timestamp).toLocaleTimeString()}
            </span>
            <span className={`mr-2 ${EVENT_COLORS[msg.type] ?? "text-white"}`}>
              [{msg.type}]
            </span>
            <span className="text-gray-300 text-xs">
              {agentId && `${agentId} · `}
              {correlationId && `corr:${correlationId}`}
            </span>
          </div>
        );
      })}
    </div>
  );
}
