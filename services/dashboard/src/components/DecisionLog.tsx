// src/components/DecisionLog.tsx
import { AuditEntry, WSMessage } from "../types/events";

export function DecisionLog({ messages }: { messages: WSMessage[] }) {
  const decisions = messages
    .filter((m) => m.type === "DECISION_VALIDATED")
    .map((m) => m.data as AuditEntry);

  return (
    <div className="bg-gray-900 rounded-lg p-4 h-96 overflow-y-auto">
      <div className="text-gray-500 text-xs mb-2 uppercase tracking-widest">
        Signed Audit Chain · {decisions.length} entries
      </div>
      {decisions.length === 0 && (
        <div className="text-gray-600 text-xs">No validated decisions yet.</div>
      )}
      {decisions.map((d, i) => (
        <div key={i} className="mb-2 border border-gray-700 rounded p-2 text-xs font-mono">
          <div className="flex justify-between mb-1">
            <span className="text-emerald-400">#{d.sequence}</span>
            <span className="text-gray-500">{d.agent_id}</span>
            <span className="text-gray-500">{new Date(d.timestamp).toLocaleTimeString()}</span>
          </div>
          <div className="text-gray-300 mb-1 truncate">{d.rationale || "(no rationale)"}</div>
          <div className="text-gray-600 text-xs truncate">hash: {d.entry_hash}</div>
          <div className="text-gray-600 text-xs truncate">prev: {d.previous_hash}</div>
          <div className="text-gray-600 text-xs truncate">sig:  {d.signature}</div>
        </div>
      ))}
    </div>
  );
}
