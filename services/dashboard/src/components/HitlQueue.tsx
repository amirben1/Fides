// src/components/HitlQueue.tsx
import { useState, useEffect } from "react";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

interface PendingDecision {
  decision_id: string;
  correlation_id: string;
  decision: Record<string, unknown>;
  rationale: string;
  enqueued_at: string;
}

export function HitlQueue() {
  const [pending, setPending] = useState<PendingDecision[]>([]);

  const fetchPending = async () => {
    try {
      const res = await fetch(`${API}/hitl/pending`);
      const data = await res.json();
      setPending(data.pending ?? []);
    } catch {}
  };

  useEffect(() => {
    fetchPending();
    const id = setInterval(fetchPending, 3000);
    return () => clearInterval(id);
  }, []);

  const resolve = async (decision_id: string, action: string) => {
    try {
      await fetch(`${API}/hitl/${decision_id}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, operator_id: "operator-001" }),
      });
      fetchPending();
    } catch {}
  };

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-500 text-xs mb-3 uppercase tracking-widest">
        HITL Queue · {pending.length} pending
      </div>
      {pending.length === 0 && (
        <div className="text-gray-600 text-xs">No decisions awaiting approval.</div>
      )}
      {pending.map((d) => (
        <div key={d.decision_id} className="mb-3 border border-yellow-800 rounded p-3 bg-gray-950">
          <div className="text-yellow-400 text-xs font-bold mb-1">⚠ HUMAN REVIEW REQUIRED</div>
          <div className="text-gray-300 text-xs mb-1">
            <span className="text-gray-500">Correlation:</span> {d.correlation_id}
          </div>
          <div className="text-gray-300 text-xs mb-2">
            <span className="text-gray-500">Rationale:</span> {d.rationale}
          </div>
          <pre className="text-gray-400 text-xs bg-gray-800 rounded p-2 mb-2 overflow-auto max-h-24">
            {JSON.stringify(d.decision, null, 2)}
          </pre>
          <div className="flex gap-2">
            <button
              onClick={() => resolve(d.decision_id, "APPROVE")}
              className="px-3 py-1 bg-emerald-700 hover:bg-emerald-600 text-white text-xs rounded"
            >
              Approve
            </button>
            <button
              onClick={() => resolve(d.decision_id, "REJECT")}
              className="px-3 py-1 bg-red-700 hover:bg-red-600 text-white text-xs rounded"
            >
              Reject
            </button>
            <button
              onClick={() => resolve(d.decision_id, "SUSPEND")}
              className="px-3 py-1 bg-yellow-700 hover:bg-yellow-600 text-white text-xs rounded"
            >
              Suspend
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
