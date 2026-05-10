// src/components/ThreatAlert.tsx
import { useEffect, useState } from "react";

interface ThreatAlertProps {
  reason: string;
  technique: string;
  agentId: string;
  onDismiss: () => void;
}

export function ThreatAlert({ reason, technique, agentId, onDismiss }: ThreatAlertProps) {
  const [countdown, setCountdown] = useState(8);

  useEffect(() => {
    const interval = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) { clearInterval(interval); onDismiss(); }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [onDismiss]);

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/70 z-40 backdrop-blur-sm"
        onClick={onDismiss}
      />

      {/* Alert panel */}
      <div
        className="fixed z-50 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg"
        style={{ boxShadow: "0 0 60px rgba(239,68,68,0.4), 0 0 120px rgba(239,68,68,0.15)" }}
      >
        <div className="bg-gray-950 border-2 border-red-600 rounded-xl overflow-hidden">
          {/* Top bar */}
          <div className="bg-red-600 px-5 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-white font-black text-sm tracking-widest uppercase">
                ⚠ Threat Detected
              </span>
              <span className="bg-white/20 text-white text-xs font-bold px-2 py-0.5 rounded tracking-widest">
                {technique}
              </span>
            </div>
            <span className="text-white/70 text-xs font-mono">auto-dismiss {countdown}s</span>
          </div>

          <div className="px-6 py-5 space-y-4">
            {/* Status */}
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-emerald-400 animate-pulse flex-shrink-0" />
              <span className="text-emerald-400 font-bold text-sm tracking-wide uppercase">
                Quarantined — Not persisted to audit chain
              </span>
            </div>

            {/* Technique */}
            <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
              <div className="text-gray-500 text-xs uppercase tracking-widest mb-2">MITRE ATLAS Technique</div>
              <div className="text-white font-mono text-sm">
                {technique} · Prompt Injection
              </div>
              <div className="text-gray-400 text-xs mt-1">
                Adversary attempted to embed malicious instructions inside a transaction payload field.
              </div>
            </div>

            {/* Detected pattern */}
            <div className="bg-red-950 rounded-lg p-4 border border-red-800">
              <div className="text-red-400 text-xs uppercase tracking-widest mb-2">Detected Pattern</div>
              <div className="text-red-200 text-sm font-mono break-words">{reason}</div>
            </div>

            {/* Source */}
            <div className="flex justify-between text-xs text-gray-600">
              <span>Source agent: <span className="text-gray-400 font-mono">{agentId}</span></span>
              <span>Governance action: <span className="text-emerald-500 font-semibold">BLOCKED</span></span>
            </div>

            <button
              onClick={onDismiss}
              className="w-full py-2 border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 rounded-lg text-xs tracking-widest uppercase transition-colors"
            >
              Acknowledge
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
