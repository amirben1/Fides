// src/components/AtlasPanel.tsx
import { useState, useEffect } from "react";
import { AtlasThreat } from "../types/events";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const STATUS_STYLES: Record<string, string> = {
  monitoring: "text-gray-400",
  active: "text-yellow-400",
  blocked: "text-emerald-400",
};

const STATUS_DOT: Record<string, string> = {
  monitoring: "bg-gray-600",
  active: "bg-yellow-500 animate-pulse",
  blocked: "bg-emerald-500",
};

const STATUS_LABEL: Record<string, string> = {
  monitoring: "MONITORING",
  active: "ACTIVE THREAT",
  blocked: "BLOCKED",
};

export function AtlasPanel() {
  const [threats, setThreats] = useState<AtlasThreat[]>([]);

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch(`${API}/atlas/threats`);
        const data = await res.json();
        setThreats(data.threats ?? []);
      } catch {}
    };
    fetchThreats();
    const id = setInterval(fetchThreats, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-3">
        <div className="text-gray-500 text-xs uppercase tracking-widest">MITRE ATLAS</div>
        <div className="text-gray-600 text-xs">· Live Threat Monitor</div>
      </div>
      <div className="space-y-2">
        {threats.map((t) => (
          <div key={t.technique_id} className="flex items-center justify-between border-b border-gray-800 pb-2">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${STATUS_DOT[t.status] ?? "bg-gray-600"}`} />
              <div>
                <div className="text-gray-300 text-xs font-mono">{t.technique_id}</div>
                <div className="text-gray-500 text-xs">{t.name}</div>
              </div>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="text-gray-600">
                {t.attempts} attempt{t.attempts !== 1 ? "s" : ""}
                {t.blocked > 0 && (
                  <span className="text-emerald-500 ml-1">· {t.blocked} blocked</span>
                )}
              </div>
              <div className={`font-bold ${STATUS_STYLES[t.status] ?? "text-gray-400"}`}>
                {STATUS_LABEL[t.status] ?? t.status.toUpperCase()}
              </div>
            </div>
          </div>
        ))}
        {threats.length === 0 && (
          <div className="text-gray-600 text-xs">Loading threat data...</div>
        )}
      </div>
    </div>
  );
}
