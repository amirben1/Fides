// src/App.tsx
import { useState, useEffect } from "react";
import { useWebSocket } from "./hooks/useWebSocket";
import { AgentFeed } from "./components/AgentFeed";
import { DecisionLog } from "./components/DecisionLog";
import { HitlQueue } from "./components/HitlQueue";
import { SystemHealth } from "./components/SystemHealth";
import { AtlasPanel } from "./components/AtlasPanel";
import { NetworkGraph } from "./components/NetworkGraph";
import { ThreatAlert } from "./components/ThreatAlert";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws";
const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

interface ThreatInfo { reason: string; technique: string; agentId: string; }

export default function App() {
  const { messages, connected } = useWebSocket(WS_URL);
  const [redTeamLoading, setRedTeamLoading] = useState(false);
  const [threat, setThreat] = useState<ThreatInfo | null>(null);

  // Watch for prompt injection events from the live feed
  useEffect(() => {
    const latest = messages[0];
    if (!latest || latest.type !== "PROMPT_INJECTION_DETECTED") return;
    const d = latest.data as unknown as Record<string, unknown>;
    setThreat({
      reason: String(d.reason ?? "Unknown injection pattern"),
      technique: String(d.technique ?? "AML0043"),
      agentId: String(d.agent_id ?? "governance"),
    });
  }, [messages]);

  const triggerRedTeam = async () => {
    setRedTeamLoading(true);
    try {
      await fetch(`${API}/redteam/inject`, { method: "POST" });
    } catch {}
    setRedTeamLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      {threat && (
        <ThreatAlert
          reason={threat.reason}
          technique={threat.technique}
          agentId={threat.agentId}
          onDismiss={() => setThreat(null)}
        />
      )}

      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Fides <span className="text-gray-600 font-normal text-lg">· NORDA Bank</span></h1>
            <p className="text-gray-500 text-sm mt-1">Autonomous Fraud Detection · Governance Operations Center</p>
          </div>
          <div className="flex items-center gap-4">
            <SystemHealth connected={connected} />
            <button
              onClick={triggerRedTeam}
              disabled={redTeamLoading}
              className="px-4 py-2 bg-red-800 hover:bg-red-700 disabled:opacity-50 text-white text-xs font-bold rounded border border-red-600 tracking-widest transition-colors"
            >
              {redTeamLoading ? "INJECTING..." : "⚠ RED TEAM"}
            </button>
          </div>
        </div>

        {/* Main grid: AgentFeed (2/3) + HitlQueue (1/3) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <AgentFeed messages={messages} />
          </div>
          <div>
            <HitlQueue />
          </div>
        </div>

        {/* ATLAS panel + Audit Log */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
          <AtlasPanel />
          <DecisionLog messages={messages} />
        </div>

        {/* Network Graph */}
        <div className="mt-6">
          <NetworkGraph messages={messages} />
        </div>
      </div>
    </div>
  );
}
