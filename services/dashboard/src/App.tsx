// src/App.tsx
import { useState } from "react";
import { useWebSocket } from "./hooks/useWebSocket";
import { AgentFeed } from "./components/AgentFeed";
import { DecisionLog } from "./components/DecisionLog";
import { HitlQueue } from "./components/HitlQueue";
import { SystemHealth } from "./components/SystemHealth";
import { AtlasPanel } from "./components/AtlasPanel";
import { NetworkGraph } from "./components/NetworkGraph";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws";
const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export default function App() {
  const { messages, connected } = useWebSocket(WS_URL);
  const [redTeamLoading, setRedTeamLoading] = useState(false);
  const [redTeamFlash, setRedTeamFlash] = useState(false);

  const triggerRedTeam = async () => {
    setRedTeamLoading(true);
    try {
      await fetch(`${API}/redteam/inject`, { method: "POST" });
      setRedTeamFlash(true);
      setTimeout(() => setRedTeamFlash(false), 2000);
    } catch {}
    setRedTeamLoading(false);
  };

  return (
    <div className={`min-h-screen bg-gray-950 text-white p-6 transition-colors duration-500 ${redTeamFlash ? "bg-red-950" : ""}`}>
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Fides <span className="text-gray-600 font-normal text-lg">· NORDA Bank</span></h1>
            <p className="text-gray-500 text-sm mt-1">Autonomous Fraud Detection · Governance Operations Center</p>
          </div>
          <div className="flex items-center gap-6">
            <SystemHealth connected={connected} />
            <div className="relative">
              <div className={`absolute -inset-1 rounded-lg bg-red-600 opacity-30 ${redTeamLoading ? "" : "animate-pulse"}`} />
              <button
                onClick={triggerRedTeam}
                disabled={redTeamLoading}
                style={{
                  boxShadow: redTeamLoading
                    ? "none"
                    : "0 0 18px rgba(239,68,68,0.5), 0 0 40px rgba(239,68,68,0.15), inset 0 0 10px rgba(239,68,68,0.08)",
                }}
                className="relative flex flex-col items-center px-5 py-2 bg-gray-950 border-2 border-red-600 text-red-400 hover:text-red-300 hover:bg-red-950 disabled:opacity-40 rounded-lg transition-all cursor-pointer"
              >
                <span className="text-lg leading-none mb-0.5">☢</span>
                <span className="text-xs font-black tracking-widest uppercase leading-none">
                  {redTeamLoading ? "INJECTING…" : "Red Team"}
                </span>
                <span className="text-red-700 text-xs leading-none mt-0.5 tracking-wider">
                  {redTeamLoading ? "" : "ATTACK SIM"}
                </span>
              </button>
            </div>
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
