// src/App.tsx
import { useWebSocket } from "./hooks/useWebSocket";
import { AgentFeed } from "./components/AgentFeed";
import { DecisionLog } from "./components/DecisionLog";
import { HitlQueue } from "./components/HitlQueue";
import { SystemHealth } from "./components/SystemHealth";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws";

export default function App() {
  const { messages, connected } = useWebSocket(WS_URL);

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">NORDA Bank · MAS Operations</h1>
            <p className="text-gray-500 text-sm mt-1">Multi-Agent Fraud Detection · Governance Console</p>
          </div>
          <SystemHealth connected={connected} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <AgentFeed messages={messages} />
          </div>
          <div>
            <HitlQueue />
          </div>
        </div>

        <div className="mt-6">
          <DecisionLog messages={messages} />
        </div>
      </div>
    </div>
  );
}
