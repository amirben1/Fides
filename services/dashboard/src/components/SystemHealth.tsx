// src/components/SystemHealth.tsx
export function SystemHealth({ connected }: { connected: boolean }) {
  return (
    <div className="flex items-center gap-4 text-xs font-mono">
      <div className="flex items-center gap-1">
        <div className={`w-2 h-2 rounded-full ${connected ? "bg-emerald-400" : "bg-red-500"} animate-pulse`} />
        <span className="text-gray-400">Orchestrator {connected ? "LIVE" : "OFFLINE"}</span>
      </div>
      <div className="flex items-center gap-1">
        <div className="w-2 h-2 rounded-full bg-emerald-400" />
        <span className="text-gray-400">Governance</span>
      </div>
      <div className="flex items-center gap-1">
        <div className="w-2 h-2 rounded-full bg-emerald-400" />
        <span className="text-gray-400">Wazuh SOC</span>
      </div>
    </div>
  );
}
