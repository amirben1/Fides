// src/components/NetworkGraph.tsx
import { useEffect, useRef } from "react";
import { WSMessage, NetworkNode, NetworkEdge } from "../types/events";

interface GraphState {
  nodes: Map<string, NetworkNode>;
  edges: NetworkEdge[];
  animFrame: number;
}

export function NetworkGraph({ messages }: { messages: WSMessage[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const stateRef = useRef<GraphState>({ nodes: new Map(), edges: [], animFrame: 0 });

  // Update graph data when new messages arrive
  useEffect(() => {
    const { nodes, edges } = stateRef.current;
    const txMessages = messages.filter((m) => m.type === "TRANSACTION_RECEIVED");

    for (const m of txMessages) {
      const data = m.data as unknown as Record<string, unknown>;
      const payload = (data.payload ?? data) as Record<string, unknown>;
      const accountId = String(payload.account_id ?? "");
      const country = String(payload.counterparty_country ?? "");
      const amount = Number(payload.amount ?? 0);
      const highRisk = Boolean(payload.high_risk ?? false);
      if (!accountId || !country) continue;

      const addOrUpdate = (id: string, risk: boolean) => {
        if (!nodes.has(id)) {
          nodes.set(id, {
            id,
            x: Math.random() * 500 + 50,
            y: Math.random() * 200 + 50,
            vx: 0,
            vy: 0,
            count: 0,
            highRisk: false,
          });
        }
        const n = nodes.get(id)!;
        n.count += 1;
        n.highRisk = n.highRisk || risk;
      };

      addOrUpdate(accountId, highRisk);
      addOrUpdate(country, highRisk);
      edges.push({ source: accountId, target: country, amount, highRisk });

      // Keep bounded
      if (edges.length > 60) edges.splice(0, edges.length - 60);
      if (nodes.size > 30) {
        const firstKey = nodes.keys().next().value;
        if (firstKey !== undefined) nodes.delete(firstKey);
      }
    }
  }, [messages]);

  // Force simulation + canvas render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;

    const tick = () => {
      const { nodes, edges } = stateRef.current;
      const W = canvas.offsetWidth || 600;
      const H = canvas.offsetHeight || 260;
      canvas.width = W;
      canvas.height = H;
      ctx.clearRect(0, 0, W, H);

      const nodeArr = [...nodes.values()];

      // Repulsion between all node pairs
      for (const a of nodeArr) {
        for (const b of nodeArr) {
          if (a === b) continue;
          const dx = a.x - b.x || 0.01;
          const dy = a.y - b.y || 0.01;
          const d2 = dx * dx + dy * dy;
          const d = Math.sqrt(d2);
          const f = 3000 / d2;
          a.vx += (dx / d) * f;
          a.vy += (dy / d) * f;
        }
        // Gravity toward center
        a.vx += (W / 2 - a.x) * 0.002;
        a.vy += (H / 2 - a.y) * 0.002;
        // Damping + integrate
        a.vx *= 0.8;
        a.vy *= 0.8;
        a.x = Math.max(24, Math.min(W - 24, a.x + a.vx));
        a.y = Math.max(24, Math.min(H - 24, a.y + a.vy));
      }

      // Spring attraction along edges
      for (const e of edges) {
        const s = nodes.get(e.source);
        const t = nodes.get(e.target);
        if (!s || !t) continue;
        const dx = t.x - s.x;
        const dy = t.y - s.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - 100) * 0.006;
        s.vx += (dx / d) * f;
        s.vy += (dy / d) * f;
        t.vx -= (dx / d) * f;
        t.vy -= (dy / d) * f;
      }

      // Draw edges
      for (const e of edges) {
        const s = nodes.get(e.source);
        const t = nodes.get(e.target);
        if (!s || !t) continue;
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        ctx.strokeStyle = e.highRisk ? "rgba(239,68,68,0.45)" : "rgba(52,211,153,0.25)";
        ctx.lineWidth = e.highRisk ? 1.5 : 0.8;
        ctx.stroke();
      }

      // Draw nodes
      for (const n of nodeArr) {
        const r = Math.min(5 + n.count * 1.2, 18);
        const isCountry = n.id.length === 2;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = n.highRisk ? "#ef4444" : isCountry ? "#6366f1" : "#10b981";
        ctx.fill();
        ctx.font = "9px monospace";
        ctx.fillStyle = "#9ca3af";
        ctx.textAlign = "center";
        ctx.fillText(n.id, n.x, n.y + r + 10);
      }

      stateRef.current.animFrame = requestAnimationFrame(tick);
    };

    stateRef.current.animFrame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(stateRef.current.animFrame);
  }, []);

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="flex items-center gap-3 mb-2">
        <div className="text-gray-500 text-xs uppercase tracking-widest">Transaction Network</div>
        <div className="flex items-center gap-3 text-xs text-gray-600">
          <span className="flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500" />
            account
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-indigo-500" />
            country
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-red-500" />
            high-risk
          </span>
        </div>
      </div>
      <canvas ref={canvasRef} className="w-full h-64 rounded" />
    </div>
  );
}
