// src/components/ExplanationCard.tsx
import { ExplanationCard as ExplanationCardType } from "../types/events";

const RISK_STYLES: Record<string, string> = {
  CRITICAL: "border-rose-600 bg-rose-950",
  HIGH: "border-red-700 bg-red-950",
  MEDIUM: "border-yellow-700 bg-yellow-950",
  LOW: "border-gray-700 bg-gray-900",
};

const RISK_BADGE: Record<string, string> = {
  CRITICAL: "bg-rose-600 text-white",
  HIGH: "bg-red-700 text-white",
  MEDIUM: "bg-yellow-700 text-white",
  LOW: "bg-gray-700 text-gray-200",
};

export function ExplanationCard({ explanation }: { explanation: ExplanationCardType }) {
  return (
    <div className={`rounded border p-3 mb-2 text-xs ${RISK_STYLES[explanation.risk_level] ?? RISK_STYLES.LOW}`}>
      <div className="flex items-center gap-2 mb-2">
        <span className={`px-2 py-0.5 rounded text-xs font-bold ${RISK_BADGE[explanation.risk_level]}`}>
          {explanation.risk_level}
        </span>
        <span className="text-gray-400 uppercase tracking-widest text-xs">Risk Assessment</span>
      </div>

      <div className="mb-2">
        <div className="text-gray-500 text-xs mb-1 uppercase tracking-wide">Why Flagged</div>
        <ul className="space-y-0.5">
          {explanation.why_flagged.map((reason, i) => (
            <li key={i} className="text-gray-200 flex gap-1">
              <span className="text-yellow-500 shrink-0">›</span>
              <span>{reason}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="mb-2">
        <div className="text-gray-500 text-xs mb-1 uppercase tracking-wide">Regulation</div>
        <div className="text-blue-300">{explanation.regulation}</div>
      </div>

      <div>
        <div className="text-gray-500 text-xs mb-1 uppercase tracking-wide">Recommended Action</div>
        <div className="text-emerald-300 font-medium">{explanation.recommended_action}</div>
      </div>
    </div>
  );
}
