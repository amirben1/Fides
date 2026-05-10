// src/hooks/useWebSocket.ts
import { useEffect, useRef, useState, useCallback } from "react";
import { WSMessage } from "../types/events";

export function useWebSocket(url: string) {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      setTimeout(connect, 2000);
    };
    ws.onmessage = (e) => {
      try {
        const msg: WSMessage = JSON.parse(e.data);
        setMessages((prev) => [msg, ...prev].slice(0, 200));
      } catch {}
    };
  }, [url]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  return { messages, connected };
}
