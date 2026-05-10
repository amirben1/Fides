// src/hooks/useWebSocket.ts
import { useEffect, useRef, useState, useCallback } from "react";
import { WSMessage } from "../types/events";

export function useWebSocket(url: string) {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const destroyedRef = useRef(false);

  const connect = useCallback(() => {
    if (destroyedRef.current) return;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      if (!destroyedRef.current) setTimeout(connect, 2000);
    };
    ws.onmessage = (e) => {
      try {
        const msg: WSMessage = JSON.parse(e.data);
        setMessages((prev) => [msg, ...prev].slice(0, 200));
      } catch {}
    };
  }, [url]);

  useEffect(() => {
    destroyedRef.current = false;
    connect();
    return () => {
      destroyedRef.current = true;
      wsRef.current?.close();
    };
  }, [connect]);

  return { messages, connected };
}
