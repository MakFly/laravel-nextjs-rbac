'use client';

import { useEffect, useRef, useSyncExternalStore } from 'react';
import { getEcho } from '@/lib/echo';

export interface OrderBookEntry {
  price: string;
  qty: string;
}

export interface OrderBookData {
  bids: OrderBookEntry[];
  asks: OrderBookEntry[];
  lastUpdateId: number;
  timestamp: number;
}

interface OrderBookState {
  data: OrderBookData | null;
  isConnected: boolean;
  error: string | null;
}

let state: OrderBookState = { data: null, isConnected: false, error: null };
const listeners = new Set<() => void>();

function getSnapshot(): OrderBookState {
  return state;
}

function getServerSnapshot(): OrderBookState {
  return { data: null, isConnected: false, error: null };
}

function setState(partial: Partial<OrderBookState>) {
  state = { ...state, ...partial };
  listeners.forEach((l) => l());
}

export function useOrderBook() {
  const subscribedRef = useRef(false);
  const snapshot = useSyncExternalStore(
    (onStoreChange) => {
      listeners.add(onStoreChange);
      return () => listeners.delete(onStoreChange);
    },
    getSnapshot,
    getServerSnapshot,
  );

  useEffect(() => {
    if (subscribedRef.current) return;
    subscribedRef.current = true;

    try {
      const echo = getEcho();
      const channel = echo.channel('orderbook');

      channel
        .listen('.OrderBookUpdated', (event: OrderBookData) => {
          setState({ data: event, isConnected: true, error: null });
        })
        .error((err: unknown) => {
          setState({ error: String(err), isConnected: false });
        });

      setState({ isConnected: true });
    } catch (err) {
      setState({ error: err instanceof Error ? err.message : String(err) });
    }

    return () => {
      subscribedRef.current = false;
      try {
        const echo = getEcho();
        echo.leave('orderbook');
      } catch {
        // Echo not initialized, nothing to clean up
      }
      setState({ data: null, isConnected: false, error: null });
    };
  }, []);

  return snapshot;
}
