import { ref, onMounted, onUnmounted } from 'vue';
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

export function useOrderBook() {
  const data = ref<OrderBookData | null>(null);
  const isConnected = ref(false);
  const error = ref<string | null>(null);

  onMounted(() => {
    try {
      const echo = getEcho();

      echo
        .channel('orderbook')
        .listen('.OrderBookUpdated', (event: OrderBookData) => {
          data.value = event;
          isConnected.value = true;
          error.value = null;
        })
        .error((err: unknown) => {
          error.value = String(err);
          isConnected.value = false;
        });

      isConnected.value = true;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
    }
  });

  onUnmounted(() => {
    try {
      const echo = getEcho();
      echo.leave('orderbook');
    } catch {
      // Echo not initialized, nothing to clean up
    }
  });

  return { data, isConnected, error };
}
