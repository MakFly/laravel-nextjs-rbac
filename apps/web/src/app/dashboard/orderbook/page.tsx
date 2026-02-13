'use client';

import { useAuthStore } from '@/stores/auth-store';
import { SiteHeaderClient } from '@/components/site-header-client';
import { OrderBookView } from '@/components/dashboard/orderbook-view';
import { redirect } from 'next/navigation';
import { Skeleton } from '@/components/ui/skeleton';

export default function OrderBookPage() {
  const { user, isHydrated } = useAuthStore();

  if (!isHydrated) {
    return (
      <>
        <div className="flex h-16 items-center gap-2 border-b px-4">
          <Skeleton className="h-8 w-8" />
          <Skeleton className="h-4 w-32" />
        </div>
        <div className="p-6 space-y-6">
          <Skeleton className="h-8 w-48" />
          <div className="grid gap-4 md:grid-cols-2">
            {[...Array(2)].map((_, i) => (
              <Skeleton key={i} className="h-96 rounded-xl" />
            ))}
          </div>
        </div>
      </>
    );
  }

  if (!user) {
    redirect('/auth/login');
  }

  return (
    <>
      <SiteHeaderClient title="OrderBook" subtitle="BTC/USDT Real-time" />
      <OrderBookView />
    </>
  );
}
