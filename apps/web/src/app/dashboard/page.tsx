'use client';

import { useAuthStore } from '@/stores/auth-store';
import { SiteHeaderClient } from '@/components/site-header-client';
import { DashboardContent } from '@/components/dashboard/dashboard-content';
import { redirect } from 'next/navigation';
import { Skeleton } from '@/components/ui/skeleton';

/**
 * Dashboard Page - Client Component
 *
 * L'utilisateur est disponible via le store Zustand (hydraté par AuthInitializer).
 * Plus de double fetch !
 */
export default function DashboardPage() {
  const { user, isHydrated } = useAuthStore();

  // Afficher un skeleton pendant l'hydration
  if (!isHydrated) {
    return (
      <>
        <div className="flex h-16 items-center gap-2 border-b px-4">
          <Skeleton className="h-8 w-8" />
          <Skeleton className="h-4 w-32" />
        </div>
        <div className="p-6 space-y-6">
          <Skeleton className="h-8 w-48" />
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-32 rounded-xl" />
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
      <SiteHeaderClient
        title="Dashboard"
        subtitle={`Welcome back, ${user.name.split(' ')[0]}`}
      />
      <DashboardContent user={user} />
    </>
  );
}
