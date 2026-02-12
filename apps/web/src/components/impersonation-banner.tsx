'use client';

import { useAuthStore } from '@/stores/auth-store';
import { Button } from '@/components/ui/button';

export function ImpersonationBanner() {
  const { isImpersonating, impersonator, stopImpersonating, isLoading } = useAuthStore();

  if (!isImpersonating) return null;

  return (
    <div className="bg-amber-500 text-amber-950 px-4 py-2 text-center text-sm font-medium flex items-center justify-center gap-3">
      <span>
        You are impersonating as the current user.
        {impersonator && (
          <> Logged in admin: <strong>{impersonator.name}</strong></>
        )}
      </span>
      <Button
        variant="outline"
        size="sm"
        className="h-7 bg-amber-600 border-amber-700 text-white hover:bg-amber-700 hover:text-white"
        onClick={() => stopImpersonating()}
        disabled={isLoading}
      >
        {isLoading ? 'Stopping...' : 'Stop Impersonating'}
      </Button>
    </div>
  );
}
