'use client';

import { useAuthStore } from '@/stores/auth-store';
import { Button } from '@/components/ui/button';
import { UsersRound, LogOut } from 'lucide-react';

export function ImpersonationBanner() {
  const { isImpersonating, impersonator, stopImpersonating, isLoading } = useAuthStore();

  if (!isImpersonating) return null;

  return (
    <div className="bg-gradient-to-r from-amber-500 via-orange-500 to-amber-500 border-b border-amber-600/50">
      <div className="px-4 py-2.5 flex items-center justify-center gap-4">
        {/* Icon + Pulse indicator */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <UsersRound className="h-4 w-4 text-white" />
            <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-white animate-pulse" />
          </div>
          <span className="text-white font-semibold text-sm tracking-wide uppercase">
            Mode Impersonation
          </span>
        </div>

        {/* Divider */}
        <div className="h-4 w-px bg-white/30" />

        {/* Info text */}
        <div className="flex items-center gap-2 text-white/90 text-sm">
          <span>Connecté en tant que</span>
          {impersonator && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-white/20 rounded-full text-white font-medium">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />
              {impersonator.name}
              <span className="text-xs text-white/70 font-normal">(admin)</span>
            </span>
          )}
        </div>

        {/* Stop button */}
        <Button
          variant="secondary"
          size="sm"
          className="h-7 gap-1.5 bg-white/90 hover:bg-white text-amber-700 font-medium shadow-sm border-0 px-3"
          onClick={() => stopImpersonating()}
          disabled={isLoading}
        >
          <LogOut className="h-3.5 w-3.5" />
          {isLoading ? 'Arrêt...' : 'Quitter'}
        </Button>
      </div>
    </div>
  );
}
