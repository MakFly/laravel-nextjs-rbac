'use client';

import { useEffect, useRef } from 'react';
import { useAuthStore } from '@/stores/auth-store';
import type { User } from '@rbac/types';

interface ZustandHydrationProps {
  user: User | null;
}

/**
 * Composant pour hydrater le store Zustand depuis les données SSR.
 *
 * Doit être placé dans un Server Component parent qui fetch l'utilisateur,
 * puis passe le user à ce composant client.
 *
 * L'hydration ne se fait qu'une seule fois au montage.
 */
export function ZustandHydration({ user }: ZustandHydrationProps) {
  const hydrated = useRef(false);

  useEffect(() => {
    if (!hydrated.current) {
      useAuthStore.getState().hydrate(user);
      hydrated.current = true;
    }
  }, [user]);

  return null;
}
