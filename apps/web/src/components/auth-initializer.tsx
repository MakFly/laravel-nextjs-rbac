import { ZustandHydration } from './zustand-hydration';
import { getCurrentUserAction } from '@/lib/api/auth';
import type { User } from '@rbac/types';

interface AuthInitializerProps {
  children: React.ReactNode;
}

/**
 * Server Component qui initialise l'auth avec SSR
 *
 * Fetch l'utilisateur côté serveur et hydrate le store Zustand
 * pour éviter le fetch côté client au montage.
 */
export async function AuthInitializer({ children }: AuthInitializerProps) {
  // Fetch côté serveur (une seule fois)
  let user: User | null = null;

  try {
    user = await getCurrentUserAction();
  } catch {
    // Pas connecté ou token invalide
    user = null;
  }

  return (
    <>
      <ZustandHydration user={user} />
      {children}
    </>
  );
}
