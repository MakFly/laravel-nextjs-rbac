import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getCurrentUserAction } from '@/lib/api/auth';
import { SiteHeaderServer } from '@/components/site-header-server';
import { ApiKeysTable } from '@/components/dashboard/api-keys-table';
import { hasPermission } from '@rbac/types';

/**
 * API Keys Management Page - SSR
 *
 * Accessible aux utilisateurs avec permission api-keys.view
 */
export default async function ApiKeysPage() {
  const user = await getCurrentUserAction();

  if (!user) {
    redirect('/auth/login');
  }

  // Vérifier les permissions
  if (!hasPermission(user, 'api-keys', 'read')) {
    redirect('/dashboard');
  }

  return (
    <>
      <SiteHeaderServer
        title="API Keys"
        subtitle="Manage your API keys for external access"
        user={user}
      />
      <div className="flex flex-1 flex-col gap-4 p-4 pt-6 md:p-8">
        <ApiKeysTable userId={user.id} />
      </div>
    </>
  );
}
