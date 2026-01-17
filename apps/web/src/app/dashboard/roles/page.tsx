import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getCurrentUserAction } from '@/lib/api/auth';
import { getRolesAction, getPermissionsAction } from '@/lib/api/admin';
import { SiteHeaderServer } from '@/components/site-header-server';
import { RolesTable } from '@/components/dashboard/roles-table';
import { isAdmin } from '@rbac/types';

/**
 * Roles Management Page - SSR
 *
 * Accessible uniquement aux admins
 */
export default async function RolesPage() {
  const user = await getCurrentUserAction();

  if (!user) {
    redirect('/auth/login');
  }

  // Vérifier les permissions admin
  if (!isAdmin(user)) {
    redirect('/dashboard');
  }

  // Récupérer les données en parallèle
  let roles = null;
  let permissions = null;
  let error = null;

  try {
    [roles, permissions] = await Promise.all([getRolesAction(), getPermissionsAction()]);
  } catch (e) {
    error = e instanceof Error ? e.message : 'Failed to load data';
  }

  return (
    <>
      <SiteHeaderServer
        title="Roles Management"
        subtitle="Manage roles and permissions"
        user={user}
      />
      <div className="flex flex-1 flex-col gap-4 p-4 pt-6 md:p-8">
        {error ? (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
            <p className="font-medium">Error loading roles</p>
            <p className="text-sm">{error}</p>
          </div>
        ) : (
          <RolesTable roles={roles || []} permissions={permissions || []} />
        )}
      </div>
    </>
  );
}
