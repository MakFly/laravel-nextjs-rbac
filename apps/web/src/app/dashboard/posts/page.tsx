import { redirect } from 'next/navigation';
import { getCurrentUserAction } from '@/lib/api/auth';
import { getPostsAction } from '@/lib/api/admin';
import { SiteHeaderServer } from '@/components/site-header-server';
import { PostsGrid } from '@/components/dashboard/posts-grid';
import { hasPermission, isAdmin } from '@rbac/types';

/**
 * Posts Page - SSR avec JSONPlaceholder
 *
 * Démontre les permissions RBAC sur des fake data
 */
export default async function PostsPage() {
  const user = await getCurrentUserAction();

  if (!user) {
    redirect('/auth/login');
  }

  // Vérifier les permissions
  const canRead = hasPermission(user, 'posts', 'read') || isAdmin(user);
  const canCreate = hasPermission(user, 'posts', 'create') || isAdmin(user);
  const canUpdate = hasPermission(user, 'posts', 'update') || isAdmin(user);
  const canDelete = hasPermission(user, 'posts', 'delete') || isAdmin(user);

  if (!canRead) {
    redirect('/dashboard');
  }

  // Récupérer les posts depuis JSONPlaceholder
  const posts = await getPostsAction(20);

  return (
    <>
      <SiteHeaderServer
        title="Posts"
        subtitle="Manage posts with RBAC permissions"
        user={user}
      />
      <div className="flex flex-1 flex-col gap-4 p-4 pt-6 md:p-8">
        <PostsGrid
          posts={posts}
          permissions={{
            canCreate,
            canUpdate,
            canDelete,
          }}
        />
      </div>
    </>
  );
}
