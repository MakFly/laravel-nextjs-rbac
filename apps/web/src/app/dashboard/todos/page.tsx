import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getCurrentUserAction } from '@/lib/api/auth';
import { getTodosAction } from '@/lib/api/admin';
import { SiteHeaderServer } from '@/components/site-header-server';
import { TodosTable } from '@/components/dashboard/todos-table';
import { hasPermission } from '@rbac/types';

/**
 * Todos Management Page - SSR
 *
 * Accessible aux utilisateurs avec permission todos.view
 */
export default async function TodosPage() {
  const user = await getCurrentUserAction();

  if (!user) {
    redirect('/auth/login');
  }

  // Vérifier les permissions
  if (!hasPermission(user, 'todos', 'read')) {
    redirect('/dashboard');
  }

  // Récupérer les todos
  let todos = null;
  let error = null;

  try {
    todos = await getTodosAction(user.id);
  } catch (e) {
    error = e instanceof Error ? e.message : 'Failed to load todos';
  }

  return (
    <>
      <SiteHeaderServer
        title="Todos"
        subtitle="Manage your tasks and priorities"
        user={user}
      />
      <div className="flex flex-1 flex-col gap-4 p-4 pt-6 md:p-8">
        {error ? (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
            <p className="font-medium">Error loading todos</p>
            <p className="text-sm">{error}</p>
          </div>
        ) : (
          <TodosTable todos={todos || []} userId={user.id} />
        )}
      </div>
    </>
  );
}
