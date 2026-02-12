import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar';
import { AppSidebar } from '@/components/app-sidebar';
import { getCurrentUserAction } from '@/lib/api/auth';

interface DashboardLayoutProps {
  children: React.ReactNode;
}

/**
 * SSR layout for the dashboard
 *
 * - Server-side auth check (session cookie)
 * - Redirects to /auth/login if not logged in
 * - Fetches user server-side for initial sidebar render
 */
export default async function DashboardLayout({ children }: DashboardLayoutProps) {
  const cookieStore = await cookies();
  const session = cookieStore.get('laravel_session');

  if (!session?.value) {
    redirect('/auth/login');
  }

  const initialUser = await getCurrentUserAction();

  return (
    <SidebarProvider>
      <AppSidebar initialUser={initialUser} />
      <SidebarInset>{children}</SidebarInset>
    </SidebarProvider>
  );
}
