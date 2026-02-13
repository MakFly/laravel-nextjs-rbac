import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getCurrentUserAction } from '@/lib/api/auth';

interface OnboardingLayoutProps {
  children: React.ReactNode;
}

/**
 * SSR layout for the onboarding wizard
 *
 * - No sidebar, minimal chrome for focused KYC experience
 * - Server-side auth check (session cookie)
 * - Redirects to /auth/login if not logged in
 * - Redirects to /dashboard if onboarding already completed
 */
export default async function OnboardingLayout({
  children,
}: OnboardingLayoutProps) {
  const cookieStore = await cookies();
  const session = cookieStore.get('laravel_session');

  if (!session?.value) {
    redirect('/auth/login');
  }

  const initialUser = await getCurrentUserAction();

  if (!initialUser) {
    redirect('/auth/login');
  }

  if (initialUser.onboarding_status === 'completed') {
    redirect('/dashboard');
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-violet-50/20 to-indigo-50/30">
      {/* Background Pattern */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:14px_24px] pointer-events-none" />
      <div className="fixed left-0 right-0 top-0 -z-10 m-auto h-[310px] w-[310px] rounded-full bg-violet-400/20 opacity-20 blur-[100px]" />

      <div className="relative z-10">{children}</div>
    </div>
  );
}
