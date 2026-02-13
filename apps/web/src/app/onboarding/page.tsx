'use client';

import { useEffect, useState } from 'react';
import { useAuthStore } from '@/stores/auth-store';
import { getOnboardingDraftAction } from '@/lib/api/onboarding';
import { OnboardingWizard } from '@/components/onboarding/onboarding-wizard';
import { Skeleton } from '@/components/ui/skeleton';
import { ShieldIcon } from 'lucide-react';
import type { OnboardingDraft } from '@rbac/types';

export default function OnboardingPage() {
  const { user, refreshUser } = useAuthStore();
  const [draft, setDraft] = useState<OnboardingDraft | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function loadDraft() {
      try {
        // Ensure user state is fresh
        if (!user) {
          await refreshUser();
        }

        const response = await getOnboardingDraftAction();
        setDraft(response.data);
      } catch {
        // Draft may not exist yet, that's fine
        setDraft(null);
      } finally {
        setIsLoading(false);
      }
    }

    loadDraft();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen px-4">
        <div className="w-full max-w-2xl space-y-6">
          {/* Header skeleton */}
          <div className="flex flex-col items-center space-y-4">
            <Skeleton className="h-16 w-16 rounded-2xl" />
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-4 w-80" />
          </div>

          {/* Stepper skeleton */}
          <div className="flex items-center justify-center gap-4 py-6">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="flex items-center gap-2">
                <Skeleton className="h-10 w-10 rounded-full" />
                <Skeleton className="h-4 w-20" />
                {i < 4 && <Skeleton className="h-0.5 w-12" />}
              </div>
            ))}
          </div>

          {/* Form skeleton */}
          <div className="space-y-4 p-6">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <div className="grid grid-cols-2 gap-4">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
            <Skeleton className="h-10 w-full" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center min-h-screen px-4 py-8">
      {/* Header */}
      <div className="flex flex-col items-center space-y-3 mb-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
        <div className="h-16 w-16 rounded-2xl bg-gradient-to-br from-violet-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-violet-500/25">
          <ShieldIcon className="h-8 w-8 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-center">
          Complete Your Profile
        </h1>
        <p className="text-muted-foreground text-center max-w-md">
          We need a few details to verify your identity and set up your account.
          This information is required for regulatory compliance.
        </p>
      </div>

      <OnboardingWizard initialDraft={draft} />
    </div>
  );
}
