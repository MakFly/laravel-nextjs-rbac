'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import type {
  OnboardingDraft,
  PersonalInfoData,
  IdentityVerificationData,
  FinancialProfileData,
  OperationSetupData,
} from '@rbac/types';
import {
  saveOnboardingStepAction,
  completeOnboardingAction,
} from '@/lib/api/onboarding';
import { useAuthStore } from '@/stores/auth-store';
import Link from 'next/link';
import { ArrowRightIcon, Wand2Icon, LoaderIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Stepper } from './stepper';
import { PersonalInfoForm } from './steps/personal-info-form';
import { IdentityVerificationForm } from './steps/identity-verification-form';
import { FinancialProfileForm } from './steps/financial-profile-form';
import { OperationSetupForm } from './steps/operation-setup-form';

type StepData =
  | PersonalInfoData
  | IdentityVerificationData
  | FinancialProfileData
  | OperationSetupData;

interface OnboardingWizardProps {
  initialDraft: OnboardingDraft | null;
}

export function OnboardingWizard({ initialDraft }: OnboardingWizardProps) {
  const router = useRouter();
  const { refreshUser } = useAuthStore();

  const [currentStep, setCurrentStep] = useState(
    initialDraft?.current_step ?? 1
  );
  const [draftData, setDraftData] = useState<OnboardingDraft['data']>(
    initialDraft?.data ?? {}
  );
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAutofilling, setIsAutofilling] = useState(false);

  // Compute completed steps from draft data
  const completedSteps = Object.keys(draftData)
    .filter((key) => draftData[key as keyof typeof draftData] !== undefined)
    .map((key) => parseInt(key.replace('step', ''), 10));

  const handleStepSubmit = useCallback(
    async (step: number, data: StepData) => {
      setIsSubmitting(true);
      try {
        const response = await saveOnboardingStepAction(step, data);

        // Update local draft data
        setDraftData(response.data.data);

        if (step < 4) {
          // Move to next step
          setCurrentStep(step + 1);
          toast.success('Progress saved', {
            description: `Step ${step} completed successfully.`,
          });
        } else {
          // Final step - complete onboarding
          await completeOnboardingAction();
          await refreshUser();
          toast.success('Onboarding complete!', {
            description: 'Your account is now fully set up.',
          });
          router.push('/dashboard');
        }
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'Failed to save progress';
        toast.error('Error', { description: message });
      } finally {
        setIsSubmitting(false);
      }
    },
    [refreshUser, router]
  );

  const handleAutofillAll = useCallback(async () => {
    setIsAutofilling(true);
    try {
      const pick = <T,>(arr: readonly T[]) => arr[Math.floor(Math.random() * arr.length)]!;
      const rnum = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
      const pad = (n: number) => String(n).padStart(2, '0');
      const rl = () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
      const rn = () => String(Math.floor(Math.random() * 10));

      const locs = [
        { country: 'FR', city: 'Paris', postal: '75001', street: '42 Rue de Rivoli', phone: '+33 6 12 34 56 78' },
        { country: 'US', city: 'New York', postal: '10001', street: '350 Fifth Avenue', phone: '+1 555 234 5678' },
        { country: 'GB', city: 'London', postal: 'SW1A 2AA', street: '10 Downing Street', phone: '+44 7911 123456' },
      ] as const;
      const loc = pick(locs);

      const step1: PersonalInfoData = {
        phone: loc.phone, date_of_birth: `${rnum(1970, 2000)}-${pad(rnum(1, 12))}-${pad(rnum(1, 28))}`,
        street: loc.street, city: loc.city, postal_code: loc.postal,
        country: loc.country, nationality: pick(locs).country,
      };

      const step2: IdentityVerificationData = {
        id_document_type: pick(['passport', 'national_id', 'drivers_license'] as const),
        id_document_number: `${rl()}${rl()}${rn()}${rn()}${rn()}${rn()}${rn()}${rn()}${rn()}`,
        id_expiry_date: `${rnum(2027, 2032)}-${pad(rnum(1, 12))}-${pad(rnum(1, 28))}`,
      };

      const step3: FinancialProfileData = {
        employment_status: pick(['employed', 'self_employed', 'retired', 'student'] as const),
        annual_income_range: pick(['under_25k', '25k_50k', '50k_100k', '100k_250k'] as const),
        source_of_funds: pick(['salary', 'business_income', 'investments', 'savings'] as const),
        investment_experience: pick(['none', 'beginner', 'intermediate', 'advanced', 'expert'] as const),
      };

      const accountType = pick(['banking', 'crypto', 'both'] as const);
      const step4: OperationSetupData = {
        account_type: accountType,
        initial_transaction_amount: pick(['under_1k', '1k_10k', '10k_50k'] as const),
      };
      if (accountType === 'banking' || accountType === 'both') {
        step4.preferred_currency = pick(['EUR', 'USD', 'GBP', 'CHF'] as const);
        step4.iban = `FR76 ${rnum(1000, 9999)} ${rnum(1000, 9999)} ${rnum(1000, 9999)} ${rnum(1000, 9999)} ${rnum(100, 999)}`;
      }
      if (accountType === 'crypto' || accountType === 'both') {
        step4.preferred_cryptocurrency = pick(['BTC', 'ETH', 'USDT', 'USDC'] as const);
        step4.wallet_address = '0x' + Array.from({ length: 40 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
      }

      await saveOnboardingStepAction(1, step1);
      await saveOnboardingStepAction(2, step2);
      await saveOnboardingStepAction(3, step3);
      await saveOnboardingStepAction(4, step4);
      await completeOnboardingAction();
      await refreshUser();
      toast.success('Onboarding complete!', { description: 'All steps filled automatically.' });
      router.push('/dashboard');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Autofill failed';
      toast.error('Error', { description: message });
    } finally {
      setIsAutofilling(false);
    }
  }, [refreshUser, router]);

  const handleBack = useCallback(() => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  }, [currentStep]);

  return (
    <div className="w-full max-w-2xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Stepper */}
      <Stepper currentStep={currentStep} completedSteps={completedSteps} />

      {/* Step Forms */}
      <div className="animate-in fade-in duration-300">
        {currentStep === 1 && (
          <PersonalInfoForm
            defaultValues={draftData.step1}
            onSubmit={(data) => handleStepSubmit(1, data)}
            isSubmitting={isSubmitting}
          />
        )}

        {currentStep === 2 && (
          <IdentityVerificationForm
            defaultValues={draftData.step2}
            onSubmit={(data) => handleStepSubmit(2, data)}
            onBack={handleBack}
            isSubmitting={isSubmitting}
          />
        )}

        {currentStep === 3 && (
          <FinancialProfileForm
            defaultValues={draftData.step3}
            onSubmit={(data) => handleStepSubmit(3, data)}
            onBack={handleBack}
            isSubmitting={isSubmitting}
          />
        )}

        {currentStep === 4 && (
          <OperationSetupForm
            defaultValues={draftData.step4}
            onSubmit={(data) => handleStepSubmit(4, data)}
            onBack={handleBack}
            isSubmitting={isSubmitting}
          />
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center justify-center gap-4">
        <Button
          variant="outline"
          size="sm"
          disabled={isAutofilling}
          onClick={handleAutofillAll}
        >
          {isAutofilling ? (
            <>
              <LoaderIcon className="h-4 w-4 mr-1.5 animate-spin" />
              Filling...
            </>
          ) : (
            <>
              <Wand2Icon className="h-4 w-4 mr-1.5" />
              Autofill all steps
            </>
          )}
        </Button>
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          Skip for now
          <ArrowRightIcon className="h-3 w-3" />
        </Link>
      </div>
    </div>
  );
}
