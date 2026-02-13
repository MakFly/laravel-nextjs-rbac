'use client';

import { CheckIcon, UserIcon, FingerprintIcon, WalletIcon, SettingsIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

const STEPS = [
  { number: 1, label: 'Personal Info', icon: UserIcon },
  { number: 2, label: 'Identity', icon: FingerprintIcon },
  { number: 3, label: 'Financial', icon: WalletIcon },
  { number: 4, label: 'Operations', icon: SettingsIcon },
] as const;

interface StepperProps {
  currentStep: number;
  completedSteps: number[];
}

export function Stepper({ currentStep, completedSteps }: StepperProps) {
  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="flex items-center justify-between">
        {STEPS.map((step, index) => {
          const isCompleted = completedSteps.includes(step.number);
          const isCurrent = currentStep === step.number;
          const isFuture = !isCompleted && !isCurrent;
          const StepIcon = step.icon;

          return (
            <div key={step.number} className="flex items-center flex-1 last:flex-none">
              {/* Step circle + label */}
              <div className="flex flex-col items-center gap-2">
                <div
                  className={cn(
                    'h-10 w-10 rounded-full flex items-center justify-center text-sm font-medium transition-all duration-300 border-2',
                    isCompleted &&
                      'bg-gradient-to-br from-violet-600 to-indigo-600 border-violet-600 text-white shadow-md shadow-violet-500/25',
                    isCurrent &&
                      'border-violet-600 bg-violet-50 text-violet-700 shadow-md shadow-violet-500/15',
                    isFuture &&
                      'border-muted-foreground/20 bg-muted/30 text-muted-foreground'
                  )}
                >
                  {isCompleted ? (
                    <CheckIcon className="h-5 w-5" />
                  ) : (
                    <StepIcon className="h-5 w-5" />
                  )}
                </div>
                <span
                  className={cn(
                    'text-xs font-medium transition-colors hidden sm:block',
                    isCompleted && 'text-violet-700',
                    isCurrent && 'text-violet-700',
                    isFuture && 'text-muted-foreground'
                  )}
                >
                  {step.label}
                </span>
              </div>

              {/* Connector line */}
              {index < STEPS.length - 1 && (
                <div className="flex-1 mx-3 mb-6 sm:mb-0">
                  <div
                    className={cn(
                      'h-0.5 w-full rounded-full transition-all duration-500',
                      isCompleted
                        ? 'bg-gradient-to-r from-violet-600 to-indigo-600'
                        : 'bg-muted-foreground/15'
                    )}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
