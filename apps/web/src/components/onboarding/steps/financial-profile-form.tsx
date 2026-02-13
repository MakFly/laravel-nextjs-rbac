'use client';

import { useState } from 'react';
import type { FinancialProfileData } from '@rbac/types';
import { financialProfileSchema } from '@/lib/validations/onboarding';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ArrowLeftIcon, ArrowRightIcon, LoaderIcon } from 'lucide-react';

const EMPLOYMENT_STATUSES = [
  { value: 'employed', label: 'Employed' },
  { value: 'self_employed', label: 'Self-Employed' },
  { value: 'business_owner', label: 'Business Owner' },
  { value: 'retired', label: 'Retired' },
  { value: 'student', label: 'Student' },
  { value: 'unemployed', label: 'Unemployed' },
] as const;

const INCOME_RANGES = [
  { value: 'under_25k', label: 'Under $25,000' },
  { value: '25k_50k', label: '$25,000 - $50,000' },
  { value: '50k_100k', label: '$50,000 - $100,000' },
  { value: '100k_250k', label: '$100,000 - $250,000' },
  { value: '250k_500k', label: '$250,000 - $500,000' },
  { value: 'over_500k', label: 'Over $500,000' },
] as const;

const SOURCE_OF_FUNDS = [
  { value: 'salary', label: 'Salary / Employment Income' },
  { value: 'business_income', label: 'Business Income' },
  { value: 'investments', label: 'Investment Returns' },
  { value: 'inheritance', label: 'Inheritance' },
  { value: 'savings', label: 'Personal Savings' },
  { value: 'pension', label: 'Pension / Retirement' },
  { value: 'other', label: 'Other' },
] as const;

const INVESTMENT_EXPERIENCE = [
  { value: 'none', label: 'No Experience' },
  { value: 'beginner', label: 'Beginner (< 1 year)' },
  { value: 'intermediate', label: 'Intermediate (1-3 years)' },
  { value: 'advanced', label: 'Advanced (3-5 years)' },
  { value: 'expert', label: 'Expert (5+ years)' },
] as const;

interface FinancialProfileFormProps {
  defaultValues?: FinancialProfileData;
  onSubmit: (data: FinancialProfileData) => void;
  onBack: () => void;
  isSubmitting: boolean;
}

export function FinancialProfileForm({
  defaultValues,
  onSubmit,
  onBack,
  isSubmitting,
}: FinancialProfileFormProps) {
  const [employmentStatus, setEmploymentStatus] = useState(
    defaultValues?.employment_status ?? ''
  );
  const [annualIncomeRange, setAnnualIncomeRange] = useState(
    defaultValues?.annual_income_range ?? ''
  );
  const [sourceOfFunds, setSourceOfFunds] = useState(
    defaultValues?.source_of_funds ?? ''
  );
  const [investmentExperience, setInvestmentExperience] = useState(
    defaultValues?.investment_experience ?? ''
  );
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    const data: FinancialProfileData = {
      employment_status: employmentStatus,
      annual_income_range: annualIncomeRange,
      source_of_funds: sourceOfFunds,
      investment_experience: investmentExperience,
    };

    const result = financialProfileSchema.safeParse(data);

    if (!result.success) {
      const fieldErrors: Record<string, string> = {};
      for (const issue of result.error.issues) {
        const field = issue.path[0] as string;
        if (!fieldErrors[field]) {
          fieldErrors[field] = issue.message;
        }
      }
      setErrors(fieldErrors);
      return;
    }

    onSubmit(result.data);
  };

  return (
    <Card className="relative overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-violet-600 via-indigo-600 to-violet-600" />

      <CardHeader className="pb-4">
        <CardTitle className="text-lg">Financial Profile</CardTitle>
        <CardDescription>
          Help us understand your financial background. This is required for
          anti-money laundering regulations.
        </CardDescription>
      </CardHeader>

      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          {/* Employment Status */}
          <div className="space-y-2">
            <Label
              htmlFor="employment_status"
              className="text-sm font-medium"
            >
              Employment Status
            </Label>
            <Select
              value={employmentStatus}
              onValueChange={setEmploymentStatus}
            >
              <SelectTrigger
                id="employment_status"
                className={`h-11 ${errors.employment_status ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              >
                <SelectValue placeholder="Select your employment status" />
              </SelectTrigger>
              <SelectContent>
                {EMPLOYMENT_STATUSES.map((status) => (
                  <SelectItem key={status.value} value={status.value}>
                    {status.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.employment_status && (
              <p className="text-xs text-red-600">
                {errors.employment_status}
              </p>
            )}
          </div>

          {/* Annual Income Range */}
          <div className="space-y-2">
            <Label
              htmlFor="annual_income_range"
              className="text-sm font-medium"
            >
              Annual Income Range
            </Label>
            <Select
              value={annualIncomeRange}
              onValueChange={setAnnualIncomeRange}
            >
              <SelectTrigger
                id="annual_income_range"
                className={`h-11 ${errors.annual_income_range ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              >
                <SelectValue placeholder="Select your income range" />
              </SelectTrigger>
              <SelectContent>
                {INCOME_RANGES.map((range) => (
                  <SelectItem key={range.value} value={range.value}>
                    {range.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.annual_income_range && (
              <p className="text-xs text-red-600">
                {errors.annual_income_range}
              </p>
            )}
          </div>

          {/* Source of Funds */}
          <div className="space-y-2">
            <Label htmlFor="source_of_funds" className="text-sm font-medium">
              Source of Funds
            </Label>
            <Select value={sourceOfFunds} onValueChange={setSourceOfFunds}>
              <SelectTrigger
                id="source_of_funds"
                className={`h-11 ${errors.source_of_funds ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              >
                <SelectValue placeholder="Select your primary source of funds" />
              </SelectTrigger>
              <SelectContent>
                {SOURCE_OF_FUNDS.map((source) => (
                  <SelectItem key={source.value} value={source.value}>
                    {source.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.source_of_funds && (
              <p className="text-xs text-red-600">{errors.source_of_funds}</p>
            )}
          </div>

          {/* Investment Experience */}
          <div className="space-y-2">
            <Label
              htmlFor="investment_experience"
              className="text-sm font-medium"
            >
              Investment Experience
            </Label>
            <Select
              value={investmentExperience}
              onValueChange={setInvestmentExperience}
            >
              <SelectTrigger
                id="investment_experience"
                className={`h-11 ${errors.investment_experience ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              >
                <SelectValue placeholder="Select your experience level" />
              </SelectTrigger>
              <SelectContent>
                {INVESTMENT_EXPERIENCE.map((exp) => (
                  <SelectItem key={exp.value} value={exp.value}>
                    {exp.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.investment_experience && (
              <p className="text-xs text-red-600">
                {errors.investment_experience}
              </p>
            )}
          </div>
        </CardContent>

        <CardFooter className="flex justify-between pt-2 pb-6">
          <Button
            type="button"
            variant="outline"
            onClick={onBack}
            disabled={isSubmitting}
          >
            <ArrowLeftIcon className="mr-2 h-4 w-4" />
            Back
          </Button>
          <Button
            type="submit"
            disabled={isSubmitting}
            className="bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 text-white shadow-lg shadow-violet-500/25 group"
          >
            {isSubmitting ? (
              <>
                <LoaderIcon className="mr-2 h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                Continue
                <ArrowRightIcon className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
              </>
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
