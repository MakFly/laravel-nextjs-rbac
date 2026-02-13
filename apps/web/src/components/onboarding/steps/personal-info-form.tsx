'use client';

import { useState } from 'react';
import type { PersonalInfoData } from '@rbac/types';
import { personalInfoSchema } from '@/lib/validations/onboarding';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
import {
  ArrowRightIcon,
  LoaderIcon,
  PhoneIcon,
  CalendarIcon,
  MapPinIcon,
} from 'lucide-react';

const COUNTRIES = [
  { value: 'FR', label: 'France' },
  { value: 'DE', label: 'Germany' },
  { value: 'GB', label: 'United Kingdom' },
  { value: 'US', label: 'United States' },
  { value: 'CA', label: 'Canada' },
  { value: 'CH', label: 'Switzerland' },
  { value: 'BE', label: 'Belgium' },
  { value: 'LU', label: 'Luxembourg' },
  { value: 'NL', label: 'Netherlands' },
  { value: 'ES', label: 'Spain' },
  { value: 'IT', label: 'Italy' },
  { value: 'PT', label: 'Portugal' },
  { value: 'AT', label: 'Austria' },
  { value: 'IE', label: 'Ireland' },
  { value: 'SE', label: 'Sweden' },
  { value: 'NO', label: 'Norway' },
  { value: 'DK', label: 'Denmark' },
  { value: 'FI', label: 'Finland' },
  { value: 'JP', label: 'Japan' },
  { value: 'AU', label: 'Australia' },
  { value: 'SG', label: 'Singapore' },
  { value: 'HK', label: 'Hong Kong' },
] as const;

interface PersonalInfoFormProps {
  defaultValues?: PersonalInfoData;
  onSubmit: (data: PersonalInfoData) => void;
  isSubmitting: boolean;
}

export function PersonalInfoForm({
  defaultValues,
  onSubmit,
  isSubmitting,
}: PersonalInfoFormProps) {
  const [phone, setPhone] = useState(defaultValues?.phone ?? '');
  const [dateOfBirth, setDateOfBirth] = useState(
    defaultValues?.date_of_birth ?? ''
  );
  const [street, setStreet] = useState(defaultValues?.street ?? '');
  const [city, setCity] = useState(defaultValues?.city ?? '');
  const [postalCode, setPostalCode] = useState(
    defaultValues?.postal_code ?? ''
  );
  const [country, setCountry] = useState(defaultValues?.country ?? '');
  const [nationality, setNationality] = useState(
    defaultValues?.nationality ?? ''
  );
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    const data: PersonalInfoData = {
      phone,
      date_of_birth: dateOfBirth,
      street,
      city,
      postal_code: postalCode,
      country,
      nationality,
    };

    const result = personalInfoSchema.safeParse(data);

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
        <CardTitle className="text-lg">Personal Information</CardTitle>
        <CardDescription>
          Please provide your personal details. This information is required for
          identity verification.
        </CardDescription>
      </CardHeader>

      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          {/* Phone */}
          <div className="space-y-2">
            <Label htmlFor="phone" className="text-sm font-medium">
              Phone Number
            </Label>
            <div className="relative">
              <PhoneIcon className="absolute left-3 top-3 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input
                id="phone"
                type="tel"
                placeholder="+33 6 12 34 56 78"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className={`pl-10 h-11 ${errors.phone ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              />
            </div>
            {errors.phone && (
              <p className="text-xs text-red-600">{errors.phone}</p>
            )}
          </div>

          {/* Date of birth */}
          <div className="space-y-2">
            <Label htmlFor="date_of_birth" className="text-sm font-medium">
              Date of Birth
            </Label>
            <div className="relative">
              <CalendarIcon className="absolute left-3 top-3 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input
                id="date_of_birth"
                type="date"
                value={dateOfBirth}
                onChange={(e) => setDateOfBirth(e.target.value)}
                className={`pl-10 h-11 ${errors.date_of_birth ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              />
            </div>
            {errors.date_of_birth && (
              <p className="text-xs text-red-600">{errors.date_of_birth}</p>
            )}
          </div>

          {/* Street */}
          <div className="space-y-2">
            <Label htmlFor="street" className="text-sm font-medium">
              Street Address
            </Label>
            <div className="relative">
              <MapPinIcon className="absolute left-3 top-3 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input
                id="street"
                type="text"
                placeholder="123 Main Street"
                value={street}
                onChange={(e) => setStreet(e.target.value)}
                className={`pl-10 h-11 ${errors.street ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              />
            </div>
            {errors.street && (
              <p className="text-xs text-red-600">{errors.street}</p>
            )}
          </div>

          {/* City + Postal Code */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="city" className="text-sm font-medium">
                City
              </Label>
              <Input
                id="city"
                type="text"
                placeholder="Paris"
                value={city}
                onChange={(e) => setCity(e.target.value)}
                className={`h-11 ${errors.city ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              />
              {errors.city && (
                <p className="text-xs text-red-600">{errors.city}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="postal_code" className="text-sm font-medium">
                Postal Code
              </Label>
              <Input
                id="postal_code"
                type="text"
                placeholder="75001"
                value={postalCode}
                onChange={(e) => setPostalCode(e.target.value)}
                className={`h-11 ${errors.postal_code ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              />
              {errors.postal_code && (
                <p className="text-xs text-red-600">{errors.postal_code}</p>
              )}
            </div>
          </div>

          {/* Country */}
          <div className="space-y-2">
            <Label htmlFor="country" className="text-sm font-medium">
              Country
            </Label>
            <Select value={country} onValueChange={setCountry}>
              <SelectTrigger
                id="country"
                className={`h-11 ${errors.country ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              >
                <SelectValue placeholder="Select a country" />
              </SelectTrigger>
              <SelectContent>
                {COUNTRIES.map((c) => (
                  <SelectItem key={c.value} value={c.value}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.country && (
              <p className="text-xs text-red-600">{errors.country}</p>
            )}
          </div>

          {/* Nationality */}
          <div className="space-y-2">
            <Label htmlFor="nationality" className="text-sm font-medium">
              Nationality
            </Label>
            <Select value={nationality} onValueChange={setNationality}>
              <SelectTrigger
                id="nationality"
                className={`h-11 ${errors.nationality ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              >
                <SelectValue placeholder="Select your nationality" />
              </SelectTrigger>
              <SelectContent>
                {COUNTRIES.map((c) => (
                  <SelectItem key={c.value} value={c.value}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.nationality && (
              <p className="text-xs text-red-600">{errors.nationality}</p>
            )}
          </div>
        </CardContent>

        <CardFooter className="flex justify-end pt-2 pb-6">
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
