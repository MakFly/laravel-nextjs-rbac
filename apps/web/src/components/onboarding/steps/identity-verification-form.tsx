'use client';

import { useState } from 'react';
import type { IdentityVerificationData } from '@rbac/types';
import { identityVerificationSchema } from '@/lib/validations/onboarding';
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
  ArrowLeftIcon,
  ArrowRightIcon,
  LoaderIcon,
  FingerprintIcon,
  CalendarIcon,
  HashIcon,
} from 'lucide-react';

const DOCUMENT_TYPES = [
  { value: 'passport', label: 'Passport' },
  { value: 'national_id', label: 'National ID Card' },
  { value: 'drivers_license', label: "Driver's License" },
] as const;

interface IdentityVerificationFormProps {
  defaultValues?: IdentityVerificationData;
  onSubmit: (data: IdentityVerificationData) => void;
  onBack: () => void;
  isSubmitting: boolean;
}

export function IdentityVerificationForm({
  defaultValues,
  onSubmit,
  onBack,
  isSubmitting,
}: IdentityVerificationFormProps) {
  const [documentType, setDocumentType] = useState(
    defaultValues?.id_document_type ?? ''
  );
  const [documentNumber, setDocumentNumber] = useState(
    defaultValues?.id_document_number ?? ''
  );
  const [expiryDate, setExpiryDate] = useState(
    defaultValues?.id_expiry_date ?? ''
  );
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    const data = {
      id_document_type: documentType,
      id_document_number: documentNumber,
      id_expiry_date: expiryDate,
    };

    const result = identityVerificationSchema.safeParse(data);

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
        <CardTitle className="text-lg">Identity Verification</CardTitle>
        <CardDescription>
          Provide your official identity document details. This is required for
          KYC compliance.
        </CardDescription>
      </CardHeader>

      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          {/* Document Type */}
          <div className="space-y-2">
            <Label htmlFor="id_document_type" className="text-sm font-medium">
              Document Type
            </Label>
            <div className="relative">
              <Select value={documentType} onValueChange={setDocumentType}>
                <SelectTrigger
                  id="id_document_type"
                  className={`h-11 ${errors.id_document_type ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
                >
                  <div className="flex items-center gap-2">
                    <FingerprintIcon className="h-4 w-4 text-muted-foreground" />
                    <SelectValue placeholder="Select document type" />
                  </div>
                </SelectTrigger>
                <SelectContent>
                  {DOCUMENT_TYPES.map((doc) => (
                    <SelectItem key={doc.value} value={doc.value}>
                      {doc.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {errors.id_document_type && (
              <p className="text-xs text-red-600">{errors.id_document_type}</p>
            )}
          </div>

          {/* Document Number */}
          <div className="space-y-2">
            <Label
              htmlFor="id_document_number"
              className="text-sm font-medium"
            >
              Document Number
            </Label>
            <div className="relative">
              <HashIcon className="absolute left-3 top-3 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input
                id="id_document_number"
                type="text"
                placeholder="AB1234567"
                value={documentNumber}
                onChange={(e) => setDocumentNumber(e.target.value)}
                className={`pl-10 h-11 ${errors.id_document_number ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              />
            </div>
            {errors.id_document_number && (
              <p className="text-xs text-red-600">
                {errors.id_document_number}
              </p>
            )}
          </div>

          {/* Expiry Date */}
          <div className="space-y-2">
            <Label htmlFor="id_expiry_date" className="text-sm font-medium">
              Expiry Date
            </Label>
            <div className="relative">
              <CalendarIcon className="absolute left-3 top-3 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input
                id="id_expiry_date"
                type="date"
                value={expiryDate}
                onChange={(e) => setExpiryDate(e.target.value)}
                className={`pl-10 h-11 ${errors.id_expiry_date ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              />
            </div>
            {errors.id_expiry_date && (
              <p className="text-xs text-red-600">{errors.id_expiry_date}</p>
            )}
          </div>

          {/* Info banner */}
          <div className="p-3 rounded-lg bg-violet-50 dark:bg-violet-950/20 border border-violet-100 dark:border-violet-900">
            <p className="text-xs text-violet-700 dark:text-violet-300">
              Your document details are encrypted and stored securely. We only
              use this information for identity verification purposes.
            </p>
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
