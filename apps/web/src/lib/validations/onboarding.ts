import { z } from 'zod';

/**
 * Step 1 - Personal Information
 */
export const personalInfoSchema = z.object({
  phone: z
    .string()
    .min(1, 'Phone number is required')
    .min(8, 'Phone number must be at least 8 characters'),
  date_of_birth: z.string().min(1, 'Date of birth is required'),
  street: z.string().min(1, 'Street address is required'),
  city: z.string().min(1, 'City is required'),
  postal_code: z.string().min(1, 'Postal code is required'),
  country: z.string().min(1, 'Country is required'),
  nationality: z.string().min(1, 'Nationality is required'),
});

/**
 * Step 2 - Identity Verification
 */
export const identityVerificationSchema = z.object({
  id_document_type: z.enum(['passport', 'national_id', 'drivers_license'], {
    message: 'Please select a document type',
  }),
  id_document_number: z
    .string()
    .min(1, 'Document number is required')
    .min(4, 'Document number must be at least 4 characters'),
  id_expiry_date: z.string().min(1, 'Expiry date is required'),
});

/**
 * Step 3 - Financial Profile
 */
export const financialProfileSchema = z.object({
  employment_status: z.string().min(1, 'Employment status is required'),
  annual_income_range: z.string().min(1, 'Annual income range is required'),
  source_of_funds: z.string().min(1, 'Source of funds is required'),
  investment_experience: z
    .string()
    .min(1, 'Investment experience is required'),
});

/**
 * Step 4 - Operation Setup
 */
export const operationSetupSchema = z.object({
  account_type: z.enum(['banking', 'crypto', 'both'], {
    message: 'Please select an account type',
  }),
  preferred_currency: z.string().optional(),
  iban: z.string().optional(),
  preferred_cryptocurrency: z.string().optional(),
  wallet_address: z.string().optional(),
  initial_transaction_amount: z.enum(
    ['under_1k', '1k_10k', '10k_50k', '50k_100k', 'over_100k'],
    {
      message: 'Please select a transaction amount range',
    }
  ),
});

export type PersonalInfoFormData = z.infer<typeof personalInfoSchema>;
export type IdentityVerificationFormData = z.infer<
  typeof identityVerificationSchema
>;
export type FinancialProfileFormData = z.infer<typeof financialProfileSchema>;
export type OperationSetupFormData = z.infer<typeof operationSetupSchema>;
