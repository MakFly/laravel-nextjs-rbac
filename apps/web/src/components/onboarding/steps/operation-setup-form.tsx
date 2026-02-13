'use client';

import { useState } from 'react';
import type { OperationSetupData } from '@rbac/types';
import { operationSetupSchema } from '@/lib/validations/onboarding';
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
  CheckIcon,
  LoaderIcon,
  BanknoteIcon,
  BitcoinIcon,
  LayersIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const CURRENCIES = [
  { value: 'EUR', label: 'EUR - Euro' },
  { value: 'USD', label: 'USD - US Dollar' },
  { value: 'GBP', label: 'GBP - British Pound' },
  { value: 'CHF', label: 'CHF - Swiss Franc' },
  { value: 'CAD', label: 'CAD - Canadian Dollar' },
  { value: 'JPY', label: 'JPY - Japanese Yen' },
  { value: 'AUD', label: 'AUD - Australian Dollar' },
] as const;

const CRYPTOCURRENCIES = [
  { value: 'BTC', label: 'BTC - Bitcoin' },
  { value: 'ETH', label: 'ETH - Ethereum' },
  { value: 'USDT', label: 'USDT - Tether' },
  { value: 'USDC', label: 'USDC - USD Coin' },
  { value: 'SOL', label: 'SOL - Solana' },
  { value: 'XRP', label: 'XRP - Ripple' },
] as const;

const TRANSACTION_AMOUNTS = [
  { value: 'under_1k', label: 'Under $1,000' },
  { value: '1k_10k', label: '$1,000 - $10,000' },
  { value: '10k_50k', label: '$10,000 - $50,000' },
  { value: '50k_100k', label: '$50,000 - $100,000' },
  { value: 'over_100k', label: 'Over $100,000' },
] as const;

const ACCOUNT_TYPES = [
  {
    value: 'banking' as const,
    label: 'Banking',
    description: 'Traditional bank account with IBAN',
    icon: BanknoteIcon,
  },
  {
    value: 'crypto' as const,
    label: 'Crypto',
    description: 'Cryptocurrency wallet operations',
    icon: BitcoinIcon,
  },
  {
    value: 'both' as const,
    label: 'Both',
    description: 'Banking and crypto combined',
    icon: LayersIcon,
  },
] as const;

interface OperationSetupFormProps {
  defaultValues?: OperationSetupData;
  onSubmit: (data: OperationSetupData) => void;
  onBack: () => void;
  isSubmitting: boolean;
}

export function OperationSetupForm({
  defaultValues,
  onSubmit,
  onBack,
  isSubmitting,
}: OperationSetupFormProps) {
  const [accountType, setAccountType] = useState<string>(
    defaultValues?.account_type ?? ''
  );
  const [preferredCurrency, setPreferredCurrency] = useState(
    defaultValues?.preferred_currency ?? ''
  );
  const [iban, setIban] = useState(defaultValues?.iban ?? '');
  const [preferredCryptocurrency, setPreferredCryptocurrency] = useState(
    defaultValues?.preferred_cryptocurrency ?? ''
  );
  const [walletAddress, setWalletAddress] = useState(
    defaultValues?.wallet_address ?? ''
  );
  const [transactionAmount, setTransactionAmount] = useState(
    defaultValues?.initial_transaction_amount ?? ''
  );
  const [errors, setErrors] = useState<Record<string, string>>({});

  const showBanking = accountType === 'banking' || accountType === 'both';
  const showCrypto = accountType === 'crypto' || accountType === 'both';

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    const data: Record<string, unknown> = {
      account_type: accountType,
      initial_transaction_amount: transactionAmount,
    };

    // Only include relevant fields based on account type
    if (showBanking) {
      data.preferred_currency = preferredCurrency || undefined;
      data.iban = iban || undefined;
    }
    if (showCrypto) {
      data.preferred_cryptocurrency = preferredCryptocurrency || undefined;
      data.wallet_address = walletAddress || undefined;
    }

    const result = operationSetupSchema.safeParse(data);

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

    onSubmit(result.data as OperationSetupData);
  };

  return (
    <Card className="relative overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-violet-600 via-indigo-600 to-violet-600" />

      <CardHeader className="pb-4">
        <CardTitle className="text-lg">Operation Setup</CardTitle>
        <CardDescription>
          Configure your preferred account type and transaction settings. This is
          the final step!
        </CardDescription>
      </CardHeader>

      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-6">
          {/* Account Type Selection */}
          <div className="space-y-3">
            <Label className="text-sm font-medium">Account Type</Label>
            <div className="grid grid-cols-3 gap-3">
              {ACCOUNT_TYPES.map((type) => {
                const Icon = type.icon;
                const isSelected = accountType === type.value;

                return (
                  <button
                    key={type.value}
                    type="button"
                    onClick={() => setAccountType(type.value)}
                    className={cn(
                      'relative flex flex-col items-center gap-2 rounded-lg border-2 p-4 text-center transition-all hover:border-violet-300 hover:bg-violet-50/50',
                      isSelected
                        ? 'border-violet-600 bg-violet-50 shadow-sm'
                        : 'border-muted-foreground/15'
                    )}
                  >
                    {isSelected && (
                      <div className="absolute top-2 right-2">
                        <CheckIcon className="h-4 w-4 text-violet-600" />
                      </div>
                    )}
                    <Icon
                      className={cn(
                        'h-6 w-6',
                        isSelected
                          ? 'text-violet-600'
                          : 'text-muted-foreground'
                      )}
                    />
                    <span
                      className={cn(
                        'text-sm font-medium',
                        isSelected ? 'text-violet-700' : ''
                      )}
                    >
                      {type.label}
                    </span>
                    <span className="text-xs text-muted-foreground hidden sm:block">
                      {type.description}
                    </span>
                  </button>
                );
              })}
            </div>
            {errors.account_type && (
              <p className="text-xs text-red-600">{errors.account_type}</p>
            )}
          </div>

          {/* Banking Fields */}
          {showBanking && (
            <div className="space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
              <div className="flex items-center gap-2 text-sm font-medium text-violet-700">
                <BanknoteIcon className="h-4 w-4" />
                Banking Details
              </div>

              <div className="space-y-2">
                <Label
                  htmlFor="preferred_currency"
                  className="text-sm font-medium"
                >
                  Preferred Currency
                </Label>
                <Select
                  value={preferredCurrency}
                  onValueChange={setPreferredCurrency}
                >
                  <SelectTrigger id="preferred_currency" className="h-11">
                    <SelectValue placeholder="Select a currency" />
                  </SelectTrigger>
                  <SelectContent>
                    {CURRENCIES.map((c) => (
                      <SelectItem key={c.value} value={c.value}>
                        {c.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="iban" className="text-sm font-medium">
                  IBAN (optional)
                </Label>
                <Input
                  id="iban"
                  type="text"
                  placeholder="FR76 1234 5678 9012 3456 7890 123"
                  value={iban}
                  onChange={(e) => setIban(e.target.value)}
                  className="h-11 font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">
                  You can add your IBAN later if you do not have it right now.
                </p>
              </div>
            </div>
          )}

          {/* Crypto Fields */}
          {showCrypto && (
            <div className="space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
              <div className="flex items-center gap-2 text-sm font-medium text-violet-700">
                <BitcoinIcon className="h-4 w-4" />
                Crypto Details
              </div>

              <div className="space-y-2">
                <Label
                  htmlFor="preferred_cryptocurrency"
                  className="text-sm font-medium"
                >
                  Preferred Cryptocurrency
                </Label>
                <Select
                  value={preferredCryptocurrency}
                  onValueChange={setPreferredCryptocurrency}
                >
                  <SelectTrigger
                    id="preferred_cryptocurrency"
                    className="h-11"
                  >
                    <SelectValue placeholder="Select a cryptocurrency" />
                  </SelectTrigger>
                  <SelectContent>
                    {CRYPTOCURRENCIES.map((c) => (
                      <SelectItem key={c.value} value={c.value}>
                        {c.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label
                  htmlFor="wallet_address"
                  className="text-sm font-medium"
                >
                  Wallet Address (optional)
                </Label>
                <Input
                  id="wallet_address"
                  type="text"
                  placeholder="0x..."
                  value={walletAddress}
                  onChange={(e) => setWalletAddress(e.target.value)}
                  className="h-11 font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">
                  You can add your wallet address later if you prefer.
                </p>
              </div>
            </div>
          )}

          {/* Transaction Amount */}
          <div className="space-y-2">
            <Label
              htmlFor="initial_transaction_amount"
              className="text-sm font-medium"
            >
              Expected Initial Transaction Amount
            </Label>
            <Select
              value={transactionAmount}
              onValueChange={setTransactionAmount}
            >
              <SelectTrigger
                id="initial_transaction_amount"
                className={`h-11 ${errors.initial_transaction_amount ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
              >
                <SelectValue placeholder="Select an amount range" />
              </SelectTrigger>
              <SelectContent>
                {TRANSACTION_AMOUNTS.map((amount) => (
                  <SelectItem key={amount.value} value={amount.value}>
                    {amount.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.initial_transaction_amount && (
              <p className="text-xs text-red-600">
                {errors.initial_transaction_amount}
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
                Completing...
              </>
            ) : (
              <>
                Complete Onboarding
                <CheckIcon className="ml-2 h-4 w-4" />
              </>
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
