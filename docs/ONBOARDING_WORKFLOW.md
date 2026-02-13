# Onboarding KYC & Operations - Workflow

## Overview

A 4-step onboarding wizard (KYC + first operation setup) with draft persistence in database, implemented across both frontends (Next.js + Vue.js).

**Key decisions:**
- Drafts stored in **DB only** (no Redis dual-layer) for simplicity and consistency
- Redis used for **sessions, cache, and queues** only
- Encrypted fields for sensitive data (phone, ID number, IBAN, wallet address)

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        INFRASTRUCTURE                          │
├────────────────────────────────────────────────────────────────┤
│  Redis (docker: rbac_redis:6379)                               │
│  ├── Sessions  (SESSION_DRIVER=redis)                          │
│  ├── Cache     (CACHE_STORE=redis)                             │
│  └── Queues    (QUEUE_CONNECTION=redis)                        │
│                                                                │
│  SQLite / PostgreSQL                                           │
│  ├── users              (onboarding_status, onboarding_step)   │
│  ├── onboarding_drafts  (JSON data, per-user)                  │
│  ├── kyc_profiles       (encrypted fields, audit trail)        │
│  └── user_operations    (encrypted fields)                     │
└────────────────────────────────────────────────────────────────┘
```

---

## Flow Diagram

```
 REGISTER
 ════════
 /register (Vue.js)
 /auth/register (Next.js)
         │
         ▼
 ┌─────────────────────────────┐
 │  POST /api/.../auth/register │
 │                              │
 │  Creates User with:          │
 │  onboarding_status = pending │
 │  onboarding_step   = 0       │
 └──────────────┬──────────────┘
                │
       redirect → /onboarding
                │
                ▼
 ONBOARDING WIZARD (4 steps)
 ═══════════════════════════

 ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
 │  Step 1  │───▶│  Step 2  │───▶│  Step 3  │───▶│  Step 4  │
 │ Personal │    │ Identity │    │Financial │    │Operation │
 │   Info   │    │  Verif.  │    │ Profile  │    │  Setup   │
 └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
      │               │               │               │
      ▼               ▼               ▼               ▼
  POST /step/1    POST /step/2    POST /step/3    POST /step/4
      │               │               │               │
      └───────────────┴───────────────┴───────────────┘
                              │
                    ┌─────────▼──────────┐
                    │ onboarding_drafts  │
                    │ (JSON merge per    │
                    │  step, persisted   │
                    │  in DB)            │
                    │                    │
                    │ users.onboarding   │
                    │ _step = N          │
                    │ _status =          │
                    │ 'in_progress'      │
                    └─────────┬──────────┘
                              │
            ┌─────────────────┤
            │   RESUME FLOW   │
            │                 │
            │  User logs out  │
            │  → logs back in │
            │  → GET /draft   │
            │  → resumes at   │
            │    saved step   │
            │    with data    │
            └─────────────────┘
                              │
                    POST /onboarding/complete
                              │
                              ▼
              ┌───────────────────────────────┐
              │  OnboardingService.finalize() │
              │                               │
              │  DB Transaction:              │
              │  1. Create kyc_profiles       │
              │     (phone, ID# encrypted)    │
              │  2. Create user_operations    │
              │     (IBAN, wallet encrypted)  │
              │  3. Set user status =         │
              │     'completed', step = 4     │
              │  4. Delete draft              │
              └──────────────┬────────────────┘
                             │
                    redirect → /dashboard
                             │
                             ▼
              ┌───────────────────────────────┐
              │          DASHBOARD            │
              │  Protected by middleware       │
              │  'onboarding.complete'         │
              └───────────────────────────────┘
```

---

## Step Details

| Step | Name | Fields | Validation |
|------|------|--------|------------|
| 1 | Personal Info | phone, date_of_birth, street, city, postal_code, country (ISO 3166-1), nationality (ISO 3166-1) | All required, DOB before today |
| 2 | Identity Verification | id_document_type (passport/national_id/drivers_license), id_document_number, id_expiry_date | All required, expiry after today |
| 3 | Financial Profile | employment_status, annual_income_range, source_of_funds, investment_experience | All required, enum-validated |
| 4 | Operation Setup | account_type (banking/crypto/both), preferred_currency, iban, preferred_cryptocurrency, wallet_address, initial_transaction_amount | account_type + amount required, others conditional |

---

## Route Guards

### Backend (Laravel Middleware)

```
Accessible WITHOUT onboarding:
  /onboarding/*     (status, draft, step/{n}, complete)
  /me               (user profile)
  /auth/logout      (logout)

Requires onboarding.complete middleware:
  /users            → 403 + { redirect: '/onboarding', current_step }
  /admin/*          → 403
  /posts            → 403
```

### Next.js (SSR Guards)

```
/dashboard/layout.tsx (server):
  if user.onboarding_status !== 'completed' → redirect /onboarding

/onboarding/layout.tsx (server):
  if no session → redirect /auth/login
  if user.onboarding_status === 'completed' → redirect /dashboard

/auth/register/page.tsx (client):
  after register → router.push('/onboarding')
```

### Vue.js (Router Guards)

```
router.beforeEach:
  if authenticated + needsOnboarding + dest !== /onboarding
    → redirect /onboarding

  if on /onboarding + !needsOnboarding
    → redirect /dashboard

  if on /register + authenticated
    → redirect /dashboard

RegisterForm.vue:
  after register → router.push('/onboarding')
```

---

## Existing Users

Migration `set_existing_users_onboarding_completed` automatically sets:
- `onboarding_status = 'completed'`
- `onboarding_step = 4`

for all pre-existing users (seeders: admin@, mod@, user@, etc.). They skip onboarding entirely.

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/onboarding/status` | Required | Returns `{ onboarding_status, onboarding_step }` |
| GET | `/onboarding/draft` | Required | Returns saved draft or `null` |
| POST | `/onboarding/step/{1-4}` | Required | Validates + saves step data to draft |
| POST | `/onboarding/complete` | Required | Finalizes: persists to kyc_profiles + user_operations, deletes draft |

Available on both prefixes:
- `/api/v1/onboarding/*` (BFF + HMAC for Next.js)
- `/api/spa/onboarding/*` (Sanctum session for Vue.js)

---

## Database Schema

### users (modified)

| Column | Type | Default |
|--------|------|---------|
| onboarding_status | varchar(20) | 'pending' |
| onboarding_step | tinyint | 0 |

Index on `onboarding_status`.

### onboarding_drafts

| Column | Type | Notes |
|--------|------|-------|
| id | bigint PK | |
| user_id | FK unique | One draft per user |
| data | json | `{ step1: {...}, step2: {...}, ... }` |
| created_at, updated_at | timestamps | |

### kyc_profiles

| Column | Type | Notes |
|--------|------|-------|
| user_id | FK unique | |
| phone | string(20) | **encrypted** |
| date_of_birth | date | |
| street, city, postal_code | string | |
| country, nationality | string(2) | ISO 3166-1 alpha-2 |
| id_document_type | string(30) | |
| id_document_number | string(50) | **encrypted** |
| id_expiry_date | date | |
| employment_status | string(30) | |
| annual_income_range | string(30) | |
| source_of_funds | string(30) | |
| investment_experience | string(20) | |
| kyc_status | string(20) | pending / approved / rejected |
| submitted_at | timestamp | Audit |
| reviewed_at | timestamp | Audit |
| reviewed_by | FK nullable | Audit |
| rejection_reason | text | Audit |
| ip_address | string(45) | Security |
| user_agent | string | Security |

### user_operations

| Column | Type | Notes |
|--------|------|-------|
| user_id | FK unique | |
| account_type | string(20) | banking / crypto / both |
| preferred_currency | string(3) | nullable |
| iban | string(34) | nullable, **encrypted** |
| preferred_cryptocurrency | string(10) | nullable |
| wallet_address | string | nullable, **encrypted** |
| initial_transaction_amount | string(20) | enum values |

---

## Redis Configuration

```env
# apps/api/.env
CACHE_STORE=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
REDIS_CLIENT=predis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
```

Requires Docker container:
```bash
docker compose up -d redis    # Start Redis
docker exec rbac_redis redis-cli ping   # Verify → PONG
```

---

## File Map

### New Files (~33)

**Laravel (15):**
- `database/migrations/2026_02_13_000001_add_onboarding_fields_to_users_table.php`
- `database/migrations/2026_02_13_000002_create_onboarding_drafts_table.php`
- `database/migrations/2026_02_13_000003_create_kyc_profiles_table.php`
- `database/migrations/2026_02_13_000004_create_user_operations_table.php`
- `database/migrations/2026_02_13_000005_set_existing_users_onboarding_completed.php`
- `app/Models/KycProfile.php`
- `app/Models/UserOperation.php`
- `app/Models/OnboardingDraft.php`
- `app/Services/OnboardingService.php`
- `app/Http/Controllers/OnboardingController.php`
- `app/Http/Middleware/EnsureOnboardingComplete.php`
- `app/Http/Requests/Onboarding/SavePersonalInfoRequest.php`
- `app/Http/Requests/Onboarding/SaveIdentityVerificationRequest.php`
- `app/Http/Requests/Onboarding/SaveFinancialProfileRequest.php`
- `app/Http/Requests/Onboarding/SaveOperationSetupRequest.php`

**Next.js (10):**
- `src/lib/api/onboarding.ts`
- `src/lib/validations/onboarding.ts`
- `src/app/onboarding/layout.tsx`
- `src/app/onboarding/page.tsx`
- `src/components/onboarding/onboarding-wizard.tsx`
- `src/components/onboarding/stepper.tsx`
- `src/components/onboarding/steps/personal-info-form.tsx`
- `src/components/onboarding/steps/identity-verification-form.tsx`
- `src/components/onboarding/steps/financial-profile-form.tsx`
- `src/components/onboarding/steps/operation-setup-form.tsx`

**Vue.js (8):**
- `src/lib/api/onboarding.ts`
- `src/composables/useOnboarding.ts`
- `src/views/OnboardingPage.vue`
- `src/views/RegisterPage.vue`
- `src/components/RegisterForm.vue`
- `src/components/onboarding/OnboardingStepper.vue`
- `src/components/onboarding/PersonalInfoForm.vue`
- `src/components/onboarding/IdentityVerificationForm.vue`
- `src/components/onboarding/FinancialProfileForm.vue`
- `src/components/onboarding/OperationSetupForm.vue`

### Modified Files (~12)

- `apps/api/.env` - Redis drivers
- `apps/api/app/Models/User.php` - Relations + fillable + helper
- `apps/api/app/Http/Controllers/Auth/AuthController.php` - formatUser()
- `apps/api/bootstrap/app.php` - Middleware alias
- `apps/api/routes/api.php` - Onboarding routes + middleware wrapping
- `packages/types/src/index.ts` - Onboarding types
- `apps/web/src/app/dashboard/layout.tsx` - Onboarding guard
- `apps/web/src/app/auth/register/page.tsx` - Redirect to /onboarding
- `apps/web/src/stores/auth-store.ts` - needsOnboarding()
- `apps/web-vuejs/src/router/index.ts` - Register route + onboarding guards
- `apps/web-vuejs/src/stores/auth.ts` - register() + needsOnboarding + refreshUser()
- `apps/web-vuejs/src/components/LoginForm.vue` - Sign up link
