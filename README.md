# Laravel + Next.js RBAC

A secure, production-ready RBAC (Role-Based Access Control) system using a **BFF (Backend For Frontend)** architecture with Laravel API and Next.js frontend.

## Architecture

This project implements a BFF pattern where Next.js acts as an intermediary between the browser and Laravel API:

```
┌─────────┐       ┌─────────────┐       ┌────────────┐
│ Browser │──────▶│  Next.js    │──────▶│  Laravel   │
│         │◀──────│  (BFF)      │◀──────│    API     │
└─────────┘       └─────────────┘       └────────────┘
                          │
                          ├─ HMAC Signing
                          ├─ Cookie Management
                          └─ Route Proxying
```

### Key Benefits

- **Security**: HMAC-signed requests prevent request forgery between BFF and API
- **No CORS Issues**: Server-to-server communication eliminates browser CORS restrictions
- **HttpOnly Cookies**: Authentication tokens stored securely, inaccessible to XSS attacks
- **Type Safety**: Full TypeScript support across the stack
- **Monorepo**: Unified development experience with Turbo

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Monorepo** | Turbo + Bun |
| **Frontend** | Next.js 15 (App Router) + React 19 + TypeScript |
| **Backend** | Laravel 11 + Sanctum |
| **UI** | Radix UI + Tailwind CSS + Lucide React |
| **Security** | HMAC-SHA256 signing |

## Project Structure

```
laravel-nextjs-rbac/
├── apps/
│   ├── web/                          # Next.js BFF (port 3001)
│   │   ├── src/
│   │   │   ├── app/
│   │   │   │   ├── api/v1/[...path]/ # BFF Proxy Route Handler
│   │   │   │   └── (routes)/         # Frontend pages
│   │   │   └── lib/
│   │   │       ├── api/
│   │   │       │   └── auth.ts       # Server Actions
│   │   │       └── security/
│   │   │           └── hmac.ts       # HMAC signing logic
│   │   └── package.json
│   └── api/                          # Laravel API (port 8000)
│       ├── app/
│       │   └── Http/
│       │       └── Middleware/
│       │           └── ValidateBffSignature.php
│       └── bootstrap/app.php
├── package.json                      # Monorepo root
├── turbo.json                        # Turbo configuration
└── README.md
```

## How the BFF Works

### Request Flow

Every request from the browser goes through the BFF proxy at `/api/v1/[...path]/route.ts`:

```
1. Browser → /api/v1/auth/login
              ↓
2. Next.js BFF Proxy validates request
              ↓
3. Generates HMAC signature (X-BFF-Signature)
              ↓
4. Forwards to Laravel API with auth token from cookie
              ↓
5. Laravel validates HMAC signature
              ↓
6. Returns response through BFF to browser
```

### HMAC Signing

The BFF and Laravel share a secret key used to sign requests:

**Signature Payload:**
```
TIMESTAMP:METHOD:PATH:BODY_HASH
```

**Headers sent to Laravel:**
- `X-BFF-Id`: BFF identifier
- `X-BFF-Timestamp`: Unix timestamp in seconds
- `X-BFF-Signature`: HMAC-SHA256 signature

**Why HMAC?**
- Prevents request forgery: only someone with the secret can generate valid signatures
- Ensures request integrity: any modification invalidates the signature
- Timestamp prevents replay attacks

### Cookie Authentication

Authentication uses **HttpOnly cookies** for maximum security:

**Login Flow:**
```
1. User submits credentials → Server Action
2. BFF forwards to Laravel /auth/login
3. Laravel validates and returns access_token
4. BFF stores token in HttpOnly cookie (auth_token)
5. Subsequent requests include cookie automatically
```

**Cookie Attributes:**
- `httpOnly: true` - Inaccessible to JavaScript (XSS protection)
- `secure: true` (production) - Only sent over HTTPS
- `sameSite: 'lax'` - CSRF protection
- `maxAge: 15 days` - Persistent session

**Critical Rule**: When making fetch requests from Server Actions, **NEVER** use `credentials: 'include'`. This is ignored server-side. Always pass cookies manually:

```typescript
'use server';

// ❌ WRONG - credentials: 'include' is ignored server-side
const response = await fetch(url, { credentials: 'include' });

// ✅ CORRECT - pass cookie manually in headers
const cookieStore = await cookies();
const authToken = cookieStore.get('auth_token');
const response = await fetch(url, {
  headers: { Cookie: `auth_token=${authToken?.value}` }
});
```

## Security Features

### 1. Path Validation
The BFF proxy validates all path segments to prevent SSRF and path traversal attacks:

```typescript
const VALID_PATH_SEGMENT = /^[a-zA-Z0-9_-]+$/;
```

### 2. Public Routes
Certain routes don't require authentication:
- `/api/v1/auth/login`
- `/api/v1/auth/register`
- `/api/v1/auth/providers`

### 3. Host Verification
The BFF verifies that all proxied requests go to the configured Laravel API host.

### 4. Request Timeout
All proxied requests have a 30-second timeout to prevent hanging.

## Getting Started

### Prerequisites

- **Node.js** 18+
- **PHP** 8.2+
- **Composer**
- **Bun** (package manager)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd laravel-nextjs-rbac
   ```

2. **Install dependencies:**
   ```bash
   bun install
   cd apps/api && composer install
   ```

3. **Configure environment variables:**

   **Next.js BFF** (`.env.local`):
   ```env
   NEXT_PUBLIC_APP_URL=http://localhost:3001
   LARAVEL_API_URL=http://localhost:8000

   # HMAC Configuration (must match Laravel)
   BFF_HMAC_SECRET=your-secret-key-here
   BFF_ID=nextjs-bff-prod
   ```

   **Laravel API** (`.env`):
   ```env
   APP_URL=http://localhost:8000
   SANCTUM_STATEFUL_DOMAINS=localhost:3001

   # BFF Configuration (must match Next.js)
   BFF_ID=nextjs-bff-prod
   BFF_SECRET=your-secret-key-here
   ```

4. **Generate Laravel app key:**
   ```bash
   cd apps/api
   php artisan key:generate
   ```

5. **Run database migrations:**
   ```bash
   php artisan migrate
   ```

### Development

Run both applications in development mode:

```bash
# Terminal 1 - Next.js BFF
bun run --filter @rbac/web dev

# Terminal 2 - Laravel API
cd apps/api && php artisan serve
```

Access the application at:
- **Frontend**: http://localhost:3001
- **API**: http://localhost:8000

### Build for Production

```bash
# Build all packages
bun run build

# Build specific app
bun run --filter @rbac/web build
```

## API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Login with email/password |
| `/api/v1/auth/register` | POST | Register new user |
| `/api/v1/auth/logout` | POST | Logout user |
| `/api/v1/auth/me` | GET | Get current user |
| `/api/v1/auth/providers` | GET | List OAuth providers |

### Example Request

```typescript
// Using Server Actions
import { login } from '@/lib/api/auth';

async function handleLogin(formData: FormData) {
  const result = await login(formData);
  if (result.error) {
    // Handle error
  }
  // Success - cookie is set automatically
}
```

## Middleware

### Laravel BFF Validation

The Laravel API validates all incoming BFF requests via middleware:

```php
// apps/api/app/Http/Middleware/ValidateBffSignature.php
class ValidateBffSignature
{
    public function handle(Request $request, Closure $next)
    {
        // 1. Extract BFF headers
        // 2. Reconstruct signature payload
        // 3. Verify HMAC signature
        // 4. Check timestamp (replay protection)
    }
}
```

## Troubleshooting

### HMAC Signature Mismatch

**Symptom**: Laravel returns 401/403 with "Invalid signature"

**Solutions**:
1. Verify `BFF_HMAC_SECRET` matches `BFF_SECRET` exactly
2. Check system time sync (timestamp validation)
3. Ensure request body is JSON with sorted keys

### Cookies Not Being Sent

**Symptom**: Authenticated requests return 401

**Solutions**:
1. Check that `credentials: 'include'` is NOT used in Server Actions
2. Verify cookie is set with `httpOnly: true`
3. Check `sameSite` attribute matches domain configuration
4. Ensure `SANCTUM_STATEFUL_DOMAINS` includes BFF domain

### CORS Issues

**Symptom**: Browser blocks requests with CORS errors

**Solutions**:
- Should not occur with BFF architecture (server-to-server)
- If seeing CORS, verify request is going through `/api/v1/` proxy

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `bun test`
2. Code follows existing patterns
3. Security best practices are maintained
4. HMAC signing is never bypassed

## License

MIT License - see LICENSE file for details

## Additional Resources

- [Next.js App Router Documentation](https://nextjs.org/docs/app)
- [Laravel Sanctum Documentation](https://laravel.com/docs/sanctum)
- [HMAC Authentication Best Practices](https://www.owlstown.com/resources/hmac)
