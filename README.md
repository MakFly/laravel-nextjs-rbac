# Laravel + Next.js + Vue.js RBAC

A secure, production-ready RBAC (Role-Based Access Control) system with **dual frontend architecture**:

- **Next.js** (App Router) — BFF pattern with Laravel Sanctum
- **Vue.js 3 SPA** — Direct API calls with session-based Sanctum auth

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DUAL AUTH SYSTEM                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  NEXT.JS BFF (Port 3001)          │    VUE.JS SPA (Port 5173)       │
│  ─────────────────────            │    ────────────────────         │
│                                   │                                 │
│  ┌─────────┐    ┌───────────┐     │    ┌─────────┐                  │
│  │ Browser │───▶│  Next.js  │     │    │ Browser │                  │
│  └─────────┘    │  Server   │     │    └────┬────┘                  │
│       ▲         │  Actions  │     │         │                       │
│       │         └─────┬─────┘     │         │                       │
│       │               │           │         ▼                       │
│  HttpOnly        Server-side      │    ┌───────────┐                │
│  Cookies         fetch()          │    │  Vue.js   │                │
│       │               │           │    │  Client   │                │
│       │               ▼           │    └─────┬─────┘                │
│       │         ┌───────────┐     │          │                      │
│       │         │           │     │          │ credentials:         │
│       │         │  Laravel  │◀────┼──────────┤   'include'          │
│       └─────────│    API    │     │          │ X-XSRF-TOKEN         │
│        Set-Cook│  (Sanctum) │     │          ▼                      │
│       ie        │           │     │    ┌───────────┐                │
│                 └───────────┘     │    │  Laravel  │                │
│                                   │    │    API    │                │
│                                   │    └───────────┘                │
│                                   │                                 │
│  Route: /api/v1/* (BFF proxy)     │  Route: /api/spa/* (direct)     │
│                                   │                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Features

| Feature | Next.js BFF | Vue.js SPA |
|---------|-------------|------------|
| **Auth** | Sanctum session (via server) | Sanctum session (direct) |
| **CSRF** | Server-side forwarding | `X-XSRF-TOKEN` header |
| **Cookies** | Forwarded manually | `credentials: 'include'` |
| **Security** | No token in browser JS | HttpOnly cookies |

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Monorepo** | Turbo + Bun |
| **Frontend 1** | Next.js 15 (App Router) + React 19 |
| **Frontend 2** | Vue.js 3 + Vite + Pinia |
| **Backend** | Laravel 11 + Sanctum |
| **RBAC** | spatie/laravel-permission |
| **UI** | shadcn/ui (both frontends) |
| **Styling** | Tailwind CSS v4 |

## Project Structure

```
laravel-nextjs-rbac/
├── apps/
│   ├── web/                          # Next.js BFF (port 3001)
│   │   └── src/
│   │       ├── app/
│   │       │   ├── api/spa/[...path] # BFF proxy to Laravel
│   │       │   └── (routes)/         # Frontend pages
│   │       └── lib/api/
│   │           ├── auth.ts           # Server Actions
│   │           └── laravel.ts        # Laravel client + CSRF
│   │
│   ├── web-vuejs/                    # Vue.js SPA (port 5173)
│   │   └── src/
│   │       ├── lib/api/              # API client with CSRF
│   │       ├── stores/               # Pinia stores
│   │       ├── views/                # Pages
│   │       └── components/           # UI components
│   │
│   └── api/                          # Laravel API (port 8000)
│       └── routes/api.php
│           ├── /api/v1/*             # BFF routes (Passport)
│           └── /api/spa/*            # SPA routes (Sanctum)
│
├── packages/types/                   # Shared TypeScript types
├── docs/CSRF-EXPLAINED.md            # CSRF documentation
├── Makefile                          # Dev commands
└── turbo.json
```

## Quick Start

### Prerequisites

- **PHP** 8.2+
- **Node.js** 18+
- **Bun** (package manager)
- **Composer**

### Installation

```bash
# Clone & install
git clone <repository-url>
cd laravel-nextjs-rbac
bun install
cd apps/api && composer install

# Setup Laravel
cp .env.example .env
php artisan key:generate
php artisan migrate --seed
```

### Development

```bash
# All services (recommended)
make dev

# Or individually:
make dev-api      # Laravel (port 8000)
make dev-web      # Next.js (port 3001)
make dev-vue      # Vue.js (port 5173)
```

| Service | URL |
|---------|-----|
| Next.js BFF | http://localhost:3001 |
| Vue.js SPA | http://localhost:5173 |
| Laravel API | http://localhost:8000 |

## Authentication Flow

### Next.js BFF (Server Actions)

```
1. Browser → Server Action (loginAction)
2. Server calls initCsrfServer() → GET /sanctum/csrf-cookie
3. Server forwards cookies + X-XSRF-TOKEN to Laravel
4. Laravel sets session cookie → forwarded to browser
5. Subsequent requests: cookies forwarded server-side
```

**Key Point**: `credentials: 'include'` does NOT work in Server Actions. Cookies must be forwarded manually.

### Vue.js SPA (Client)

```
1. Browser → initCsrf() → GET /sanctum/csrf-cookie
2. Laravel sets XSRF-TOKEN cookie (readable by JS)
3. Login → POST with X-XSRF-TOKEN header + credentials: 'include'
4. Laravel sets laravel_session (HttpOnly)
5. Subsequent requests: browser sends cookies automatically
```

## API Routes

| Prefix | Auth | Usage |
|--------|------|-------|
| `/api/v1/*` | Passport | Next.js BFF |
| `/api/spa/*` | Sanctum | Vue.js SPA |
| `/sanctum/csrf-cookie` | Public | CSRF token init |

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | Login |
| `/auth/register` | POST | Register |
| `/auth/logout` | POST | Logout |
| `/me` | GET | Current user |
| `/auth/providers` | GET | OAuth providers |

## RBAC (spatie/laravel-permission)

### Roles & Permissions

```php
// Seeders create default roles:
- Super Admin (all permissions)
- Admin (user management)
- Editor (content management)
- User (basic access)
```

### Usage in Code

```php
// Laravel
$user->hasPermissionTo('edit users');
$user->hasRole('admin');

// Blade
@role('admin')
    <!-- Admin content -->
@endrole
```

## Environment Variables

### Next.js (`apps/web/.env.local`)

```env
NEXT_PUBLIC_APP_URL=http://localhost:3001
LARAVEL_API_URL=http://localhost:8000
```

### Vue.js (`apps/web-vuejs/.env.local`)

```env
VITE_APP_URL=http://localhost:5173
VITE_LARAVEL_API_URL=http://localhost:8000
```

### Laravel (`apps/api/.env`)

```env
APP_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3001
VUE_FRONTEND_URL=http://localhost:5173

SANCTUM_STATEFUL_DOMAINS=localhost:3001,localhost:5173
SESSION_DOMAIN=localhost
```

## CSRF Protection

Both frontends use CSRF tokens with Laravel Sanctum. See [docs/CSRF-EXPLAINED.md](docs/CSRF-EXPLAINED.md) for detailed explanation.

**Summary:**
- CSRF tokens protect against Cross-Site Request Forgery
- Required because cookies are sent automatically by browsers
- Token proves request comes from YOUR frontend, not a malicious site

## Troubleshooting

### 419 CSRF Token Mismatch

**Next.js**: Call `initCsrfServer()` before POST requests
**Vue.js**: Call `initCsrf()` before POST requests

### Session Not Persisting

1. Check `SANCTUM_STATEFUL_DOMAINS` includes your frontend URL
2. Verify `SESSION_DOMAIN` is correct
3. Ensure cookies are not blocked by browser

### CORS Errors (Vue.js only)

1. Vite proxy should forward `/api/spa/*` to Laravel
2. Check `cors.php` configuration in Laravel

## Commands

```bash
# Monorepo
bun install              # Install dependencies
bun run build            # Build all packages
make dev                 # Start all services

# Individual services
make dev-api             # Laravel only
make dev-web             # Next.js only
make dev-vue             # Vue.js only

# Laravel
cd apps/api
php artisan migrate      # Run migrations
php artisan db:seed      # Seed database
php artisan test         # Run tests
```

## License

MIT License
