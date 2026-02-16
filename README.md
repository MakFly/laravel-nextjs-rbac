# Laravel + Next.js + Vue.js RBAC

A secure, production-ready RBAC (Role-Based Access Control) system with **dual frontend architecture**:

- **Next.js** (App Router) — BFF pattern with Passport + HMAC
- **Vue.js 3 SPA** — Passport tokens in HttpOnly cookies

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DUAL FRONTEND — PASSPORT AUTH                     │
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
│       └─────────│    API    │     │          │ (HttpOnly cookies)   │
│        Set-Cook │ (Passport)│     │          ▼                      │
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
| **Auth** | Passport (via server) | Passport (HttpOnly cookies) |
| **Tokens** | Server-side forwarding | Cookie-based (automatic) |
| **Security** | No token in browser JS | HttpOnly cookies, no CSRF needed |
| **State** | Stateless | Stateless |

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Monorepo** | Turbo + Bun |
| **Frontend 1** | Next.js 15 (App Router) + React 19 |
| **Frontend 2** | Vue.js 3 + Vite + Pinia |
| **Backend** | Laravel 11 + Passport |
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
│   │       │   ├── api/v1/[...path]  # BFF proxy to Laravel
│   │       │   └── (routes)/         # Frontend pages
│   │       └── lib/api/
│   │           ├── auth.ts           # Server Actions
│   │           └── laravel.ts        # Laravel client
│   │
│   ├── web-vuejs/                    # Vue.js SPA (port 5173)
│   │   └── src/
│   │       ├── lib/api/              # API client (HttpOnly cookies)
│   │       ├── stores/               # Pinia stores
│   │       ├── views/                # Pages
│   │       └── components/           # UI components
│   │
│   └── api/                          # Laravel API (port 8000)
│       └── routes/api.php
│           ├── /api/v1/*             # BFF routes (Passport + HMAC)
│           └── /api/spa/*            # SPA routes (Passport cookies)
│
├── packages/types/                   # Shared TypeScript types
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
2. Server calls Laravel /api/v1/auth/login
3. Laravel returns access_token (Passport JWT)
4. Server Action sets HttpOnly cookie auth_token
5. Subsequent requests: cookie forwarded server-side
```

**Key Point**: `credentials: 'include'` does NOT work in Server Actions. Cookies must be forwarded manually.

### Vue.js SPA (Passport Cookies)

```
1. Login → POST /api/spa/auth/token/login
2. Laravel creates Passport token + sets HttpOnly cookies:
   - access_token (JWT, 6h TTL)
   - refresh_token (UUID, 30d TTL)
3. Subsequent requests: browser sends cookies automatically
4. PassportCookieMiddleware injects Bearer token from cookie
```

## API Routes

| Prefix | Auth | Usage |
|--------|------|-------|
| `/api/v1/*` | Passport + HMAC | Next.js BFF |
| `/api/spa/*` | Passport cookie | Vue.js SPA |

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/token/login` | POST | Login (token + cookies) |
| `/auth/token/register` | POST | Register (token + cookies) |
| `/auth/token/logout` | POST | Logout (clear cookies) |
| `/auth/token/refresh` | POST | Refresh tokens |
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
BFF_HMAC_SECRET=xxx
BFF_ID=nextjs-bff-prod
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
```

## Troubleshooting

### 401 Unauthorized on SPA requests

1. Check cookies are sent (`credentials: 'include'` in fetch)
2. Verify `access_token` cookie is present in browser DevTools
3. Try refreshing the token via POST `/api/spa/auth/token/refresh`

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
