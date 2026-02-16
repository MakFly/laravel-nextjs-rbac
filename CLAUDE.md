# Laravel + Next.js + Vue.js RBAC

## Architecture

Ce projet utilise une architecture **dual frontend, single auth** :

```
Navigateur → Next.js (BFF + HMAC) → Laravel API (Passport tokens)
Navigateur → Vue.js SPA (Passport cookies) → Laravel API (Passport tokens)
```

- **Frontend Next.js** : Next.js App Router (`apps/web/`) — BFF pattern avec Passport + HMAC
- **Frontend Vue.js** : Vue 3 SPA (`apps/web-vuejs/`) — Passport tokens dans cookies HttpOnly
- **Backend** : Laravel avec Passport (`apps/api/`) — 100% stateless, 0 session

## Structure du projet

```
apps/
├── web/                    # Next.js App Router
│   └── src/
│       ├── app/api/v1/     # BFF Route Handlers (proxy vers Laravel)
│       └── lib/api/        # Server Actions pour l'auth
├── web-vuejs/              # Vue 3 SPA
│   └── src/
│       ├── lib/api/        # API client + auth + admin
│       ├── stores/         # Pinia stores (auth)
│       ├── views/          # Pages (Dashboard, Users, Roles, etc.)
│       └── components/     # Composants UI (shadcn-vue)
└── api/                    # Laravel API
    └── routes/api.php      # /api/v1/* (BFF) + /api/spa/* (SPA)
```

## Commandes

```bash
# Monorepo
bun install                 # Installer les dépendances
bun run build               # Build tous les packages
make dev                    # Lance api + web + web-vuejs en parallèle

# Web (Next.js)
bun run --filter @rbac/web dev      # Dev server (port 3001)
bun run --filter @rbac/web build    # Production build
make dev-web                        # Raccourci Makefile

# Web Vue.js
bun run --filter @rbac/web-vuejs dev  # Dev server (port 5173)
make dev-vue                          # Raccourci Makefile

# API (Laravel)
cd apps/api && php artisan serve    # Dev server (port 8000)
make dev-api                        # Raccourci Makefile
```

## Authentification

### Next.js (BFF) — Passport + HMAC

L'authentification utilise des **cookies HttpOnly** pour sécuriser les tokens.

1. Login via Server Action → BFF → Laravel `/api/v1/auth/login`
2. Laravel retourne `access_token` (Passport)
3. BFF stocke le token dans un cookie HttpOnly `auth_token`
4. Les requêtes suivantes lisent le cookie et l'envoient à Laravel

### Vue.js — Passport tokens dans cookies HttpOnly

Le SPA Vue utilise des **Passport tokens stockés dans des cookies HttpOnly** :

1. Login → POST `/api/spa/auth/token/login` → Laravel crée un token Passport
2. Laravel retourne 2 cookies HttpOnly : `access_token` (JWT) + `refresh_token` (UUID)
3. Les requêtes suivantes envoient les cookies automatiquement (`credentials: 'include'`)
4. `PassportCookieMiddleware` lit le cookie et injecte le Bearer token

### Impersonation (token-based)

L'impersonation fonctionne via un **cookie `admin_token`** (UUID du token Passport admin) :

1. Admin POST `/admin/impersonate/{user}` → sauvegarde admin token ID dans cookie `admin_token`
2. Crée de nouveaux tokens Passport pour le user cible → remplace `access_token` + `refresh_token`
3. `GET /me` → détecte le cookie `admin_token` → lookup Token DB → ajoute `is_impersonating` + `impersonator`
4. Stop → lookup `admin_token` → restaure tokens admin → clear `admin_token`

### Fichiers clés

- `apps/web/src/app/api/v1/[...path]/route.ts` - BFF Proxy Next.js
- `apps/web/src/lib/api/auth.ts` - Server Actions auth
- `apps/web-vuejs/src/lib/api/client.ts` - API client (cookies HttpOnly)
- `apps/web-vuejs/src/lib/api/auth.ts` - API auth Vue.js (token-based)
- `apps/web-vuejs/src/stores/auth.ts` - Pinia auth store
- `apps/api/app/Http/Controllers/Concerns/HasTokenCookies.php` - Trait cookie partagé
- `apps/api/app/Http/Middleware/PassportCookieMiddleware.php` - Cookie → Bearer injection

## API Routes

| Prefix | Auth | Usage |
|--------|------|-------|
| `/api/v1/*` | Passport + HMAC | Next.js BFF |
| `/api/spa/*` | Passport cookie (HttpOnly) | Vue.js SPA |

## Règles importantes

Voir `.claude/rules/` pour les règles détaillées :
- @.claude/rules/nextjs-server-actions-cookies.md

## Variables d'environnement

```env
# Web Next.js (.env.local)
NEXT_PUBLIC_APP_URL=http://localhost:3001
LARAVEL_API_URL=http://localhost:8000
BFF_HMAC_SECRET=xxx
BFF_ID=nextjs-bff-prod

# Web Vue.js (.env.local)
VITE_APP_URL=http://localhost:5173
VITE_LARAVEL_API_URL=http://localhost:8000

# API (.env)
APP_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3001
VUE_FRONTEND_URL=http://localhost:5173
```
