# Laravel + Next.js + Vue.js RBAC

## Architecture

Ce projet utilise une architecture **dual auth** :

```
Navigateur → Next.js (BFF + HMAC) → Laravel API (Passport tokens)
Navigateur → Vue.js SPA (Sanctum) → Laravel API (session + CSRF)
```

- **Frontend Next.js** : Next.js App Router (`apps/web/`) — BFF pattern avec Passport + HMAC
- **Frontend Vue.js** : Vue 3 SPA (`apps/web-vuejs/`) — Sanctum SPA mode (session + CSRF + cookies HttpOnly)
- **Backend** : Laravel avec Passport + Sanctum (`apps/api/`)

## Structure du projet

```
apps/
├── web/                    # Next.js App Router
│   └── src/
│       ├── app/api/v1/     # BFF Route Handlers (proxy vers Laravel)
│       └── lib/api/        # Server Actions pour l'auth
├── web-vuejs/              # Vue 3 SPA
│   └── src/
│       ├── lib/api/        # API client (CSRF) + auth + admin
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

### Vue.js (Sanctum SPA mode)

Le SPA Vue utilise **Sanctum session-based auth** (cookies HttpOnly gérés par Laravel) :

1. `GET /sanctum/csrf-cookie` → Laravel pose les cookies `XSRF-TOKEN` + `laravel_session`
2. Login → POST `/api/spa/auth/login` avec `X-XSRF-TOKEN` header → Laravel crée la session
3. Les requêtes suivantes envoient automatiquement le cookie session (`credentials: 'include'`)
4. Le Vite dev server proxy les requêtes `/api/spa/*` et `/sanctum/*` vers Laravel

### Fichiers clés

- `apps/web/src/app/api/v1/[...path]/route.ts` - BFF Proxy Next.js
- `apps/web/src/lib/api/auth.ts` - Server Actions auth
- `apps/web-vuejs/src/lib/api/client.ts` - API client avec CSRF (Sanctum)
- `apps/web-vuejs/src/lib/api/auth.ts` - API auth Vue.js (session-based)
- `apps/web-vuejs/src/stores/auth.ts` - Pinia auth store

## API Routes

| Prefix | Auth | Usage |
|--------|------|-------|
| `/api/v1/*` | Passport + HMAC | Next.js BFF |
| `/api/spa/*` | Sanctum session (web guard) | Vue.js SPA |

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
SANCTUM_STATEFUL_DOMAINS=localhost:5173,localhost:3000
SESSION_DOMAIN=localhost
FRONTEND_URL=http://localhost:3001
VUE_FRONTEND_URL=http://localhost:5173
```
