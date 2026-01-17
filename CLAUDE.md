# Laravel + Next.js RBAC

## Architecture

Ce projet utilise une architecture **BFF (Backend For Frontend)** :

```
Navigateur → Next.js (BFF) → Laravel API
```

- **Frontend** : Next.js App Router (`apps/web/`)
- **Backend** : Laravel avec Sanctum (`apps/api/`)
- **Communication** : HMAC-signed requests entre BFF et Laravel

## Structure du projet

```
apps/
├── web/                    # Next.js App Router
│   └── src/
│       ├── app/api/v1/     # BFF Route Handlers (proxy vers Laravel)
│       └── lib/api/        # Server Actions pour l'auth
└── api/                    # Laravel API
```

## Commandes

```bash
# Monorepo
bun install                 # Installer les dépendances
bun run build               # Build tous les packages

# Web (Next.js)
bun run --filter @rbac/web dev      # Dev server (port 3000)
bun run --filter @rbac/web build    # Production build

# API (Laravel)
cd apps/api && php artisan serve    # Dev server (port 8000)
```

## Authentification

L'authentification utilise des **cookies HttpOnly** pour sécuriser les tokens.

### Flow d'authentification

1. Login via Server Action → BFF → Laravel
2. Laravel retourne `access_token`
3. BFF stocke le token dans un cookie HttpOnly `auth_token`
4. Les requêtes suivantes lisent le cookie et l'envoient à Laravel

### Fichiers clés

- `apps/web/src/app/api/v1/[...path]/route.ts` - BFF Proxy
- `apps/web/src/lib/api/auth.ts` - Server Actions auth

## Règles importantes

Voir `.claude/rules/` pour les règles détaillées :
- @.claude/rules/nextjs-server-actions-cookies.md

## Variables d'environnement

```env
# Web (.env.local)
NEXT_PUBLIC_APP_URL=http://localhost:3000
LARAVEL_API_URL=http://localhost:8000
BFF_SECRET=xxx              # Pour HMAC signing

# API (.env)
APP_URL=http://localhost:8000
SANCTUM_STATEFUL_DOMAINS=localhost:3000
```
