# AGENTS.md - Agent Guidelines for Laravel + Next.js RBAC

## Overview

This is a monorepo with three applications:

- **apps/web** - Next.js 15 (App Router, port 3001)
- **apps/web-vuejs** - Vue 3 + Vite (port 5173)
- **apps/api** - Laravel 12 (port 8000)

## Build / Lint / Test Commands

### Monorepo (root)

```bash
bun install           # Install all dependencies
bun run build         # Build all apps for production
bun run dev           # Run all apps in parallel (turbo)
bun run lint          # Lint all apps
bun run format        # Format code with Prettier
```

### Next.js (apps/web)

```bash
bun run dev           # Dev server on port 3001
bun run build         # Production build
bun run start         # Start production server
bun run lint          # ESLint checks

# Single test (if tests exist)
bun vitest run --filter=<test-name>
```

### Vue.js (apps/web-vuejs)

```bash
bun run dev           # Dev server on port 5173
bun run build         # TypeScript check + Vite build
bun run preview       # Preview production build
```

### Laravel (apps/api)

```bash
cd apps/api
php artisan serve --port=8000      # Dev server
composer test                       # Run PHPUnit tests
php artisan test                    # Same as above
php artisan test --filter=TestName  # Single test

# Run specific test suite
php artisan test --testsuite=Unit
php artisan test --testsuite=Feature

# Laravel Pint (code style)
./vendor/bin/pint                    # Format code
./vendor/bin/pint --test             # Check style without modifying
```

### Makefile Shortcuts

```bash
make dev              # All apps in parallel
make dev-web          # Next.js only
make dev-vue          # Vue.js only
make dev-api          # Laravel only
make test             # Run web + api tests
make lint             # Lint all apps
make db-migrate       # Run migrations
make db-reset         # Fresh migrate + seed
```

## Code Style Guidelines

### TypeScript / JavaScript

- **Strict Mode**: Always enabled (`"strict": true` in tsconfig.json)
- **Import Aliases**: Use `@/*` for local imports in Next.js (e.g., `@/components/Button`)
- **Types**: Never use `any` unless absolutely necessary; use `unknown` and type narrow
- **Naming**: camelCase for variables/functions, PascalCase for components/classes, SCREAMING_SNAKE_CASE for constants

### React / Next.js

- Use **Server Components** by default; add `'use client'` only when needed
- Prefer **React Server Actions** over API routes for form submissions
- Use **Zod** for form validation (already installed)
- Use **sonner** for toast notifications
- Component structure: `components/ui/` for shadcn components, `components/` for business components

### Vue.js

- Use **Composition API** with `<script setup>` syntax
- Use **Pinia** for state management
- Use **vee-validate** + **zod** for form validation
- Follow Vue 3 style guide: https://vuejs.org/style-guide/

### PHP / Laravel

- Use **Pint** for code formatting (PSR-12 compliant)
- Follow Laravel conventions: https://laravel.com/docs/12.x/contributions#coding-style
- Use **type hints** on all method parameters and return types
- Use **PHPUnit** for testing with feature/unit test separation
- Use **Facades** sparingly; inject dependencies instead
- Follow **Repository Pattern** for database queries

### Tailwind CSS

- Use **shadcn/ui** components as base (already configured)
- Next.js: Tailwind v3, Vue.js: Tailwind v4
- Use `cn()` utility for conditional classes (clsx + tailwind-merge)

## Error Handling

### Frontend

- Use **error boundaries** in React for graceful error recovery
- Display user-friendly error messages from API responses
- Log errors to console in development, use error tracking service in production

### Backend (Laravel)

- Use **try-catch** for expected exceptions with custom handling
- Use **validation requests** (`FormRequest`) for input validation
- Return consistent JSON structure: `{ "message": "...", "errors": {...} }`
- Use Laravel's exception handler for API error formatting

## Database

- Use **migrations** for all schema changes
- Use **seeders** for test data
- Use **Eloquent** ORM with proper relationships
- Use **factories** for testing

## Git Conventions

- Use **Conventional Commits**: `feat/fix/refactor/docs/test/chore: description`
- Messages in **English**
- Never commit secrets or environment files

## Important File Locations

```
apps/web/src/app/              # Next.js App Router pages
apps/web/src/lib/              # Server Actions, utilities
apps/web-vuejs/src/             # Vue.js app
apps/web-vuejs/src/views/       # Page components
apps/web-vuejs/src/stores/      # Pinia stores
apps/api/app/Http/Controllers/ # Laravel controllers
apps/api/app/Http/Middleware/  # Laravel middleware
apps/api/routes/               # Route definitions
apps/api/database/migrations/  # Migrations
apps/api/tests/                # PHPUnit tests
```

## Environment Variables

- **Never commit `.env` files**
- Copy from `.env.example` and fill in values
- Key variables: `LARAVEL_API_URL`, `NEXT_PUBLIC_APP_URL`, `BFF_HMAC_SECRET`
