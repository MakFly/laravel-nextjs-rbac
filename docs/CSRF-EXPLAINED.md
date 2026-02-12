# CSRF Token - Explication Complète

## Le Problème

### L'authentification par cookie = envoi automatique

Quand un utilisateur est connecté via **cookies de session** (Laravel Sanctum), le navigateur envoie automatiquement ces cookies avec **chaque requête**, même celles provenant d'un site malveillant.

```
Utilisateur connecté à app.example.com
    ↓
Cookie: laravel_session=abc123 (posé automatiquement)
    ↓
Utilisateur visite evil.com
    ↓
evil.com exécute: fetch('https://app.example.com/api/delete-account', { method: 'POST' })
    ↓
Navigateur envoie AUTOMATIQUEMENT: Cookie: laravel_session=abc123
    ↓
Backend exécute l'action → 💥 Compte supprimé
```

### Pourquoi l'attaquant peut faire ça ?

- Le navigateur envoie les cookies **pour le domaine cible**, peu importe l'origine de la requête
- Le backend ne peut pas distinguer une requête légitime d'une requête malveillante
- L'utilisateur est authentifié, donc le backend autorise l'action

## La Solution : CSRF Token

Le CSRF token est une **preuve que la requête vient de TON frontend**.

### Principe

```
1. Backend génère un token unique lié à la session
2. Token stocké en cookie (XSRF-TOKEN) + en session serveur
3. Frontend DOIT renvoyer ce token explicitement dans un header
4. Backend vérifie: token envoyé === token attendu
```

### Pourquoi ça marche ?

Un site malveillant (evil.com) :
- ❌ Ne peut PAS lire les cookies (Same Origin Policy)
- ❌ Ne peut PAS lire le DOM de app.example.com
- ❌ Ne peut PAS deviner le token (cryptographiquement aléatoire)

Résultat : evil.com peut envoyer une requête, mais **sans le token** → rejet.

---

## Implémentation dans ce projet

### Vue.js SPA (`apps/web-vuejs/`)

#### Flux complet

```
┌──────────────────────────────────────────────────────────────────┐
│                    VUE.JS SPA (Sanctum)                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. INIT CSRF (avant login)                                     │
│     ┌─────────┐    GET /sanctum/csrf-cookie    ┌─────────────┐  │
│     │  Vue    │ ────────────────────────────▶  │   Laravel   │  │
│     │         │    Set-Cookie: XSRF-TOKEN      │             │  │
│     │         │ ◀────────────────────────────  │             │  │
│     └─────────┘                                 └─────────────┘  │
│                                                                  │
│  2. LOGIN                                                        │
│     ┌─────────┐    POST /api/spa/auth/login     ┌─────────────┐  │
│     │  Vue    │ ────────────────────────────▶  │   Laravel   │  │
│     │         │    Cookie: XSRF-TOKEN          │             │  │
│     │         │    Header: X-XSRF-TOKEN        │             │  │
│     │         │    Body: { email, password }   │             │  │
│     │         │                                 │  Vérifie    │  │
│     │         │    Set-Cookie: laravel_session │  token      │  │
│     │         │ ◀────────────────────────────  │             │  │
│     └─────────┘                                 └─────────────┘  │
│                                                                  │
│  3. REQUÊTES SUIVANTES                                          │
│     ┌─────────┐    POST /api/spa/...           ┌─────────────┐  │
│     │  Vue    │ ────────────────────────────▶  │   Laravel   │  │
│     │         │    Cookie: XSRF-TOKEN          │             │  │
│     │         │          + laravel_session     │  Vérifie    │  │
│     │         │    Header: X-XSRF-TOKEN        │  CSRF       │  │
│     └─────────┘                                 └─────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Code (`src/lib/api/client.ts`)

```typescript
// 1. Initialiser CSRF avant login
export async function initCsrf(): Promise<void> {
  await fetch('/sanctum/csrf-cookie', { credentials: 'include' })
  // Laravel pose: Set-Cookie: XSRF-TOKEN=xxx; Path=/; SameSite=Lax
}

// 2. Lire le token depuis les cookies
function getXsrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/)
  return match?.[1] ? decodeURIComponent(match[1]) : null
}

// 3. Inclure le token dans chaque requête
export async function apiRequest<T>(endpoint: string, options = {}) {
  const xsrfToken = getXsrfToken()

  const headers = {
    'Content-Type': 'application/json',
    // Le token prouve que la requête vient de notre frontend
    ...(xsrfToken ? { 'X-XSRF-TOKEN': xsrfToken } : {}),
  }

  return fetch(`/api/spa${endpoint}`, {
    ...options,
    headers,
    credentials: 'include', // Envoie les cookies automatiquement
  })
}
```

#### Utilisation (`src/lib/api/auth.ts`)

```typescript
export async function login(credentials: LoginCredentials) {
  await initCsrf()  // ← OBLIGATOIRE avant POST
  return apiRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  })
}
```

---

### Next.js BFF (`apps/web/`)

#### Flux complet

```
┌───────────────────────────────────────────────────────────────────────┐
│                    NEXT.JS BFF (Sanctum via Server Actions)           │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. LOGIN (Server Action)                                            │
│     ┌─────────────┐                              ┌─────────────┐     │
│     │   Browser   │   loginAction()              │   Next.js   │     │
│     │             │ ─────────────────────────▶   │   Server    │     │
│     │             │                              │             │     │
│     │             │   cookies forwarded          │             │     │
│     │             │ ◀─────────────────────────   │             │     │
│     └─────────────┘                              └──────┬──────┘     │
│                                                         │            │
│                    ┌────────────────────────────────────┘            │
│                    │                                                  │
│                    ▼                                                  │
│     ┌─────────────────────────────────────────────────────────────┐  │
│     │  initCsrfServer()                                            │  │
│     │  ┌─────────┐    GET /sanctum/csrf-cookie    ┌────────────┐  │  │
│     │  │ Next.js │ ────────────────────────────▶  │  Laravel   │  │  │
│     │  │ Server  │    Cookie: (existing)          │            │  │  │
│     │  │         │    Referer: localhost:3001     │            │  │  │
│     │  │         │                                │ Génère     │  │  │
│     │  │         │    Set-Cookie: XSRF-TOKEN      │ token      │  │  │
│     │  │         │ ◀────────────────────────────  │            │  │  │
│     │  └─────────┘                                 └────────────┘  │  │
│     └─────────────────────────────────────────────────────────────┘  │
│                                                                       │
│                    ┌─────────────────────────────────────┐           │
│                    │  laravelRequest('/auth/login')      │           │
│                    │  ┌─────────┐    POST /api/spa/auth  ┌────────┐  │
│                    │  │ Next.js │ ────────────────────▶  │Laravel │  │
│                    │  │ Server  │    Cookie: all + XSRF  │        │  │
│                    │  │         │    Header: X-XSRF      │Vérifie │  │
│                    │  │         │    Body: credentials   │token   │  │
│                    │  │         │                        │        │  │
│                    │  │         │    Set-Cookie: session │        │  │
│                    │  │         │ ◀───────────────────── │        │  │
│                    │  └─────────┘                         └────────┘  │
│                    └─────────────────────────────────────┘           │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

#### Code (`src/lib/api/laravel.ts`)

```typescript
'use server'

import { cookies } from 'next/headers'

// Initialiser CSRF (appelé avant chaque POST/PUT/DELETE)
export async function initCsrfServer(): Promise<void> {
  const cookieStore = await cookies()
  const allCookies = cookieStore.getAll()
  const cookieHeader = allCookies.map(c => `${c.name}=${c.value}`).join('; ')

  const response = await fetch(`${LARAVEL_API_URL}/sanctum/csrf-cookie`, {
    headers: {
      'Cookie': cookieHeader,      // ← Forward les cookies existants
      'Referer': APP_URL,          // ← Pour Sanctum stateful check
      'Origin': APP_URL,
    },
  })

  // Forward Set-Cookie vers le browser (XSRF-TOKEN)
  for (const setCookie of response.headers.getSetCookie()) {
    // Parse et set le cookie dans le browser
    cookieStore.set({ name, value, sameSite: 'lax', ... })
  }
}

// Requête authentifiée
export async function laravelRequest<T>(endpoint: string, options = {}) {
  const cookieStore = await cookies()
  const xsrfToken = cookieStore.get('XSRF-TOKEN')?.value

  const headers = {
    // Token CSRF - preuve que ça vient de notre frontend
    ...(xsrfToken ? { 'X-XSRF-TOKEN': decodeURIComponent(xsrfToken) } : {}),
    // Cookies forwardés manuellement (credentials: 'include' ne marche pas en server-side)
    'Cookie': allCookies.map(c => `${c.name}=${c.value}`).join('; '),
    'Referer': APP_URL,
  }

  return fetch(`${LARAVEL_API_URL}/api/spa${endpoint}`, { headers })
}
```

#### Utilisation (`src/lib/api/auth.ts`)

```typescript
'use server'

export async function loginAction(credentials: LoginCredentials) {
  await initCsrfServer()  // ← OBLIGATOIRE avant POST
  return laravelRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  })
}
```

---

## Résumé

| Concept | Explication |
|---------|-------------|
| **Problème** | Les cookies sont envoyés automatiquement, même par un site malveillant |
| **Solution** | Un token secret que seul ton frontend peut connaître et renvoyer |
| **Implémentation** | 1. GET `/sanctum/csrf-cookie` → 2. Lire `XSRF-TOKEN` → 3. Header `X-XSRF-TOKEN` |
| **Vue.js** | `credentials: 'include'` fonctionne (navigateur) |
| **Next.js BFF** | Cookies forwardés manuellement (server-side) |

## Pourquoi pas JWT dans localStorage ?

| Méthode | CSRF | XSS |
|---------|------|-----|
| Cookie + CSRF | ✅ Protégé | ✅ Protégé (HttpOnly) |
| localStorage JWT | ❌ Pas de CSRF | ❌ Vulnérable XSS |
| Cookie HttpOnly sans CSRF | ❌ Vulnérable CSRF | ✅ Protégé |

**Conclusion** : `Cookie HttpOnly + CSRF` = meilleure protection combinée CSRF + XSS.
