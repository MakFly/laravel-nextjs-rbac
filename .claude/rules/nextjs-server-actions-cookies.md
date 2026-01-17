---
paths:
  - "apps/web/src/lib/api/**/*.ts"
  - "apps/web/src/app/api/**/*.ts"
---

# Next.js Server Actions et Cookies - Règle critique

## Le piège `credentials: 'include'`

**ATTENTION** : `credentials: 'include'` dans `fetch()` ne fonctionne **PAS** pour les requêtes server-to-server.

### Pourquoi ?

`credentials: 'include'` est une instruction pour le **navigateur** qui lui dit d'inclure les cookies dans la requête. Mais dans une Server Action (`'use server'`), c'est **Node.js** qui exécute le `fetch()`, pas le navigateur.

Résultat : les cookies ne sont jamais envoyés.

### Pattern incorrect

```typescript
'use server';

async function bffRequest(endpoint: string) {
  const cookieStore = await cookies();
  const authToken = cookieStore.get('auth_token'); // ← Lu mais ignoré !

  const response = await fetch(url, {
    credentials: 'include', // ❌ IGNORÉ côté serveur !
  });
}
```

### Pattern correct

```typescript
'use server';

async function bffRequest(endpoint: string) {
  const cookieStore = await cookies();
  const authToken = cookieStore.get('auth_token');

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  // ✅ Passer le cookie manuellement dans les headers
  if (authToken?.value) {
    (headers as Record<string, string>)['Cookie'] = `auth_token=${authToken.value}`;
  }

  const response = await fetch(url, { headers });
}
```

## Règle à appliquer

Quand tu vois du code qui :
1. Est dans un fichier avec `'use server'`
2. Utilise `cookies()` de `next/headers`
3. Fait un `fetch()` vers une API

**Vérifie TOUJOURS** que le cookie est passé explicitement dans le header `Cookie`, et non via `credentials: 'include'`.

## Schéma de flux

```
❌ Incorrect :
Server Action → fetch(credentials:'include') → API
                    ↑
              Cookie ignoré !

✅ Correct :
Server Action → cookies().get() → headers['Cookie'] → fetch() → API
                    ↑                     ↑
              Cookie lu            Cookie envoyé
```

## Quand utiliser `credentials: 'include'`

`credentials: 'include'` est **UNIQUEMENT** pour les composants **client** (`'use client'`).

| Contexte | `credentials: 'include'` | Cookie manuel |
|----------|--------------------------|---------------|
| `'use client'` (navigateur) | ✅ Fonctionne | Pas nécessaire |
| `'use server'` (Server Action) | ❌ Ignoré | ✅ Obligatoire |
| Route Handler → API externe | ❌ Ignoré | ✅ Obligatoire |

### Exemple correct côté client

```typescript
'use client';

// ✅ Ici credentials: 'include' FONCTIONNE
async function fetchUserProfile() {
  const response = await fetch('/api/v1/me', {
    credentials: 'include',  // Le navigateur envoie les cookies automatiquement
  });
  return response.json();
}
```

### Règle simple

| Tu es où ? | Que faire ? |
|------------|-------------|
| `'use client'` | `credentials: 'include'` |
| `'use server'` | `headers: { Cookie: ... }` |
| Route Handler | `headers: { Cookie: ... }` |

## Référence

- Documentation Next.js cookies(): https://nextjs.org/docs/app/api-reference/functions/cookies
- Ce bug a été corrigé dans `apps/web/src/lib/api/auth.ts`
