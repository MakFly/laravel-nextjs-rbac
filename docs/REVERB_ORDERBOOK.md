# Laravel Reverb & OrderBook en temps reel

## Vue d'ensemble

Cette feature implementee un **carnet d'ordres (Order Book) BTC/USDT en temps reel** en utilisant :

- **Laravel Reverb** comme serveur WebSocket (remplacement open-source de Pusher)
- **Binance WebSocket API** comme source de donnees
- **Laravel Echo** cote client (Vue.js + Next.js)

```
Binance WS ──→ Commande Artisan ──→ Reverb (WS) ──→ Vue.js / Next.js
  (source)       (bridge)           (broadcast)       (affichage)
```

---

## Architecture

```
┌──────────────────┐     WebSocket      ┌───────────────────────┐
│  Binance Stream   │ ───────────────→  │  artisan orderbook:   │
│  depth@100ms      │                   │  stream (bridge)      │
└──────────────────┘                    └───────────┬───────────┘
                                                    │ Pusher SDK
                                                    ▼
                                        ┌───────────────────────┐
                                        │   Laravel Reverb      │
                                        │   ws://localhost:8080  │
                                        └───────────┬───────────┘
                                                    │ WebSocket
                                        ┌───────────┴───────────┐
                                        ▼                       ▼
                                ┌──────────────┐     ┌──────────────┐
                                │   Vue.js     │     │   Next.js    │
                                │   :5173      │     │   :3001      │
                                └──────────────┘     └──────────────┘
```

**Flux detaille :**

1. La commande Artisan se connecte au WebSocket Binance (`wss://stream.binance.com`)
2. Elle recoit les mises a jour du carnet d'ordres toutes les 100ms
3. Elle throttle les broadcasts (par defaut 1 update/seconde)
4. Elle envoie les donnees a Reverb via le SDK Pusher
5. Reverb diffuse a tous les clients connectes sur le channel `orderbook`
6. Les frontends Vue.js et Next.js affichent les donnees en temps reel

---

## Packages installes

### Laravel (Composer)

| Package | Version | Role |
|---------|---------|------|
| `laravel/reverb` | ^1.7 | Serveur WebSocket compatible Pusher |
| `ratchet/pawl` | ^0.4.3 | Client WebSocket PHP (connexion a Binance) |

### Vue.js & Next.js (npm/bun)

| Package | Version | Role |
|---------|---------|------|
| `laravel-echo` | ^2.3.0 | Client de broadcasting Laravel |
| `pusher-js` | ^8.4.0 | Transport WebSocket (protocole Pusher) |

---

## Configuration

### Variables d'environnement

#### Laravel (`apps/api/.env`)

```env
# Broadcasting
BROADCAST_CONNECTION=reverb

# Reverb Server
REVERB_APP_ID=123456
REVERB_APP_KEY=your-reverb-key
REVERB_APP_SECRET=your-reverb-secret
REVERB_HOST=localhost
REVERB_PORT=8080
REVERB_SCHEME=http
REVERB_SERVER_HOST=0.0.0.0
REVERB_SERVER_PORT=8080
```

#### Vue.js (`apps/web-vuejs/.env.local`)

```env
VITE_REVERB_APP_KEY=your-reverb-key
VITE_REVERB_HOST=localhost
VITE_REVERB_PORT=8080
```

#### Next.js (`apps/web/.env.local`)

```env
NEXT_PUBLIC_REVERB_APP_KEY=your-reverb-key
NEXT_PUBLIC_REVERB_HOST=localhost
NEXT_PUBLIC_REVERB_PORT=8080
```

> La `REVERB_APP_KEY` doit etre **identique** entre Laravel et les frontends.

### Fichiers de configuration Laravel

#### `config/reverb.php`

Configure le serveur Reverb :
- **Host** : `0.0.0.0` (ecoute sur toutes les interfaces)
- **Port** : `8080`
- **Scaling** : Desactive par defaut (activable avec Redis pour du multi-serveur)
- **Ping interval** : 60s
- **Activity timeout** : 30s
- **Max message size** : 10 000 bytes

#### `config/broadcasting.php`

Definit la connexion `reverb` comme broadcaster :
- Driver : `reverb`
- Utilise les memes credentials (`REVERB_APP_KEY`, `REVERB_APP_SECRET`, `REVERB_APP_ID`)
- En dev local : `scheme=http`, `useTLS=false`

#### `bootstrap/app.php`

Enregistre le fichier `routes/channels.php` pour l'authentification des channels prives.

---

## Backend Laravel

### Event : `OrderBookUpdated`

**Fichier** : `app/Events/OrderBookUpdated.php`

```php
class OrderBookUpdated implements ShouldBroadcastNow
{
    public function __construct(
        public array $bids,    // Ordres d'achat [{price, qty}, ...]
        public array $asks,    // Ordres de vente [{price, qty}, ...]
        public int $lastUpdateId,
        public int $timestamp,
    ) {}

    public function broadcastOn(): Channel
    {
        return new Channel('orderbook');  // Channel PUBLIC
    }

    public function broadcastAs(): string
    {
        return 'OrderBookUpdated';
    }
}
```

**Points cles :**
- `ShouldBroadcastNow` : broadcast immediat, sans passer par la queue
- Channel **public** `orderbook` : pas besoin d'authentification pour ecouter
- Le nom custom `OrderBookUpdated` (via `broadcastAs()`) evite le namespace PHP complet

### Commande Artisan : `orderbook:stream`

**Fichier** : `app/Console/Commands/StreamOrderBook.php`

```bash
php artisan orderbook:stream [symbol] [--depth] [--throttle]
```

| Argument/Option | Defaut | Description |
|-----------------|--------|-------------|
| `symbol` | `btcusdt` | Paire de trading (ex: `ethusdt`, `bnbusdt`) |
| `--depth` | `20` | Profondeur du carnet (5, 10 ou 20) |
| `--throttle` | `1000` | Intervalle minimum entre broadcasts (ms) |

**Fonctionnement :**

1. **Connexion** a `wss://stream.binance.com:9443/ws/{symbol}@depth{depth}@100ms`
2. **Reception** des updates toutes les 100ms
3. **Throttling** : ignore les messages si le dernier broadcast date de moins de `--throttle` ms
4. **Broadcast** via Pusher SDK → Reverb → clients
5. **Reconnexion automatique** :
   - Reconnexion preventive avant la limite de 24h de Binance (apres 23h)
   - Backoff exponentiel en cas d'erreur (1s → 2s → 4s → ... → max 30s)
6. **Logging** : affiche un compteur tous les 10 broadcasts

### Channel de broadcasting

**Fichier** : `routes/channels.php`

```php
// Channel prive pour les notifications utilisateur (pas utilise par l'OrderBook)
Broadcast::channel('App.Models.User.{id}', function ($user, $id) {
    return (int) $user->id === (int) $id;
});
```

L'OrderBook utilise un channel **public** defini directement dans l'event, donc pas besoin d'autorisation dans `channels.php`.

---

## Frontend Vue.js

### Echo Client

**Fichier** : `src/lib/echo.ts`

```typescript
import Echo from 'laravel-echo';
import Pusher from 'pusher-js';

let echoInstance: Echo<'pusher'> | null = null;

export function getEcho(): Echo<'pusher'> {
  if (echoInstance) return echoInstance;

  // Pusher doit etre global (requis par laravel-echo)
  (window as unknown as Record<string, unknown>).Pusher = Pusher;

  echoInstance = new Echo({
    broadcaster: 'pusher',
    key: import.meta.env.VITE_REVERB_APP_KEY,
    wsHost: import.meta.env.VITE_REVERB_HOST,
    wsPort: Number(import.meta.env.VITE_REVERB_PORT),
    forceTLS: false,           // Pas de TLS en dev local
    disableStats: true,        // Pas de stats Pusher
    enabledTransports: ['ws'], // WebSocket uniquement (pas de fallback HTTP)
    cluster: '',               // Requis mais vide pour Reverb
  });

  return echoInstance;
}
```

**Pattern singleton** : l'instance Echo est creee une seule fois et reutilisee.

### Composable : `useOrderBook`

**Fichier** : `src/composables/useOrderBook.ts`

```typescript
export function useOrderBook() {
  const data = ref<OrderBookData | null>(null);
  const isConnected = ref(false);
  const error = ref<string | null>(null);

  onMounted(() => {
    const echo = getEcho();
    echo.channel('orderbook')
      .listen('.OrderBookUpdated', (event: OrderBookData) => {
        data.value = event;
        isConnected.value = true;
      });
  });

  onUnmounted(() => {
    getEcho().leave('orderbook');  // Nettoyage a la destruction
  });

  return { data, isConnected, error };
}
```

**Points cles :**
- `.OrderBookUpdated` : le point (`.`) prefix est **obligatoire** pour les events avec `broadcastAs()` custom
- `echo.leave()` dans `onUnmounted` pour eviter les fuites memoire
- Retourne des `ref()` reactifs

### Page : `OrderBookPage.vue`

**Fichier** : `src/views/OrderBookPage.vue`

- Affichage en grille deux colonnes : **Bids** (vert) / **Asks** (rouge)
- Badge de statut de connexion (Live / Connecting / Error)
- Calcul et affichage du **spread** (ecart entre meilleur ask et meilleur bid)
- Skeletons de chargement en attendant les premieres donnees
- Formatage : prix a 2 decimales, quantites a 5 decimales

### Route

```typescript
// src/router/index.ts
{
  path: '/dashboard/orderbook',
  name: 'OrderBook',
  component: () => import('@/views/OrderBookPage.vue'),
  meta: { requiresAuth: true }
}
```

---

## Frontend Next.js

### Echo Client

**Fichier** : `src/lib/echo.ts`

Identique a Vue.js sauf :
- Verification `typeof window === 'undefined'` (erreur si SSR)
- Variables d'env prefixees `NEXT_PUBLIC_` au lieu de `VITE_`

### Hook : `useOrderBook`

**Fichier** : `src/hooks/use-orderbook.ts`

```typescript
// State global externe a React
let state: OrderBookState = { data: null, isConnected: false, error: null };
const listeners = new Set<() => void>();

export function useOrderBook() {
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  useEffect(() => {
    const echo = getEcho();
    echo.channel('orderbook')
      .listen('.OrderBookUpdated', (event) => {
        setState({ data: event, isConnected: true });
      });

    return () => {
      echo.leave('orderbook');
      setState({ data: null, isConnected: false });
    };
  }, []);

  return snapshot;
}
```

**Pourquoi `useSyncExternalStore` ?**
- L'etat vient d'une source externe (WebSocket via Echo)
- Ce hook React garantit que le rendu est synchrone avec la source
- `getServerSnapshot` retourne un etat vide pour le SSR

### Composant : `OrderBookView`

**Fichier** : `src/components/dashboard/orderbook-view.tsx`

- Composant client (`'use client'`)
- Meme layout que la version Vue.js
- Composant `OrderBookTable` reutilisable pour bids et asks
- `SkeletonTable` pendant le chargement

### Page

**Fichier** : `src/app/dashboard/orderbook/page.tsx`

- Verification d'authentification cote client
- Redirect vers login si non authentifie
- Skeletons pendant l'hydratation du store auth

---

## Commandes Makefile

```bash
# Terminal 1 : Serveur WebSocket Reverb
make dev-reverb        # → php artisan reverb:start --port=8080

# Terminal 2 : Bridge Binance → Reverb
make dev-orderbook     # → php artisan orderbook:stream btcusdt

# Terminal 3 : API + Frontends
make dev               # → bun run dev (api + web + web-vuejs)
```

**Ordre de lancement important :**

1. `make dev-reverb` en premier (le serveur WS doit etre disponible)
2. `make dev-orderbook` ensuite (se connecte a Reverb)
3. `make dev` pour les frontends et l'API

---

## Fichiers concernes

```
apps/api/
├── app/
│   ├── Console/Commands/
│   │   └── StreamOrderBook.php      # Commande bridge Binance → Reverb
│   └── Events/
│       └── OrderBookUpdated.php     # Event de broadcast
├── config/
│   ├── broadcasting.php             # Config connexions broadcast
│   └── reverb.php                   # Config serveur Reverb
├── routes/
│   └── channels.php                 # Autorisation channels prives
└── bootstrap/
    └── app.php                      # Enregistrement des channels

apps/web-vuejs/
├── src/
│   ├── lib/echo.ts                  # Client Echo (singleton)
│   ├── composables/useOrderBook.ts  # Composable reactif
│   ├── views/OrderBookPage.vue      # Page OrderBook
│   ├── router/index.ts              # Route /dashboard/orderbook
│   └── components/NavMain.vue       # Lien dans la navigation

apps/web/
├── src/
│   ├── lib/echo.ts                  # Client Echo (singleton)
│   ├── hooks/use-orderbook.ts       # Hook React
│   ├── components/dashboard/
│   │   └── orderbook-view.tsx       # Composant OrderBook
│   ├── app/dashboard/orderbook/
│   │   └── page.tsx                 # Page Next.js
│   └── components/app-sidebar.tsx   # Lien dans la sidebar
```

---

## Concepts cles

### Pourquoi Reverb et pas Pusher ?

| | Reverb | Pusher |
|---|---|---|
| **Hebergement** | Self-hosted | Cloud (SaaS) |
| **Cout** | Gratuit | Payant au-dela du free tier |
| **Protocole** | Compatible Pusher | Pusher natif |
| **Latence** | Locale (meme serveur) | Reseau externe |
| **Controle** | Total | Limite |

Reverb utilise le **meme protocole** que Pusher, donc `laravel-echo` + `pusher-js` fonctionnent sans modification.

### Pourquoi `ShouldBroadcastNow` et pas `ShouldBroadcast` ?

- `ShouldBroadcast` passe par la **queue** Laravel (Redis, database, etc.)
- `ShouldBroadcastNow` broadcast **immediatement** dans le process courant
- Pour du temps reel a haute frequence (order book), la queue ajouterait une latence inutile

### Pourquoi un channel public ?

- Les donnees de l'order book sont **publiques** (disponibles sur Binance sans auth)
- Pas besoin de proteger ces donnees
- Un channel prive necessiterait une authentification supplementaire sans benefice

### Le throttling

Binance envoie des updates toutes les **100ms** (10/seconde). Le throttle par defaut est a **1000ms** (1/seconde) :
- Reduit la charge sur Reverb et les clients
- 1 update/seconde est suffisant pour l'affichage
- Configurable via `--throttle` pour ajuster selon les besoins

### Le point (`.`) devant le nom d'event

Quand un event Laravel utilise `broadcastAs()` pour definir un nom custom, il faut prefixer avec `.` cote client :

```typescript
// Sans broadcastAs() → Laravel ajoute le namespace complet
echo.channel('orderbook').listen('App\\Events\\OrderBookUpdated', ...)

// Avec broadcastAs() → Prefixer avec . pour utiliser le nom custom
echo.channel('orderbook').listen('.OrderBookUpdated', ...)
```

---

## Troubleshooting

### "Cannot reach Reverb"

```
Make sure Reverb is running: make dev-reverb
```

→ Lancer Reverb avant la commande orderbook.

### Pas de donnees affichees

1. Verifier que Reverb tourne : `make dev-reverb`
2. Verifier que le stream tourne : `make dev-orderbook`
3. Verifier les variables d'env (meme `REVERB_APP_KEY` partout)
4. Ouvrir la console du navigateur pour voir les erreurs WebSocket

### Connexion WebSocket echoue

- Verifier que le port 8080 n'est pas bloque par un firewall
- Verifier `VITE_REVERB_HOST` / `NEXT_PUBLIC_REVERB_HOST` = `localhost`
- Verifier que `forceTLS: false` est bien configure en dev

### Binance WebSocket se deconnecte

- Normal apres ~24h (limite Binance) → reconnexion automatique
- En cas d'erreur reseau → backoff exponentiel jusqu'a 30s
