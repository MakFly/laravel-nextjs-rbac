# Tilvest - Instructions Claude

## Stack technique

- **Framework**: Vue 3 + TypeScript
- **Build**: Vite + Bun
- **UI**: shadcn-vue (Tailwind CSS v4)
- **Charts**: @unovis/vue
- **Tables**: @tanstack/vue-table
- **Router**: vue-router
- **State**: Pinia

## Commandes

```bash
bun install      # Installer les dépendances
bun run build    # Build production
bun run preview  # Preview du build
```

## Problèmes connus et solutions

### Performance des charts Unovis avec sidebar

**Problème**: Latence importante lors de l'ouverture/fermeture de la sidebar causée par le ResizeObserver d'Unovis qui se déclenche à chaque frame de la transition.

**Solution**: Utiliser `Sizing.Extend` et `duration={0}` sur les composants `VisXYContainer` :

```vue
<script setup>
import { Sizing } from "@unovis/ts"
</script>

<template>
  <VisXYContainer
    :duration="0"
    :sizing="Sizing.Extend"
  >
    <!-- ... -->
  </VisXYContainer>
</template>
```

### Scroll horizontal avec sidebar

**Problème**: Scroll horizontal indésirable quand la sidebar est ouverte.

**Solution**: Les composants `SidebarProvider` et `SidebarInset` doivent avoir :
- `SidebarProvider`: `overflow-hidden`
- `SidebarInset`: `min-w-0 overflow-x-hidden`

## Structure du projet

```
src/
├── components/
│   ├── ui/           # Composants shadcn-vue
│   └── *.vue         # Composants métier
├── views/            # Pages
├── stores/           # Stores Pinia
├── router/           # Configuration routes
└── style.css         # Styles globaux + variables CSS
```
