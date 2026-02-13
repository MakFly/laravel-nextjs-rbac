<script setup lang="ts">
import AppSidebar from '@/components/AppSidebar.vue'
import SiteHeader from '@/components/SiteHeader.vue'
import {
  SidebarInset,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import {
  Database as DatabaseIcon,
  Server as ServerIcon,
  RefreshCw as RefreshCwIcon,
  Trash2 as Trash2Icon,
  CheckCircle as CheckCircleIcon,
  XCircle as XCircleIcon,
  AlertTriangle as AlertTriangleIcon,
  Zap as ZapIcon,
} from 'lucide-vue-next'
import { ref, computed, onMounted } from 'vue'
import {
  getCacheDebug,
  warmupCache,
  invalidateCache,
  type CacheDebugData,
} from '@/lib/api/cache-debug'

const cacheData = ref<CacheDebugData | null>(null)
const isLoading = ref(true)
const isPending = ref(false)
const error = ref<string | null>(null)
const message = ref<string | null>(null)

const fetchCacheData = async () => {
  isLoading.value = true
  error.value = null
  try {
    const response = await getCacheDebug()
    cacheData.value = response.data
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to fetch cache data'
  } finally {
    isLoading.value = false
  }
}

const handleWarmup = async () => {
  isPending.value = true
  message.value = null
  try {
    const response = await warmupCache()
    cacheData.value = response.data
    message.value = response.message
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Warmup failed'
  } finally {
    isPending.value = false
  }
}

const handleInvalidate = async () => {
  isPending.value = true
  message.value = null
  try {
    const response = await invalidateCache()
    cacheData.value = response.data
    message.value = response.message
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Invalidation failed'
  } finally {
    isPending.value = false
  }
}

const formatTtl = (seconds: number | null) => {
  if (seconds === null) return 'N/A'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}min`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

const getKeyStatus = (exists: boolean, data: unknown) => {
  if (!exists) return { icon: XCircleIcon, color: 'text-red-500', label: 'MISS' }
  if (data) return { icon: CheckCircleIcon, color: 'text-green-500', label: 'HIT' }
  return { icon: AlertTriangleIcon, color: 'text-yellow-500', label: 'EMPTY' }
}

const hasDiff = computed(() => {
  if (!cacheData.value) return false
  return (
    cacheData.value.diff.in_cache_only.length ||
    cacheData.value.diff.in_db_only.length ||
    cacheData.value.diff.different.length
  )
})

onMounted(() => {
  fetchCacheData()
})
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <SiteHeader title="Cache Debug" subtitle="Visualisation du cache Redis" />
      <div class="flex flex-1 flex-col gap-6 p-4 pt-0 max-w-5xl">
        <!-- Actions -->
        <Card>
          <CardHeader>
            <CardTitle class="flex items-center gap-2">
              <ZapIcon class="h-5 w-5" />
              Actions
            </CardTitle>
            <CardDescription>Controler le cache pour l'utilisateur connecte</CardDescription>
          </CardHeader>
          <CardContent>
            <div class="flex items-center gap-4">
              <Button
                @click="fetchCacheData"
                :disabled="isLoading || isPending"
                variant="outline"
                class="flex items-center gap-2"
              >
                <RefreshCwIcon :class="['h-4 w-4', { 'animate-spin': isLoading || isPending }]" />
                Rafraichir
              </Button>
              <Button
                @click="handleWarmup"
                :disabled="isLoading || isPending"
                class="flex items-center gap-2 bg-gradient-to-r from-green-600 to-emerald-600"
              >
                <DatabaseIcon class="h-4 w-4" />
                Warmup
              </Button>
              <Button
                @click="handleInvalidate"
                :disabled="isLoading || isPending"
                variant="destructive"
                class="flex items-center gap-2"
              >
                <Trash2Icon class="h-4 w-4" />
                Invalider
              </Button>
            </div>

            <div
              v-if="message"
              class="mt-4 p-3 rounded-lg bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
            >
              {{ message }}
            </div>
            <div
              v-if="error"
              class="mt-4 p-3 rounded-lg bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
            >
              {{ error }}
            </div>
          </CardContent>
        </Card>

        <!-- Cache Keys -->
        <Card>
          <CardHeader>
            <CardTitle class="flex items-center gap-2">
              <ServerIcon class="h-5 w-5" />
              Cles Redis
            </CardTitle>
            <CardDescription>
              Etat des cles en cache pour l'utilisateur #{{ cacheData?.user_id }}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div v-if="isLoading" class="space-y-4">
              <div v-for="i in 3" :key="i" class="h-20 w-full bg-muted animate-pulse rounded" />
            </div>
            <div v-else-if="cacheData" class="space-y-4">
              <div
                v-for="(info, key) in cacheData.keys"
                :key="key"
                class="p-4 rounded-lg border bg-muted/30 space-y-2"
              >
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <component
                      :is="getKeyStatus(info.exists, info.data).icon"
                      :class="['h-5 w-5', getKeyStatus(info.exists, info.data).color]"
                    />
                    <code class="text-sm font-mono">{{ info.key }}</code>
                  </div>
                  <div class="flex items-center gap-2">
                    <Badge :variant="info.exists ? 'default' : 'secondary'">
                      {{ getKeyStatus(info.exists, info.data).label }}
                    </Badge>
                    <Badge v-if="info.ttl_seconds !== null" variant="outline">
                      TTL: {{ formatTtl(info.ttl_seconds) }}
                    </Badge>
                  </div>
                </div>
                <pre
                  v-if="info.data"
                  class="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-32"
                >{{ JSON.stringify(info.data, null, 2) }}</pre>
              </div>
            </div>
            <p v-else class="text-muted-foreground">Aucune donnee disponible</p>
          </CardContent>
        </Card>

        <!-- Diff Analysis -->
        <Card v-if="cacheData && hasDiff" class="border-yellow-200">
          <CardHeader>
            <CardTitle class="flex items-center gap-2 text-yellow-600">
              <AlertTriangleIcon class="h-5 w-5" />
              Differences detectees
            </CardTitle>
            <CardDescription>Ecarts entre le cache et la base de donnees</CardDescription>
          </CardHeader>
          <CardContent>
            <div class="grid gap-4 md:grid-cols-3">
              <div class="p-4 rounded-lg bg-blue-50 dark:bg-blue-900/20">
                <p class="font-medium text-blue-700 dark:text-blue-400">Cache uniquement</p>
                <ul class="mt-2 space-y-1">
                  <li
                    v-for="item in cacheData.diff.in_cache_only"
                    :key="item"
                    class="text-sm text-blue-600 dark:text-blue-300"
                  >
                    - {{ item }}
                  </li>
                  <li v-if="!cacheData.diff.in_cache_only.length" class="text-sm text-muted-foreground">
                    Aucun
                  </li>
                </ul>
              </div>
              <div class="p-4 rounded-lg bg-orange-50 dark:bg-orange-900/20">
                <p class="font-medium text-orange-700 dark:text-orange-400">DB uniquement</p>
                <ul class="mt-2 space-y-1">
                  <li
                    v-for="item in cacheData.diff.in_db_only"
                    :key="item"
                    class="text-sm text-orange-600 dark:text-orange-300"
                  >
                    - {{ item }}
                  </li>
                  <li v-if="!cacheData.diff.in_db_only.length" class="text-sm text-muted-foreground">
                    Aucun
                  </li>
                </ul>
              </div>
              <div class="p-4 rounded-lg bg-red-50 dark:bg-red-900/20">
                <p class="font-medium text-red-700 dark:text-red-400">Valeurs differentes</p>
                <ul class="mt-2 space-y-1">
                  <li
                    v-for="item in cacheData.diff.different"
                    :key="item"
                    class="text-sm text-red-600 dark:text-red-300"
                  >
                    - {{ item }}
                  </li>
                  <li v-if="!cacheData.diff.different.length" class="text-sm text-muted-foreground">
                    Aucun
                  </li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

        <!-- Database State -->
        <Card>
          <CardHeader>
            <CardTitle class="flex items-center gap-2">
              <DatabaseIcon class="h-5 w-5" />
              Etat de la base de donnees
            </CardTitle>
            <CardDescription>Donnees persistees en base</CardDescription>
          </CardHeader>
          <CardContent>
            <div v-if="isLoading" class="h-32 w-full bg-muted animate-pulse rounded" />
            <div v-else-if="cacheData?.database" class="space-y-4">
              <div class="grid gap-4 md:grid-cols-2">
                <div>
                  <h4 class="font-medium mb-2">User</h4>
                  <pre
                    v-if="cacheData.database.user"
                    class="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24"
                  >{{ JSON.stringify(cacheData.database.user, null, 2) }}</pre>
                  <p v-else class="text-sm text-muted-foreground">Non trouve</p>
                </div>
                <div>
                  <h4 class="font-medium mb-2">Draft</h4>
                  <pre
                    v-if="cacheData.database.draft"
                    class="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24"
                  >{{ JSON.stringify(cacheData.database.draft, null, 2) }}</pre>
                  <p v-else class="text-sm text-muted-foreground">Aucun draft</p>
                </div>
              </div>
              <Separator />
              <div class="grid gap-4 md:grid-cols-2">
                <div>
                  <h4 class="font-medium mb-2">KYC Profile</h4>
                  <pre
                    v-if="cacheData.database.kyc_profile"
                    class="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24"
                  >{{ JSON.stringify(cacheData.database.kyc_profile, null, 2) }}</pre>
                  <p v-else class="text-sm text-muted-foreground">Non complete</p>
                </div>
                <div>
                  <h4 class="font-medium mb-2">User Operation</h4>
                  <pre
                    v-if="cacheData.database.user_operation"
                    class="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24"
                  >{{ JSON.stringify(cacheData.database.user_operation, null, 2) }}</pre>
                  <p v-else class="text-sm text-muted-foreground">Non configure</p>
                </div>
              </div>
            </div>
            <p v-else class="text-muted-foreground">Aucune donnee disponible</p>
          </CardContent>
        </Card>
      </div>
    </SidebarInset>
  </SidebarProvider>
</template>
