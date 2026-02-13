<script setup lang="ts">
import AppSidebar from '@/components/AppSidebar.vue'
import SiteHeader from '@/components/SiteHeader.vue'
import {
  SidebarInset,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { useOrderBook, type OrderBookEntry } from '@/composables/useOrderBook'
import { computed } from 'vue'

const { data, isConnected, error } = useOrderBook()

function formatPrice(price: string): string {
  return parseFloat(price).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })
}

function formatQty(qty: string): string {
  return parseFloat(qty).toFixed(5)
}

function formatTotal(entry: OrderBookEntry): string {
  return (parseFloat(entry.price) * parseFloat(entry.qty)).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })
}

const spread = computed(() => {
  const d = data.value
  const bestAsk = d?.asks[0]
  const bestBid = d?.bids[0]
  if (!bestAsk || !bestBid) return null
  return parseFloat(bestAsk.price) - parseFloat(bestBid.price)
})
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <SiteHeader />
      <div class="flex flex-1 flex-col gap-4 py-4 md:gap-6 md:py-6">
        <!-- Header -->
        <div class="flex items-center justify-between px-4 lg:px-6">
          <div>
            <h2 class="text-2xl font-bold tracking-tight">BTC/USDT</h2>
            <p class="text-sm text-muted-foreground">
              Real-time order book from Binance
            </p>
          </div>
          <div class="flex items-center gap-2">
            <Badge v-if="error" variant="destructive">Error</Badge>
            <Badge v-else-if="isConnected && data" class="bg-emerald-600 hover:bg-emerald-700 text-white">
              <span class="mr-1.5 inline-block h-2 w-2 animate-pulse rounded-full bg-white" />
              Live
            </Badge>
            <Badge v-else variant="secondary">
              <span class="mr-1.5 inline-block h-2 w-2 animate-pulse rounded-full bg-yellow-400" />
              Connecting
            </Badge>
          </div>
        </div>

        <!-- Error -->
        <div v-if="error" class="px-4 lg:px-6">
          <Card class="border-destructive">
            <CardContent class="pt-6">
              <p class="text-sm text-destructive">{{ error }}</p>
            </CardContent>
          </Card>
        </div>

        <!-- Order Book Grid -->
        <div class="grid gap-4 px-4 md:grid-cols-2 lg:px-6">
          <!-- Bids -->
          <Card>
            <CardHeader class="pb-3">
              <CardTitle class="text-emerald-500">Bids (Buy)</CardTitle>
            </CardHeader>
            <CardContent class="p-0">
              <template v-if="data">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead class="text-right">Price (USDT)</TableHead>
                      <TableHead class="text-right">Qty (BTC)</TableHead>
                      <TableHead class="text-right">Total (USDT)</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    <TableRow v-for="(entry, i) in data.bids" :key="i" class="font-mono text-xs">
                      <TableCell class="text-right text-emerald-500">
                        {{ formatPrice(entry.price) }}
                      </TableCell>
                      <TableCell class="text-right">{{ formatQty(entry.qty) }}</TableCell>
                      <TableCell class="text-right text-muted-foreground">
                        {{ formatTotal(entry) }}
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </template>
              <div v-else class="space-y-2 p-4">
                <Skeleton v-for="i in 10" :key="i" class="h-6 w-full" />
              </div>
            </CardContent>
          </Card>

          <!-- Asks -->
          <Card>
            <CardHeader class="pb-3">
              <CardTitle class="text-red-500">Asks (Sell)</CardTitle>
            </CardHeader>
            <CardContent class="p-0">
              <template v-if="data">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead class="text-right">Price (USDT)</TableHead>
                      <TableHead class="text-right">Qty (BTC)</TableHead>
                      <TableHead class="text-right">Total (USDT)</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    <TableRow v-for="(entry, i) in data.asks" :key="i" class="font-mono text-xs">
                      <TableCell class="text-right text-red-500">
                        {{ formatPrice(entry.price) }}
                      </TableCell>
                      <TableCell class="text-right">{{ formatQty(entry.qty) }}</TableCell>
                      <TableCell class="text-right text-muted-foreground">
                        {{ formatTotal(entry) }}
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </template>
              <div v-else class="space-y-2 p-4">
                <Skeleton v-for="i in 10" :key="i" class="h-6 w-full" />
              </div>
            </CardContent>
          </Card>
        </div>

        <!-- Spread -->
        <div v-if="spread !== null" class="px-4 lg:px-6">
          <Card>
            <CardContent class="flex items-center justify-between py-3">
              <span class="text-sm font-medium text-muted-foreground">Spread</span>
              <span class="font-mono text-sm font-semibold">
                {{ formatPrice(spread.toString()) }} USDT
              </span>
            </CardContent>
          </Card>
        </div>
      </div>
    </SidebarInset>
  </SidebarProvider>
</template>
