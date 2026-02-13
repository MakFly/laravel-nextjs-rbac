'use client';

import { useOrderBook, type OrderBookEntry } from '@/hooks/use-orderbook';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';

function formatPrice(price: string): string {
  return parseFloat(price).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function formatQty(qty: string): string {
  return parseFloat(qty).toFixed(5);
}

function formatTotal(price: string, qty: string): string {
  return (parseFloat(price) * parseFloat(qty)).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function OrderBookTable({
  entries,
  side,
}: {
  entries: OrderBookEntry[];
  side: 'bid' | 'ask';
}) {
  const colorClass = side === 'bid' ? 'text-emerald-500' : 'text-red-500';

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="text-right">Price (USDT)</TableHead>
          <TableHead className="text-right">Qty (BTC)</TableHead>
          <TableHead className="text-right">Total (USDT)</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {entries.map((entry, i) => (
          <TableRow key={i} className="font-mono text-xs">
            <TableCell className={`text-right ${colorClass}`}>
              {formatPrice(entry.price)}
            </TableCell>
            <TableCell className="text-right">{formatQty(entry.qty)}</TableCell>
            <TableCell className="text-right text-muted-foreground">
              {formatTotal(entry.price, entry.qty)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function SkeletonTable() {
  return (
    <div className="space-y-2 p-4">
      {[...Array(10)].map((_, i) => (
        <Skeleton key={i} className="h-6 w-full" />
      ))}
    </div>
  );
}

export function OrderBookView() {
  const { data, isConnected, error } = useOrderBook();

  const spread =
    data && data.asks.length > 0 && data.bids.length > 0
      ? parseFloat(data.asks[0].price) - parseFloat(data.bids[0].price)
      : null;

  return (
    <div className="flex flex-col gap-4 px-4 lg:px-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">BTC/USDT</h2>
          <p className="text-sm text-muted-foreground">
            Real-time order book from Binance
          </p>
        </div>
        <div className="flex items-center gap-2">
          {error ? (
            <Badge variant="destructive">Error</Badge>
          ) : isConnected && data ? (
            <Badge variant="default" className="bg-emerald-600 hover:bg-emerald-700">
              <span className="mr-1.5 inline-block h-2 w-2 animate-pulse rounded-full bg-white" />
              Live
            </Badge>
          ) : (
            <Badge variant="secondary">
              <span className="mr-1.5 inline-block h-2 w-2 animate-pulse rounded-full bg-yellow-400" />
              Connecting
            </Badge>
          )}
        </div>
      </div>

      {error && (
        <Card className="border-destructive">
          <CardContent className="pt-6">
            <p className="text-sm text-destructive">{error}</p>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-emerald-500">Bids (Buy)</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {data ? (
              <OrderBookTable entries={data.bids} side="bid" />
            ) : (
              <SkeletonTable />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-red-500">Asks (Sell)</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {data ? (
              <OrderBookTable entries={data.asks} side="ask" />
            ) : (
              <SkeletonTable />
            )}
          </CardContent>
        </Card>
      </div>

      {spread !== null && (
        <Card>
          <CardContent className="flex items-center justify-between py-3">
            <span className="text-sm font-medium text-muted-foreground">Spread</span>
            <span className="font-mono text-sm font-semibold">
              {formatPrice(spread.toString())} USDT
            </span>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
