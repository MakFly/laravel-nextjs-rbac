'use client';

import { useAuthStore } from '@/stores/auth-store';
import { SiteHeaderClient } from '@/components/site-header-client';
import { redirect } from 'next/navigation';
import { Skeleton } from '@/components/ui/skeleton';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
  DatabaseIcon,
  ServerIcon,
  RefreshCwIcon,
  Trash2Icon,
  CheckCircleIcon,
  XCircleIcon,
  AlertTriangleIcon,
  ZapIcon,
} from 'lucide-react';
import { useEffect, useState, useTransition } from 'react';
import {
  getCacheDebugAction,
  warmupCacheAction,
  invalidateCacheAction,
  type CacheDebugData,
} from '@/lib/api/cache-debug';

export default function CacheDebugPage() {
  const { user, isHydrated } = useAuthStore();
  const [cacheData, setCacheData] = useState<CacheDebugData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);

  const fetchCacheData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await getCacheDebugAction();
      setCacheData(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch cache data');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isHydrated && user) {
      fetchCacheData();
    }
  }, [isHydrated, user]);

  const handleWarmup = () => {
    startTransition(async () => {
      setMessage(null);
      try {
        const response = await warmupCacheAction();
        setCacheData(response.data);
        setMessage(response.message);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Warmup failed');
      }
    });
  };

  const handleInvalidate = () => {
    startTransition(async () => {
      setMessage(null);
      try {
        const response = await invalidateCacheAction();
        setCacheData(response.data);
        setMessage(response.message);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Invalidation failed');
      }
    });
  };

  if (!isHydrated) {
    return (
      <>
        <div className="flex h-16 items-center gap-2 border-b px-4">
          <Skeleton className="h-8 w-8" />
          <Skeleton className="h-4 w-32" />
        </div>
        <div className="p-6 space-y-6">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-64 rounded-xl" />
        </div>
      </>
    );
  }

  if (!user) {
    redirect('/auth/login');
  }

  const formatTtl = (seconds: number | null) => {
    if (seconds === null) return 'N/A';
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}min`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return `${Math.floor(seconds / 86400)}d`;
  };

  const getKeyStatus = (exists: boolean, data: unknown) => {
    if (!exists) return { icon: XCircleIcon, color: 'text-red-500', label: 'MISS' };
    if (data) return { icon: CheckCircleIcon, color: 'text-green-500', label: 'HIT' };
    return { icon: AlertTriangleIcon, color: 'text-yellow-500', label: 'EMPTY' };
  };

  const hasDiff =
    cacheData?.diff.in_cache_only.length ||
    cacheData?.diff.in_db_only.length ||
    cacheData?.diff.different.length;

  return (
    <>
      <SiteHeaderClient title="Cache Debug" subtitle="Visualisation du cache Redis" />
      <div className="flex flex-1 flex-col gap-6 p-4 pt-0 max-w-5xl">
        {/* Actions */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ZapIcon className="h-5 w-5" />
              Actions
            </CardTitle>
            <CardDescription>Controler le cache pour l'utilisateur connecte</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <Button
                onClick={fetchCacheData}
                disabled={isLoading || isPending}
                variant="outline"
                className="flex items-center gap-2"
              >
                <RefreshCwIcon className={`h-4 w-4 ${isLoading || isPending ? 'animate-spin' : ''}`} />
                Rafraichir
              </Button>
              <Button
                onClick={handleWarmup}
                disabled={isLoading || isPending}
                className="flex items-center gap-2 bg-gradient-to-r from-green-600 to-emerald-600"
              >
                <DatabaseIcon className="h-4 w-4" />
                Warmup
              </Button>
              <Button
                onClick={handleInvalidate}
                disabled={isLoading || isPending}
                variant="destructive"
                className="flex items-center gap-2"
              >
                <Trash2Icon className="h-4 w-4" />
                Invalider
              </Button>
            </div>

            {message && (
              <div className="mt-4 p-3 rounded-lg bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                {message}
              </div>
            )}
            {error && (
              <div className="mt-4 p-3 rounded-lg bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">
                {error}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Cache Keys */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ServerIcon className="h-5 w-5" />
              Cles Redis
            </CardTitle>
            <CardDescription>Etat des cles en cache pour l'utilisateur #{cacheData?.user_id}</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-20 w-full" />
                ))}
              </div>
            ) : cacheData ? (
              <div className="space-y-4">
                {Object.entries(cacheData.keys).map(([key, info]) => {
                  const status = getKeyStatus(info.exists, info.data);
                  const StatusIcon = status.icon;
                  return (
                    <div
                      key={key}
                      className="p-4 rounded-lg border bg-muted/30 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <StatusIcon className={`h-5 w-5 ${status.color}`} />
                          <code className="text-sm font-mono">{info.key}</code>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={info.exists ? 'default' : 'secondary'}>
                            {status.label}
                          </Badge>
                          {info.ttl_seconds !== null && (
                            <Badge variant="outline">TTL: {formatTtl(info.ttl_seconds)}</Badge>
                          )}
                        </div>
                      </div>
                      {info.data && (
                        <pre className="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-32">
                          {JSON.stringify(info.data, null, 2)}
                        </pre>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-muted-foreground">Aucune donnee disponible</p>
            )}
          </CardContent>
        </Card>

        {/* Diff Analysis */}
        {cacheData && hasDiff > 0 && (
          <Card className="border-yellow-200">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-yellow-600">
                <AlertTriangleIcon className="h-5 w-5" />
                Differences detectees
              </CardTitle>
              <CardDescription>Ecarts entre le cache et la base de donnees</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-3">
                <div className="p-4 rounded-lg bg-blue-50 dark:bg-blue-900/20">
                  <p className="font-medium text-blue-700 dark:text-blue-400">Cache uniquement</p>
                  <ul className="mt-2 space-y-1">
                    {cacheData.diff.in_cache_only.map((item) => (
                      <li key={item} className="text-sm text-blue-600 dark:text-blue-300">
                        - {item}
                      </li>
                    ))}
                    {cacheData.diff.in_cache_only.length === 0 && (
                      <li className="text-sm text-muted-foreground">Aucun</li>
                    )}
                  </ul>
                </div>
                <div className="p-4 rounded-lg bg-orange-50 dark:bg-orange-900/20">
                  <p className="font-medium text-orange-700 dark:text-orange-400">DB uniquement</p>
                  <ul className="mt-2 space-y-1">
                    {cacheData.diff.in_db_only.map((item) => (
                      <li key={item} className="text-sm text-orange-600 dark:text-orange-300">
                        - {item}
                      </li>
                    ))}
                    {cacheData.diff.in_db_only.length === 0 && (
                      <li className="text-sm text-muted-foreground">Aucun</li>
                    )}
                  </ul>
                </div>
                <div className="p-4 rounded-lg bg-red-50 dark:bg-red-900/20">
                  <p className="font-medium text-red-700 dark:text-red-400">Valeurs differentes</p>
                  <ul className="mt-2 space-y-1">
                    {cacheData.diff.different.map((item) => (
                      <li key={item} className="text-sm text-red-600 dark:text-red-300">
                        - {item}
                      </li>
                    ))}
                    {cacheData.diff.different.length === 0 && (
                      <li className="text-sm text-muted-foreground">Aucun</li>
                    )}
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Database State */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <DatabaseIcon className="h-5 w-5" />
              Etat de la base de donnees
            </CardTitle>
            <CardDescription>Donnees persistees en base</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-32 w-full" />
            ) : cacheData?.database ? (
              <div className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div>
                    <h4 className="font-medium mb-2">User</h4>
                    {cacheData.database.user ? (
                      <pre className="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24">
                        {JSON.stringify(cacheData.database.user, null, 2)}
                      </pre>
                    ) : (
                      <p className="text-sm text-muted-foreground">Non trouve</p>
                    )}
                  </div>
                  <div>
                    <h4 className="font-medium mb-2">Draft</h4>
                    {cacheData.database.draft ? (
                      <pre className="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24">
                        {JSON.stringify(cacheData.database.draft, null, 2)}
                      </pre>
                    ) : (
                      <p className="text-sm text-muted-foreground">Aucun draft</p>
                    )}
                  </div>
                </div>
                <Separator />
                <div className="grid gap-4 md:grid-cols-2">
                  <div>
                    <h4 className="font-medium mb-2">KYC Profile</h4>
                    {cacheData.database.kyc_profile ? (
                      <pre className="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24">
                        {JSON.stringify(cacheData.database.kyc_profile, null, 2)}
                      </pre>
                    ) : (
                      <p className="text-sm text-muted-foreground">Non complete</p>
                    )}
                  </div>
                  <div>
                    <h4 className="font-medium mb-2">User Operation</h4>
                    {cacheData.database.user_operation ? (
                      <pre className="text-xs bg-black/5 dark:bg-white/5 p-2 rounded overflow-auto max-h-24">
                        {JSON.stringify(cacheData.database.user_operation, null, 2)}
                      </pre>
                    ) : (
                      <p className="text-sm text-muted-foreground">Non configure</p>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-muted-foreground">Aucune donnee disponible</p>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
