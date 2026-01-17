'use client';

import { useAuthStore } from '@/stores/auth-store';
import { SiteHeaderClient } from '@/components/site-header-client';
import { redirect } from 'next/navigation';
import { Skeleton } from '@/components/ui/skeleton';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ShieldIcon, KeyIcon } from 'lucide-react';

export default function RolePermissionsPage() {
  const { user, isHydrated, isAdmin } = useAuthStore();

  if (!isHydrated) {
    return (
      <>
        <div className="flex h-16 items-center gap-2 border-b px-4">
          <Skeleton className="h-8 w-8" />
          <Skeleton className="h-4 w-32" />
        </div>
        <div className="p-6 space-y-6">
          <Skeleton className="h-8 w-48" />
          <div className="grid gap-4">
            {[...Array(3)].map((_, i) => (
              <Skeleton key={i} className="h-32 rounded-xl" />
            ))}
          </div>
        </div>
      </>
    );
  }

  if (!user) {
    redirect('/auth/login');
  }

  if (!isAdmin()) {
    return (
      <>
        <SiteHeaderClient title="Role Permissions" />
        <div className="flex flex-1 flex-col items-center justify-center gap-4 p-4">
          <ShieldIcon className="h-16 w-16 text-muted-foreground" />
          <h2 className="text-xl font-semibold">Accès refusé</h2>
          <p className="text-muted-foreground">
            Vous devez être administrateur pour accéder à cette page.
          </p>
        </div>
      </>
    );
  }

  return (
    <>
      <SiteHeaderClient
        title="Role Permissions"
        subtitle="Gérer les permissions par rôle"
      />
      <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyIcon className="h-5 w-5" />
              Matrice des permissions
            </CardTitle>
            <CardDescription>
              Vue d'ensemble des permissions assignées à chaque rôle
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-center py-8 text-muted-foreground">
              <ShieldIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>La matrice des permissions sera disponible prochainement.</p>
              <p className="text-sm mt-2">
                Cette fonctionnalité permet de visualiser et modifier les permissions de chaque rôle.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Aperçu des rôles existants */}
        <Card>
          <CardHeader>
            <CardTitle>Rôles du système</CardTitle>
            <CardDescription>
              Les rôles disponibles dans l'application
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <Badge variant="destructive" className="px-4 py-2">
                Admin
              </Badge>
              <Badge variant="secondary" className="px-4 py-2 bg-amber-100 text-amber-800">
                Moderator
              </Badge>
              <Badge variant="secondary" className="px-4 py-2">
                User
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
