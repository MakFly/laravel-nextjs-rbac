'use client';

import { useAuthStore } from '@/stores/auth-store';
import { SiteHeaderClient } from '@/components/site-header-client';
import { redirect } from 'next/navigation';
import { Skeleton } from '@/components/ui/skeleton';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ShieldIcon } from 'lucide-react';

export default function PermissionsPage() {
  const { user, isHydrated } = useAuthStore();

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
              <Skeleton key={i} className="h-24 rounded-xl" />
            ))}
          </div>
        </div>
      </>
    );
  }

  if (!user) {
    redirect('/auth/login');
  }

  // Grouper les permissions par ressource
  const permissionsByResource = user.permissions.reduce((acc, permission) => {
    if (!acc[permission.resource]) {
      acc[permission.resource] = [];
    }
    acc[permission.resource].push(permission);
    return acc;
  }, {} as Record<string, typeof user.permissions>);

  return (
    <>
      <SiteHeaderClient
        title="Permissions"
        subtitle="Vos permissions d'accès"
      />
      <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
        <div className="grid gap-4">
          {Object.entries(permissionsByResource).length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <ShieldIcon className="h-12 w-12 text-muted-foreground mb-4" />
                <p className="text-muted-foreground">Aucune permission assignée</p>
              </CardContent>
            </Card>
          ) : (
            Object.entries(permissionsByResource).map(([resource, permissions]) => (
              <Card key={resource}>
                <CardHeader>
                  <CardTitle className="capitalize">{resource}</CardTitle>
                  <CardDescription>
                    {permissions.length} permission{permissions.length > 1 ? 's' : ''}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {permissions.map((permission) => (
                      <Badge
                        key={permission.id}
                        variant="secondary"
                        className="px-3 py-1"
                      >
                        {permission.action}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Résumé des rôles */}
        <Card>
          <CardHeader>
            <CardTitle>Vos rôles</CardTitle>
            <CardDescription>
              Les rôles déterminent vos permissions
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {user.roles.map((role) => (
                <Badge
                  key={role.id}
                  className="px-4 py-2 bg-gradient-to-r from-violet-600 to-indigo-600"
                >
                  {role.name}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
