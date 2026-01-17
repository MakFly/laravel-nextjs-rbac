import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  ShieldIcon,
  UserIcon,
  KeyIcon,
  CheckCircleIcon,
  XCircleIcon,
  UsersIcon,
  SettingsIcon,
  FileTextIcon,
} from 'lucide-react';
import { hasPermission, isAdmin } from '@rbac/types';
import type { User } from '@rbac/types';

interface DashboardContentProps {
  user: User;
}

const getPermissionColor = (action: string) => {
  switch (action) {
    case 'manage':
      return 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300';
    case 'delete':
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
    case 'create':
      return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
    case 'update':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300';
    case 'read':
      return 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';
    default:
      return 'bg-gray-100 text-gray-700';
  }
};

const getRoleColor = (slug: string) => {
  switch (slug) {
    case 'admin':
      return 'bg-gradient-to-r from-red-500 to-pink-500 text-white border-0';
    case 'moderator':
      return 'bg-gradient-to-r from-amber-500 to-orange-500 text-white border-0';
    case 'user':
      return 'bg-gradient-to-r from-blue-500 to-indigo-500 text-white border-0';
    default:
      return 'bg-gradient-to-r from-slate-500 to-slate-600 text-white border-0';
  }
};

/**
 * Dashboard Content - Server Component
 */
export function DashboardContent({ user }: DashboardContentProps) {
  const userIsAdmin = isAdmin(user);

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const accountAgeDays = Math.floor(
    (Date.now() - new Date(user.created_at).getTime()) / (1000 * 60 * 60 * 24)
  );

  return (
    <div className="flex flex-1 flex-col gap-4 p-4 pt-6 md:p-8">
      {/* Quick Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="relative overflow-hidden group hover:shadow-lg transition-all duration-300">
          <div className="absolute inset-0 bg-gradient-to-br from-violet-500/10 to-indigo-500/10 opacity-0 group-hover:opacity-100 transition-opacity" />
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Profile</CardTitle>
            <UserIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-3">
              <Avatar className="h-10 w-10">
                <AvatarFallback className="bg-gradient-to-br from-violet-600 to-indigo-600 text-white text-xs font-semibold">
                  {getInitials(user.name)}
                </AvatarFallback>
              </Avatar>
              <div className="space-y-0.5">
                <p className="text-sm font-medium leading-none">{user.name}</p>
                <p className="text-xs text-muted-foreground">{user.email}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden group hover:shadow-lg transition-all duration-300">
          <div className="absolute inset-0 bg-gradient-to-br from-violet-500/10 to-indigo-500/10 opacity-0 group-hover:opacity-100 transition-opacity" />
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Roles</CardTitle>
            <ShieldIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{user.roles.length}</div>
            <p className="text-xs text-muted-foreground">Active roles</p>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden group hover:shadow-lg transition-all duration-300">
          <div className="absolute inset-0 bg-gradient-to-br from-violet-500/10 to-indigo-500/10 opacity-0 group-hover:opacity-100 transition-opacity" />
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Permissions</CardTitle>
            <KeyIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{user.permissions.length}</div>
            <p className="text-xs text-muted-foreground">Granted permissions</p>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden group hover:shadow-lg transition-all duration-300">
          <div className="absolute inset-0 bg-gradient-to-br from-violet-500/10 to-indigo-500/10 opacity-0 group-hover:opacity-100 transition-opacity" />
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Account Age</CardTitle>
            <SettingsIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{accountAgeDays}</div>
            <p className="text-xs text-muted-foreground">Days member</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* Roles Card */}
        <Card className="hover:shadow-lg transition-all duration-300">
          <CardHeader>
            <CardTitle>Your Roles</CardTitle>
            <CardDescription>Assigned roles and their associated permissions</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {user.roles.map((role) => (
              <div
                key={role.id}
                className="flex items-center justify-between p-3 rounded-lg border bg-muted/50"
              >
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-violet-100 to-indigo-100 flex items-center justify-center">
                    <ShieldIcon className="h-5 w-5 text-violet-700" />
                  </div>
                  <div>
                    <p className="font-medium">{role.name}</p>
                    <p className="text-xs text-muted-foreground capitalize">{role.slug}</p>
                  </div>
                </div>
                <Badge className={getRoleColor(role.slug)}>{role.name}</Badge>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Access Checks Card */}
        <Card className="hover:shadow-lg transition-all duration-300">
          <CardHeader>
            <CardTitle>Access Checks</CardTitle>
            <CardDescription>Real-time permission verification</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <AccessCheckRow
                label="Administrator Access"
                hasAccess={userIsAdmin}
              />
              <AccessCheckRow
                label="Read Posts"
                hasAccess={hasPermission(user, 'posts', 'read')}
              />
              <AccessCheckRow
                label="Create Posts"
                hasAccess={hasPermission(user, 'posts', 'create')}
              />
              <AccessCheckRow
                label="Manage Users"
                hasAccess={hasPermission(user, 'users', 'manage')}
              />
              <AccessCheckRow
                label="API Access"
                hasAccess={hasPermission(user, 'api', 'manage')}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Admin Section */}
      {userIsAdmin && (
        <Card className="relative overflow-hidden hover:shadow-lg transition-all duration-300">
          <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-pink-500/5" />
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Admin Section</CardTitle>
                <CardDescription>
                  Restricted area - Administrator access required
                </CardDescription>
              </div>
              <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-red-500 to-pink-500 flex items-center justify-center">
                <ShieldIcon className="h-6 w-6 text-white" />
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground mb-6">
              You have administrator privileges. You can manage users, roles, and system settings.
            </p>
            <div className="flex flex-wrap gap-3">
              <Button
                asChild
                className="bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700"
              >
                <a href="/dashboard/users">
                  <UsersIcon className="mr-2 h-4 w-4" />
                  Manage Users
                </a>
              </Button>
              <Button asChild variant="outline">
                <a href="/dashboard/roles">
                  <ShieldIcon className="mr-2 h-4 w-4" />
                  Manage Roles
                </a>
              </Button>
              <Button asChild variant="outline">
                <a href="/dashboard/posts">
                  <FileTextIcon className="mr-2 h-4 w-4" />
                  View Posts
                </a>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Permissions Table */}
      <Card className="hover:shadow-lg transition-all duration-300">
        <CardHeader>
          <CardTitle>All Permissions</CardTitle>
          <CardDescription>Complete list of your granted permissions</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Permission</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {user.permissions.map((perm) => (
                <TableRow key={perm.id}>
                  <TableCell className="font-medium">{perm.name}</TableCell>
                  <TableCell>
                    <code className="px-2 py-1 rounded bg-muted text-sm">
                      {perm.resource}
                    </code>
                  </TableCell>
                  <TableCell>
                    <Badge className={getPermissionColor(perm.action)}>{perm.action}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function AccessCheckRow({ label, hasAccess }: { label: string; hasAccess: boolean }) {
  return (
    <div className="flex items-center justify-between p-3 rounded-lg border bg-muted/50">
      <span className="text-sm">{label}</span>
      {hasAccess ? (
        <CheckCircleIcon className="h-5 w-5 text-green-600" />
      ) : (
        <XCircleIcon className="h-5 w-5 text-red-600" />
      )}
    </div>
  );
}
