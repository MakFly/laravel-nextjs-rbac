'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  MoreHorizontalIcon,
  ShieldIcon,
  ShieldPlusIcon,
  ShieldMinusIcon,
  UserIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
} from 'lucide-react';
import { assignRoleAction, removeRoleAction } from '@/lib/api/admin';
import type { User, Role, Permission } from '@rbac/types';

interface UsersTableProps {
  users: (User & { roles: Role[] })[];
  roles: (Role & { permissions: Permission[] })[];
  pagination: {
    currentPage: number;
    lastPage: number;
    total: number;
  };
}

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

export function UsersTable({ users, roles, pagination }: UsersTableProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [selectedUser, setSelectedUser] = useState<(User & { roles: Role[] }) | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogMode, setDialogMode] = useState<'assign' | 'remove'>('assign');
  const [selectedRole, setSelectedRole] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const openAssignDialog = (user: User & { roles: Role[] }) => {
    setSelectedUser(user);
    setDialogMode('assign');
    setSelectedRole('');
    setError(null);
    setDialogOpen(true);
  };

  const openRemoveDialog = (user: User & { roles: Role[] }) => {
    setSelectedUser(user);
    setDialogMode('remove');
    setSelectedRole('');
    setError(null);
    setDialogOpen(true);
  };

  const handleAssignRole = () => {
    if (!selectedUser || !selectedRole) return;

    startTransition(async () => {
      try {
        await assignRoleAction(selectedUser.id, selectedRole);
        setDialogOpen(false);
        router.refresh();
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to assign role');
      }
    });
  };

  const handleRemoveRole = () => {
    if (!selectedUser || !selectedRole) return;

    startTransition(async () => {
      try {
        await removeRoleAction(selectedUser.id, parseInt(selectedRole));
        setDialogOpen(false);
        router.refresh();
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to remove role');
      }
    });
  };

  // Roles disponibles pour l'assignation (exclure ceux déjà assignés)
  const availableRoles = selectedUser
    ? roles.filter((r) => !selectedUser.roles.some((ur) => ur.id === r.id))
    : [];

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <UserIcon className="h-5 w-5" />
                Users
              </CardTitle>
              <CardDescription>
                {pagination.total} users total
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[70px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <Avatar className="h-8 w-8">
                        <AvatarFallback className="bg-gradient-to-br from-violet-600 to-indigo-600 text-white text-xs">
                          {getInitials(user.name)}
                        </AvatarFallback>
                      </Avatar>
                      <span className="font-medium">{user.name}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {user.email}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {user.roles.length > 0 ? (
                        user.roles.map((role) => (
                          <Badge key={role.id} className={getRoleColor(role.slug)}>
                            {role.name}
                          </Badge>
                        ))
                      ) : (
                        <span className="text-muted-foreground text-sm">No roles</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {new Date(user.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon">
                          <MoreHorizontalIcon className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={() => openAssignDialog(user)}>
                          <ShieldPlusIcon className="mr-2 h-4 w-4" />
                          Assign Role
                        </DropdownMenuItem>
                        {user.roles.length > 0 && (
                          <DropdownMenuItem onClick={() => openRemoveDialog(user)}>
                            <ShieldMinusIcon className="mr-2 h-4 w-4" />
                            Remove Role
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {/* Pagination */}
          {pagination.lastPage > 1 && (
            <div className="flex items-center justify-between mt-4">
              <p className="text-sm text-muted-foreground">
                Page {pagination.currentPage} of {pagination.lastPage}
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={pagination.currentPage <= 1}
                  onClick={() => {
                    const params = new URLSearchParams(window.location.search);
                    params.set('page', String(pagination.currentPage - 1));
                    router.push(`?${params.toString()}`);
                  }}
                >
                  <ChevronLeftIcon className="h-4 w-4" />
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={pagination.currentPage >= pagination.lastPage}
                  onClick={() => {
                    const params = new URLSearchParams(window.location.search);
                    params.set('page', String(pagination.currentPage + 1));
                    router.push(`?${params.toString()}`);
                  }}
                >
                  Next
                  <ChevronRightIcon className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Dialog pour assigner/retirer un rôle */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldIcon className="h-5 w-5" />
              {dialogMode === 'assign' ? 'Assign Role' : 'Remove Role'}
            </DialogTitle>
            <DialogDescription>
              {dialogMode === 'assign'
                ? `Select a role to assign to ${selectedUser?.name}`
                : `Select a role to remove from ${selectedUser?.name}`}
            </DialogDescription>
          </DialogHeader>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-red-800 text-sm">
              {error}
            </div>
          )}

          <div className="py-4">
            <Select value={selectedRole} onValueChange={setSelectedRole}>
              <SelectTrigger>
                <SelectValue placeholder="Select a role..." />
              </SelectTrigger>
              <SelectContent>
                {dialogMode === 'assign'
                  ? availableRoles.map((role) => (
                      <SelectItem key={role.id} value={role.slug}>
                        <div className="flex items-center gap-2">
                          <Badge className={getRoleColor(role.slug)}>{role.name}</Badge>
                          {role.description && (
                            <span className="text-muted-foreground text-xs">
                              - {role.description}
                            </span>
                          )}
                        </div>
                      </SelectItem>
                    ))
                  : selectedUser?.roles.map((role) => (
                      <SelectItem key={role.id} value={String(role.id)}>
                        <Badge className={getRoleColor(role.slug)}>{role.name}</Badge>
                      </SelectItem>
                    ))}
              </SelectContent>
            </Select>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={dialogMode === 'assign' ? handleAssignRole : handleRemoveRole}
              disabled={!selectedRole || isPending}
              variant={dialogMode === 'remove' ? 'destructive' : 'default'}
            >
              {isPending
                ? 'Processing...'
                : dialogMode === 'assign'
                  ? 'Assign Role'
                  : 'Remove Role'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
