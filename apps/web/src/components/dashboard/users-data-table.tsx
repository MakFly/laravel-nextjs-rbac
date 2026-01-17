'use client';

import * as React from 'react';
import { useTransition } from 'react';
import {
  ColumnDef,
  ColumnFiltersState,
  SortingState,
  VisibilityState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
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
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  MoreHorizontalIcon,
  ShieldPlusIcon,
  ShieldMinusIcon,
  ShieldIcon,
  UserIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronsLeftIcon,
  ChevronsRightIcon,
  CheckIcon,
  XIcon,
  EyeIcon,
  PencilIcon,
  TrashIcon,
  PlusIcon,
  SettingsIcon,
} from 'lucide-react';
import { assignRoleAction, removeRoleAction } from '@/lib/api/admin';
import type { User, Role, Permission } from '@rbac/types';

interface UsersDataTableProps {
  users: (User & { roles: Role[] })[];
  roles: (Role & { permissions: Permission[] })[];
  pagination?: {
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

// Icônes pour les actions CRUD
const getActionIcon = (action: string) => {
  switch (action) {
    case 'create':
      return <PlusIcon className="h-3 w-3" />;
    case 'read':
      return <EyeIcon className="h-3 w-3" />;
    case 'update':
      return <PencilIcon className="h-3 w-3" />;
    case 'delete':
      return <TrashIcon className="h-3 w-3" />;
    case 'manage':
      return <SettingsIcon className="h-3 w-3" />;
    default:
      return <CheckIcon className="h-3 w-3" />;
  }
};

// Grouper les permissions par ressource
const groupPermissionsByResource = (permissions: Permission[]) => {
  const groups: Record<string, Permission[]> = {};

  permissions.forEach((permission) => {
    const [resource] = permission.slug.split('.');
    if (!groups[resource]) {
      groups[resource] = [];
    }
    groups[resource].push(permission);
  });

  return groups;
};

// Composant pour afficher les permissions d'un rôle
function RolePermissionsDisplay({ role }: { role: Role & { permissions: Permission[] } }) {
  const groups = groupPermissionsByResource(role.permissions);
  const resources = Object.keys(groups).sort();

  if (role.permissions.length === 0) {
    return (
      <p className="text-sm text-muted-foreground italic">Aucune permission assignée</p>
    );
  }

  return (
    <div className="space-y-3">
      {resources.map((resource) => (
        <div key={resource} className="space-y-1">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {resource}
          </p>
          <div className="flex flex-wrap gap-1">
            {groups[resource].map((permission) => {
              const action = permission.slug.split('.')[1];
              return (
                <Badge
                  key={permission.id}
                  variant="secondary"
                  className="flex items-center gap-1 text-xs"
                >
                  {getActionIcon(action)}
                  {action}
                </Badge>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export function UsersDataTable({ users, roles, pagination }: UsersDataTableProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [selectedUser, setSelectedUser] = React.useState<(User & { roles: Role[] }) | null>(null);
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [dialogMode, setDialogMode] = React.useState<'assign' | 'remove'>('assign');
  const [selectedRole, setSelectedRole] = React.useState<string>('');
  const [error, setError] = React.useState<string | null>(null);

  const [sorting, setSorting] = React.useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([]);
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({});
  const [rowSelection, setRowSelection] = React.useState({});

  const columns: ColumnDef<User & { roles: Role[] }>[] = [
    {
      accessorKey: 'name',
      header: 'User',
      cell: ({ row }) => {
        const user = row.original;
        const initials = user.name
          .split(' ')
          .map((n) => n[0])
          .join('')
          .toUpperCase()
          .slice(0, 2);

        return (
          <div className="flex items-center gap-3">
            <Avatar className="h-8 w-8">
              <AvatarFallback className="bg-gradient-to-br from-violet-600 to-indigo-600 text-white text-xs">
                {initials}
              </AvatarFallback>
            </Avatar>
            <span className="font-medium">{user.name}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'email',
      header: 'Email',
      cell: ({ row }) => <span className="text-muted-foreground">{row.original.email}</span>,
    },
    {
      accessorKey: 'roles',
      header: 'Roles',
      cell: ({ row }) => {
        const user = row.original;
        return (
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
        );
      },
    },
    {
      accessorKey: 'created_at',
      header: 'Created',
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {new Date(row.original.created_at).toLocaleDateString()}
        </span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const user = row.original;

        return (
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
        );
      },
    },
  ];

  const table = useReactTable({
    data: users,
    columns,
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      rowSelection,
    },
    initialState: {
      pagination: {
        pageSize: 10,
      },
    },
  });

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
              <CardDescription>{pagination?.total || users.length} users total</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-4 flex items-center justify-between">
            <Input
              placeholder="Filter users..."
              value={(table.getColumn('email')?.getFilterValue() as string) ?? ''}
              onChange={(event) =>
                table.getColumn('email')?.setFilterValue(event.target.value)
              }
              className="max-w-sm"
            />
          </div>

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map((headerGroup) => (
                  <TableRow key={headerGroup.id}>
                    {headerGroup.headers.map((header) => {
                      return (
                        <TableHead key={header.id}>
                          {header.isPlaceholder
                            ? null
                            : flexRender(
                                header.column.columnDef.header,
                                header.getContext()
                              )}
                        </TableHead>
                      );
                    })}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {table.getRowModel().rows?.length ? (
                  table.getRowModel().rows.map((row) => (
                    <TableRow
                      key={row.id}
                      data-state={row.getIsSelected() && 'selected'}
                    >
                      {row.getVisibleCells().map((cell) => (
                        <TableCell key={cell.id}>
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={columns.length} className="h-24 text-center">
                      No results.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-end space-x-2 py-4">
            <div className="flex-1 text-sm text-muted-foreground">
              {table.getFilteredSelectedRowModel().rows.length} of{' '}
              {table.getFilteredRowModel().rows.length} row(s) selected.
            </div>
            <div className="space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => table.setPageIndex(0)}
                disabled={!table.getCanPreviousPage()}
              >
                <ChevronsLeftIcon className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => table.previousPage()}
                disabled={!table.getCanPreviousPage()}
              >
                <ChevronLeftIcon className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => table.nextPage()}
                disabled={!table.getCanNextPage()}
              >
                <ChevronRightIcon className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                disabled={!table.getCanNextPage()}
              >
                <ChevronsRightIcon className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldIcon className="h-5 w-5" />
              {dialogMode === 'assign' ? 'Assigner un rôle' : 'Retirer un rôle'}
            </DialogTitle>
            <DialogDescription>
              {dialogMode === 'assign'
                ? `Sélectionnez un rôle à assigner à ${selectedUser?.name}`
                : `Sélectionnez un rôle à retirer de ${selectedUser?.name}`}
            </DialogDescription>
          </DialogHeader>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-red-800 text-sm">
              {error}
            </div>
          )}

          {/* Rôles actuels de l'utilisateur */}
          {selectedUser && selectedUser.roles.length > 0 && (
            <div className="rounded-lg border bg-muted/30 p-4">
              <p className="text-sm font-medium mb-2">Rôles actuels de {selectedUser.name} :</p>
              <div className="flex flex-wrap gap-2">
                {selectedUser.roles.map((role) => (
                  <Badge key={role.id} className={getRoleColor(role.slug)}>
                    {role.name}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="py-2">
            <label className="text-sm font-medium mb-2 block">
              {dialogMode === 'assign' ? 'Sélectionner un rôle à assigner :' : 'Sélectionner un rôle à retirer :'}
            </label>
            <Select value={selectedRole} onValueChange={setSelectedRole}>
              <SelectTrigger>
                <SelectValue placeholder="Choisir un rôle..." />
              </SelectTrigger>
              <SelectContent>
                {dialogMode === 'assign'
                  ? availableRoles.map((role) => (
                      <SelectItem key={role.id} value={role.slug}>
                        <div className="flex items-center gap-2">
                          <Badge className={getRoleColor(role.slug)}>{role.name}</Badge>
                          <span className="text-muted-foreground text-xs">
                            ({role.permissions?.length || 0} permissions)
                          </span>
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

          {/* Afficher les permissions du rôle sélectionné */}
          {dialogMode === 'assign' && selectedRole && (
            <div className="rounded-lg border bg-card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium">
                  Permissions du rôle{' '}
                  <Badge className={getRoleColor(selectedRole)}>
                    {availableRoles.find((r) => r.slug === selectedRole)?.name}
                  </Badge>
                </div>
              </div>
              <div className="border-t pt-3">
                {(() => {
                  const role = availableRoles.find((r) => r.slug === selectedRole);
                  return role ? (
                    <RolePermissionsDisplay role={role} />
                  ) : null;
                })()}
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                En assignant ce rôle, l'utilisateur pourra effectuer toutes les actions listées ci-dessus.
              </p>
            </div>
          )}

          {/* Afficher les permissions du rôle à retirer */}
          {dialogMode === 'remove' && selectedRole && (
            <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-4 space-y-3">
              <div className="flex items-center gap-2 text-destructive">
                <XIcon className="h-4 w-4" />
                <p className="text-sm font-medium">Permissions qui seront retirées :</p>
              </div>
              <div className="border-t border-destructive/20 pt-3">
                {(() => {
                  const role = roles.find((r) => r.id === parseInt(selectedRole));
                  return role ? (
                    <RolePermissionsDisplay role={role} />
                  ) : null;
                })()}
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                L'utilisateur perdra ces permissions (sauf si un autre rôle les lui accorde).
              </p>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Annuler
            </Button>
            <Button
              onClick={dialogMode === 'assign' ? handleAssignRole : handleRemoveRole}
              disabled={!selectedRole || isPending}
              variant={dialogMode === 'remove' ? 'destructive' : 'default'}
            >
              {isPending
                ? 'Traitement...'
                : dialogMode === 'assign'
                  ? 'Assigner le rôle'
                  : 'Retirer le rôle'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function useRouter() {
  const router = require('next/navigation');
  return router.useRouter();
}
