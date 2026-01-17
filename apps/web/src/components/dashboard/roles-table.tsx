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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Checkbox,
} from '@/components/ui/checkbox';
import {
  PlusIcon,
  PencilIcon,
  ShieldIcon,
} from 'lucide-react';
import {
  createRoleAction,
  updateRolePermissionsAction,
} from '@/lib/api/admin';
import type { Role, Permission } from '@rbac/types';

interface RolesTableProps {
  roles: (Role & { permissions: Permission[] })[];
  permissions: Permission[];
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

export function RolesTable({ roles, permissions }: RolesTableProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [items, setItems] = useState<(Role & { permissions: Permission[] })[]>(roles);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogMode, setDialogMode] = useState<'create' | 'permissions'>('create');
  const [selectedRole, setSelectedRole] = useState<(Role & { permissions: Permission[] }) | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    description: '',
  });
  const [selectedPermissions, setSelectedPermissions] = useState<number[]>([]);

  const openCreateDialog = () => {
    setDialogMode('create');
    setFormData({ name: '', slug: '', description: '' });
    setSelectedPermissions([]);
    setDialogOpen(true);
  };

  const openPermissionsDialog = (role: Role & { permissions: Permission[] }) => {
    setDialogMode('permissions');
    setSelectedRole(role);
    setSelectedPermissions(role.permissions.map((p) => p.id));
    setDialogOpen(true);
  };

  const handleCreate = () => {
    if (!formData.name.trim() || !formData.slug.trim()) return;

    startTransition(async () => {
      try {
        const newRole = await createRoleAction(formData);
        setItems([...items, { ...newRole, permissions: [] }]);
        setDialogOpen(false);
      } catch (e) {
        console.error('Failed to create role:', e);
      }
    });
  };

  const handleUpdatePermissions = () => {
    if (!selectedRole) return;

    startTransition(async () => {
      try {
        const result = await updateRolePermissionsAction(selectedRole.id, selectedPermissions);
        setItems(items.map((r) => (r.id === selectedRole.id ? result.data : r)));
        setDialogOpen(false);
      } catch (e) {
        console.error('Failed to update permissions:', e);
      }
    });
  };

  const togglePermission = (permissionId: number) => {
    setSelectedPermissions((prev) =>
      prev.includes(permissionId)
        ? prev.filter((id) => id !== permissionId)
        : [...prev, permissionId]
    );
  };

  const groupedPermissions = permissions.reduce((acc, perm) => {
    const [resource] = perm.slug.split('.');
    if (!acc[resource]) acc[resource] = [];
    acc[resource].push(perm);
    return acc;
  }, {} as Record<string, Permission[]>);

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ShieldIcon className="h-5 w-5" />
                Roles
              </CardTitle>
              <CardDescription>{items.length} roles defined</CardDescription>
            </div>
            <Button onClick={openCreateDialog} size="sm">
              <PlusIcon className="mr-2 h-4 w-4" />
              New Role
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Permissions</TableHead>
                <TableHead className="w-[120px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((role) => (
                <TableRow key={role.id}>
                  <TableCell>
                    <Badge className={getRoleColor(role.slug)}>{role.name}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    {role.slug}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{role.description || '-'}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      <Badge variant="outline" className="text-xs">
                        {role.permissions.length} permissions
                      </Badge>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => openPermissionsDialog(role)}
                    >
                      <PencilIcon className="mr-2 h-4 w-4" />
                      Permissions
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldIcon className="h-5 w-5" />
              {dialogMode === 'create' ? 'Create Role' : 'Manage Permissions'}
            </DialogTitle>
            <DialogDescription>
              {dialogMode === 'create'
                ? 'Create a new role with specific permissions'
                : `Configure permissions for ${selectedRole?.name}`}
            </DialogDescription>
          </DialogHeader>

          {dialogMode === 'create' ? (
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., Editor"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="slug">Slug</Label>
                <Input
                  id="slug"
                  value={formData.slug}
                  onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
                  placeholder="e.g., editor"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Role description..."
                  rows={3}
                />
              </div>
            </div>
          ) : (
            <div className="space-y-4 py-4">
              {Object.entries(groupedPermissions).map(([resource, perms]) => (
                <div key={resource}>
                  <h4 className="font-medium mb-2 capitalize">{resource}</h4>
                  <div className="space-y-2">
                    {perms.map((perm) => (
                      <div key={perm.id} className="flex items-center space-x-2">
                        <Checkbox
                          id={`perm-${perm.id}`}
                          checked={selectedPermissions.includes(perm.id)}
                          onCheckedChange={() => togglePermission(perm.id)}
                        />
                        <Label htmlFor={`perm-${perm.id}`} className="cursor-pointer">
                          {perm.name}
                          <span className="text-muted-foreground text-xs ml-2">
                            {perm.slug}
                          </span>
                        </Label>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={dialogMode === 'create' ? handleCreate : handleUpdatePermissions}
              disabled={isPending}
            >
              {dialogMode === 'create' ? 'Create' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
