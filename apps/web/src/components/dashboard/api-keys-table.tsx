'use client';

import { useState, useTransition, useMemo } from 'react';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  PlusIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  Trash2Icon,
  KeyIcon,
} from 'lucide-react';

interface ApiKey {
  id: string;
  name: string;
  key: string;
  scopes: string[];
  expiresAt: string | null;
  lastUsed: string | null;
  createdAt: string;
}

interface ApiKeysTableProps {
  userId: number;
}

// Mock storage pour les API keys
let mockApiKeys: ApiKey[] = [
  {
    id: '1',
    name: 'Production API',
    key: 'sk_prod_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15),
    scopes: ['read', 'write'],
    expiresAt: null,
    lastUsed: new Date(Date.now() - 86400000).toISOString(),
    createdAt: new Date(Date.now() - 604800000).toISOString(),
  },
];

const SCOPE_OPTIONS = [
  { value: 'read', label: 'Read' },
  { value: 'write', label: 'Write' },
  { value: 'admin', label: 'Admin' },
];

const SCOPE_COLORS: Record<string, string> = {
  read: 'bg-blue-500 text-white',
  write: 'bg-amber-500 text-white',
  admin: 'bg-red-500 text-white',
};

export function ApiKeysTable({ userId }: ApiKeysTableProps) {
  const [isPending, startTransition] = useTransition();
  const [items, setItems] = useState<ApiKey[]>(mockApiKeys);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    scopes: ['read'],
    expiresIn: '',
  });
  const [visibleKeys, setVisibleKeys] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCreate = () => {
    if (!formData.name.trim()) return;

    startTransition(() => {
      const newKey: ApiKey = {
        id: Date.now().toString(),
        name: formData.name,
        key: 'sk_prod_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15),
        scopes: formData.scopes,
        expiresAt: formData.expiresIn
          ? new Date(Date.now() + parseInt(formData.expiresIn) * 86400000).toISOString()
          : null,
        lastUsed: null,
        createdAt: new Date().toISOString(),
      };

      mockApiKeys = [...mockApiKeys, newKey];
      setItems(mockApiKeys);
      setDialogOpen(false);
      setFormData({ name: '', scopes: ['read'], expiresIn: '' });

      // Auto-show the new key
      setVisibleKeys((prev) => ({ ...prev, [newKey.id]: true }));
    });
  };

  const handleDelete = (id: string) => {
    startTransition(() => {
      mockApiKeys = mockApiKeys.filter((k) => k.id !== id);
      setItems(mockApiKeys);
    });
  };

  const copyToClipboard = (key: string, id: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleKeyVisibility = (id: string) => {
    setVisibleKeys((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const maskKey = (key: string) => {
    return key.slice(0, 8) + '•'.repeat(20) + key.slice(-8);
  };

  const isExpiringSoon = (expiresAt: string | null) => {
    if (!expiresAt) return false;
    const daysLeft = Math.floor((new Date(expiresAt).getTime() - Date.now()) / 86400000);
    return daysLeft <= 7 && daysLeft > 0;
  };

  const isExpired = (expiresAt: string | null) => {
    if (!expiresAt) return false;
    return new Date(expiresAt) < new Date();
  };

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <KeyIcon className="h-5 w-5" />
                API Keys
              </CardTitle>
              <CardDescription>{items.length} keys configured</CardDescription>
            </div>
            <Button onClick={() => setDialogOpen(true)} size="sm">
              <PlusIcon className="mr-2 h-4 w-4" />
              Generate Key
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead className="w-[100px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    No API keys yet. Generate your first key to get started!
                  </TableCell>
                </TableRow>
              ) : (
                items.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-medium">{item.name}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2 font-mono text-sm">
                        <span className="text-muted-foreground">
                          {visibleKeys[item.id] ? item.key : maskKey(item.key)}
                        </span>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6"
                          onClick={() => copyToClipboard(item.key, item.id)}
                        >
                          <CopyIcon className="h-3 w-3" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6"
                          onClick={() => toggleKeyVisibility(item.id)}
                        >
                          {visibleKeys[item.id] ? (
                            <EyeOffIcon className="h-3 w-3" />
                          ) : (
                            <EyeIcon className="h-3 w-3" />
                          )}
                        </Button>
                        {copiedKey === item.id && (
                          <Badge variant="outline" className="text-xs">
                            Copied!
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {item.scopes.map((scope) => (
                          <Badge key={scope} className={SCOPE_COLORS[scope] || 'bg-gray-500'}>
                            {scope}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      {isExpired(item.expiresAt) ? (
                        <Badge variant="destructive">Expired</Badge>
                      ) : isExpiringSoon(item.expiresAt) ? (
                        <Badge variant="outline" className="border-amber-500 text-amber-700">
                          Expiring soon
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-green-700 border-green-500">
                          Active
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {item.lastUsed
                        ? new Date(item.lastUsed).toLocaleDateString()
                        : 'Never'}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDelete(item.id)}
                      >
                        <Trash2Icon className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyIcon className="h-5 w-5" />
              Generate API Key
            </DialogTitle>
            <DialogDescription>
              Create a new API key for external access to your resources
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g., Production API Key"
              />
            </div>

            <div className="space-y-2">
              <Label>Scopes</Label>
              <div className="flex flex-wrap gap-2">
                {SCOPE_OPTIONS.map((option) => (
                  <Button
                    key={option.value}
                    type="button"
                    variant={formData.scopes.includes(option.value) ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => {
                      setFormData({
                        ...formData,
                        scopes: formData.scopes.includes(option.value)
                          ? formData.scopes.filter((s) => s !== option.value)
                          : [...formData.scopes, option.value],
                      });
                    }}
                  >
                    {option.label}
                  </Button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="expires">Expiration (optional)</Label>
              <Select
                value={formData.expiresIn}
                onValueChange={(value) => setFormData({ ...formData, expiresIn: value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select expiration" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">Never expires</SelectItem>
                  <SelectItem value="7">7 days</SelectItem>
                  <SelectItem value="30">30 days</SelectItem>
                  <SelectItem value="90">90 days</SelectItem>
                  <SelectItem value="365">1 year</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={!formData.name.trim() || isPending}>
              Generate Key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
