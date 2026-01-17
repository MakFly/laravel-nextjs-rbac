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
import {
  Checkbox,
} from '@/components/ui/checkbox';
import {
  PlusIcon,
  CheckCircle2Icon,
  CircleIcon,
  PencilIcon,
  Trash2Icon,
} from 'lucide-react';
import type { Todo } from '@/lib/api/admin';

interface TodosTableProps {
  todos: Todo[];
  userId: number;
}

export function TodosTable({ todos, userId }: TodosTableProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [items, setItems] = useState<Todo[]>(todos);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<Todo | null>(null);
  const [formData, setFormData] = useState({ title: '', completed: false });

  const openCreateDialog = () => {
    setEditingItem(null);
    setFormData({ title: '', completed: false });
    setDialogOpen(true);
  };

  const openEditDialog = (todo: Todo) => {
    setEditingItem(todo);
    setFormData({ title: todo.title, completed: todo.completed });
    setDialogOpen(true);
  };

  const handleSave = () => {
    if (!formData.title.trim()) return;

    startTransition(async () => {
      try {
        if (editingItem) {
          // Update
          const response = await fetch(`https://jsonplaceholder.typicode.com/todos/${editingItem.id}`, {
            method: 'PATCH',
            body: JSON.stringify({
              title: formData.title,
              completed: formData.completed,
            }),
            headers: { 'Content-Type': 'application/json' },
          });
          const updated = await response.json();
          setItems(items.map((i) => (i.id === editingItem.id ? { ...i, ...updated } : i)));
        } else {
          // Create
          const response = await fetch('https://jsonplaceholder.typicode.com/todos', {
            method: 'POST',
            body: JSON.stringify({
              title: formData.title,
              completed: formData.completed,
              userId,
            }),
            headers: { 'Content-Type': 'application/json' },
          });
          const created = await response.json();
          setItems([{ ...created, userId }, ...items]);
        }
        setDialogOpen(false);
      } catch (e) {
        console.error('Failed to save todo:', e);
      }
    });
  };

  const handleToggle = (todo: Todo) => {
    startTransition(async () => {
      try {
        const response = await fetch(`https://jsonplaceholder.typicode.com/todos/${todo.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ completed: !todo.completed }),
          headers: { 'Content-Type': 'application/json' },
        });
        const updated = await response.json();
        setItems(items.map((i) => (i.id === todo.id ? { ...i, ...updated } : i)));
      } catch (e) {
        console.error('Failed to toggle todo:', e);
      }
    });
  };

  const handleDelete = (todo: Todo) => {
    startTransition(async () => {
      try {
        await fetch(`https://jsonplaceholder.typicode.com/todos/${todo.id}`, {
          method: 'DELETE',
        });
        setItems(items.filter((i) => i.id !== todo.id));
      } catch (e) {
        console.error('Failed to delete todo:', e);
      }
    });
  };

  const completedCount = items.filter((i) => i.completed).length;
  const totalCount = items.length;

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>My Todos</CardTitle>
              <CardDescription>
                {completedCount} of {totalCount} completed
              </CardDescription>
            </div>
            <Button onClick={openCreateDialog} size="sm">
              <PlusIcon className="mr-2 h-4 w-4" />
              Add Todo
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[50px]">Status</TableHead>
                <TableHead>Task</TableHead>
                <TableHead className="w-[120px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-muted-foreground">
                    No todos yet. Create your first one!
                  </TableCell>
                </TableRow>
              ) : (
                items.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      <button
                        onClick={() => handleToggle(item)}
                        className="flex items-center justify-center"
                      >
                        {item.completed ? (
                          <CheckCircle2Icon className="h-5 w-5 text-green-500" />
                        ) : (
                          <CircleIcon className="h-5 w-5 text-muted-foreground" />
                        )}
                      </button>
                    </TableCell>
                    <TableCell>
                      <span className={item.completed ? 'line-through text-muted-foreground' : ''}>
                        {item.title}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openEditDialog(item)}
                        >
                          <PencilIcon className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleDelete(item)}
                        >
                          <Trash2Icon className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
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
            <DialogTitle>{editingItem ? 'Edit Todo' : 'New Todo'}</DialogTitle>
            <DialogDescription>
              {editingItem ? 'Update your task details' : 'Create a new task'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="title">Task</Label>
              <Input
                id="title"
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                placeholder="What needs to be done?"
              />
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="completed"
                checked={formData.completed}
                onCheckedChange={(checked) =>
                  setFormData({ ...formData, completed: checked === true })
                }
              />
              <Label htmlFor="completed">Mark as completed</Label>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={!formData.title.trim() || isPending}>
              {editingItem ? 'Update' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
