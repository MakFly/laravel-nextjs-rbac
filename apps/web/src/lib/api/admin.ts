/**
 * Server Actions for administration (Sanctum SPA mode)
 *
 * Uses Laravel Sanctum session-based auth via server-side helper.
 * All admin routes require admin role.
 */

'use server';

import type { User, Role, Permission } from '@rbac/types';
import { laravelRequest } from './laravel';

// =========================================================================
// Users Management
// =========================================================================

export async function getUsersAction(): Promise<(User & { roles: Role[] })[]> {
  const response = await laravelRequest<{ data: (User & { roles: Role[] })[] }>('/users');
  return response.data;
}

export async function getUserAction(
  userId: number
): Promise<User & { roles: Role[]; permissions: Permission[] }> {
  const response = await laravelRequest<{ data: User & { roles: Role[]; permissions: Permission[] } }>(
    `/admin/users/${userId}`
  );
  return response.data;
}

export async function assignRoleAction(
  userId: number,
  roleSlug: string
): Promise<{ message: string; data: User & { roles: Role[] } }> {
  return laravelRequest(`/admin/users/${userId}/roles`, {
    method: 'POST',
    body: JSON.stringify({ role: roleSlug }),
  });
}

export async function removeRoleAction(
  userId: number,
  roleId: number
): Promise<{ message: string }> {
  return laravelRequest(`/admin/users/${userId}/roles/${roleId}`, {
    method: 'DELETE',
  });
}

// =========================================================================
// Roles Management
// =========================================================================

export async function getRolesAction(): Promise<(Role & { permissions: Permission[] })[]> {
  const response = await laravelRequest<{ data: (Role & { permissions: Permission[] })[] }>(
    '/admin/roles'
  );
  return response.data;
}

export async function createRoleAction(data: { name: string }): Promise<Role> {
  const response = await laravelRequest<{ data: Role }>('/admin/roles', {
    method: 'POST',
    body: JSON.stringify(data),
  });
  return response.data;
}

export async function updateRolePermissionsAction(
  roleId: number,
  permissionIds: number[]
): Promise<{ message: string; data: Role & { permissions: Permission[] } }> {
  return laravelRequest(`/admin/roles/${roleId}/permissions`, {
    method: 'POST',
    body: JSON.stringify({ permissions: permissionIds }),
  });
}

// =========================================================================
// Permissions Management
// =========================================================================

export async function getPermissionsAction(): Promise<Permission[]> {
  const response = await laravelRequest<{ data: Permission[] }>('/admin/permissions');
  return response.data;
}

// =========================================================================
// Impersonation
// =========================================================================

export async function impersonateUserAction(userId: number): Promise<{ data: User; message: string }> {
  return laravelRequest(`/admin/impersonate/${userId}`, {
    method: 'POST',
  });
}

export async function stopImpersonatingAction(): Promise<{ data: User; message: string }> {
  return laravelRequest('/admin/stop-impersonate', {
    method: 'POST',
  });
}

// =========================================================================
// JSONPlaceholder - Fake Data for RBAC business logic tests
// =========================================================================

export interface Post {
  id: number;
  userId: number;
  title: string;
  body: string;
}

export interface Comment {
  id: number;
  postId: number;
  name: string;
  email: string;
  body: string;
}

export interface Album {
  id: number;
  userId: number;
  title: string;
}

export interface Photo {
  id: number;
  albumId: number;
  title: string;
  url: string;
  thumbnailUrl: string;
}

export interface Todo {
  id: number;
  userId: number;
  title: string;
  completed: boolean;
}

export async function getPostsAction(limit = 20): Promise<Post[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/posts?_limit=${limit}`
  );
  return response.json();
}

export async function getPostAction(id: number): Promise<Post> {
  const response = await fetch(`https://jsonplaceholder.typicode.com/posts/${id}`);
  return response.json();
}

export async function getPostCommentsAction(postId: number): Promise<Comment[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/posts/${postId}/comments`
  );
  return response.json();
}

export async function createPostAction(data: Omit<Post, 'id'>): Promise<Post> {
  const response = await fetch('https://jsonplaceholder.typicode.com/posts', {
    method: 'POST',
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  });
  return response.json();
}

export async function updatePostAction(id: number, data: Partial<Post>): Promise<Post> {
  const response = await fetch(`https://jsonplaceholder.typicode.com/posts/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  });
  return response.json();
}

export async function deletePostAction(id: number): Promise<void> {
  await fetch(`https://jsonplaceholder.typicode.com/posts/${id}`, {
    method: 'DELETE',
  });
}

export async function getTodosAction(userId?: number): Promise<Todo[]> {
  const url = userId
    ? `https://jsonplaceholder.typicode.com/users/${userId}/todos`
    : 'https://jsonplaceholder.typicode.com/todos?_limit=20';
  const response = await fetch(url);
  return response.json();
}

export async function getAlbumsAction(limit = 10): Promise<Album[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/albums?_limit=${limit}`
  );
  return response.json();
}

export async function getAlbumPhotosAction(albumId: number): Promise<Photo[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/albums/${albumId}/photos`
  );
  return response.json();
}
