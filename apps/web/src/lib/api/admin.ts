/**
 * Server Actions for administration
 *
 * These actions use the BFF to communicate with Laravel.
 * All these routes require admin role.
 */

'use server';

import { cookies } from 'next/headers';
import type { User, Role, Permission } from '@rbac/types';

/**
 * Base URL of Next.js BFF
 */
const BFF_URL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

/**
 * Types for paginated responses
 */
interface PaginatedResponse<T> {
  data: T[];
  current_page: number;
  last_page: number;
  per_page: number;
  total: number;
}

/**
 * Makes a request to the BFF
 *
 * Note: credentials: 'include' does NOT work for server-to-server requests.
 * Must pass cookie manually in headers.
 *
 * @returns JSON response directly (T)
 */
async function bffRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${BFF_URL}${endpoint}`;

  // Get cookie for authenticated requests
  const cookieStore = await cookies();
  const authToken = cookieStore.get('auth_token');

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...options.headers,
  };

  // For server-to-server requests, pass cookie manually
  if (authToken?.value) {
    (headers as Record<string, string>)['Cookie'] = `auth_token=${authToken.value}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(error.message || `HTTP error ${response.status}`);
  }

  return response.json();
}

// =========================================================================
// Users Management
// =========================================================================

/**
 * Get list of users
 */
export async function getUsersAction(): Promise<(User & { roles: Role[] })[]> {
  const response = await bffRequest<{ data: (User & { roles: Role[] })[] }>(
    '/api/v1/users'
  );
  return response.data;
}

/**
 * Get a user by ID
 */
export async function getUserAction(
  userId: number
): Promise<User & { roles: Role[]; permissions: Permission[] }> {
  const response = await bffRequest<{ data: User & { roles: Role[]; permissions: Permission[] } }>(
    `/api/v1/admin/users/${userId}`
  );
  return response.data;
}

/**
 * Assign a role to a user
 */
export async function assignRoleAction(
  userId: number,
  roleSlug: string
): Promise<{ message: string; data: User & { roles: Role[] } }> {
  const response = await bffRequest<{
    message: string;
    data: User & { roles: Role[] };
  }>(`/api/v1/admin/users/${userId}/roles`, {
    method: 'POST',
    body: JSON.stringify({ role: roleSlug }),
  });
  return response;
}

/**
 * Remove a role from a user
 */
export async function removeRoleAction(
  userId: number,
  roleId: number
): Promise<{ message: string }> {
  const response = await bffRequest<{ message: string }>(
    `/api/v1/admin/users/${userId}/roles/${roleId}`,
    { method: 'DELETE' }
  );
  return response;
}

// =========================================================================
// Roles Management
// =========================================================================

/**
 * Get list of roles
 */
export async function getRolesAction(): Promise<(Role & { permissions: Permission[] })[]> {
  const response = await bffRequest<{ data: (Role & { permissions: Permission[] })[] }>(
    '/api/v1/admin/roles'
  );
  return response.data;
}

/**
 * Create a new role
 */
export async function createRoleAction(data: {
  name: string;
  slug: string;
  description?: string;
}): Promise<Role> {
  const response = await bffRequest<{ data: Role }>('/api/v1/admin/roles', {
    method: 'POST',
    body: JSON.stringify(data),
  });
  return response.data;
}

/**
 * Update role permissions
 */
export async function updateRolePermissionsAction(
  roleId: number,
  permissionIds: number[]
): Promise<{ message: string; data: Role & { permissions: Permission[] } }> {
  const response = await bffRequest<{
    message: string;
    data: Role & { permissions: Permission[] };
  }>(`/api/v1/admin/roles/${roleId}/permissions`, {
    method: 'POST',
    body: JSON.stringify({ permissions: permissionIds }),
  });
  return response;
}

// =========================================================================
// Permissions Management
// =========================================================================

/**
 * Get list of permissions
 */
export async function getPermissionsAction(): Promise<Permission[]> {
  const response = await bffRequest<{ data: Permission[] }>('/api/v1/admin/permissions');
  return response.data;
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

/**
 * Get all posts
 */
export async function getPostsAction(limit = 20): Promise<Post[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/posts?_limit=${limit}`
  );
  return response.json();
}

/**
 * Get a post by ID
 */
export async function getPostAction(id: number): Promise<Post> {
  const response = await fetch(`https://jsonplaceholder.typicode.com/posts/${id}`);
  return response.json();
}

/**
 * Get comments of a post
 */
export async function getPostCommentsAction(postId: number): Promise<Comment[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/posts/${postId}/comments`
  );
  return response.json();
}

/**
 * Create a post (simulation)
 */
export async function createPostAction(data: Omit<Post, 'id'>): Promise<Post> {
  const response = await fetch('https://jsonplaceholder.typicode.com/posts', {
    method: 'POST',
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  });
  return response.json();
}

/**
 * Update a post (simulation)
 */
export async function updatePostAction(id: number, data: Partial<Post>): Promise<Post> {
  const response = await fetch(`https://jsonplaceholder.typicode.com/posts/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  });
  return response.json();
}

/**
 * Delete a post (simulation)
 */
export async function deletePostAction(id: number): Promise<void> {
  await fetch(`https://jsonplaceholder.typicode.com/posts/${id}`, {
    method: 'DELETE',
  });
}

/**
 * Get todos of a user
 */
export async function getTodosAction(userId?: number): Promise<Todo[]> {
  const url = userId
    ? `https://jsonplaceholder.typicode.com/users/${userId}/todos`
    : 'https://jsonplaceholder.typicode.com/todos?_limit=20';
  const response = await fetch(url);
  return response.json();
}

/**
 * Get albums
 */
export async function getAlbumsAction(limit = 10): Promise<Album[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/albums?_limit=${limit}`
  );
  return response.json();
}

/**
 * Get photos of an album
 */
export async function getAlbumPhotosAction(albumId: number): Promise<Photo[]> {
  const response = await fetch(
    `https://jsonplaceholder.typicode.com/albums/${albumId}/photos`
  );
  return response.json();
}
