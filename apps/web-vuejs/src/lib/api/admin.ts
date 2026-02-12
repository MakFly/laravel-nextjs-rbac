import type { User, Role, Permission } from '@rbac/types'
import { apiRequest } from './client'

// =========================================================================
// Users Management
// =========================================================================

export async function getUsers(): Promise<(User & { roles: Role[] })[]> {
  const response = await apiRequest<{ data: (User & { roles: Role[] })[] }>('/users')
  return response.data
}

export async function getUser(userId: number): Promise<User & { roles: Role[]; permissions: Permission[] }> {
  const response = await apiRequest<{ data: User & { roles: Role[]; permissions: Permission[] } }>(
    `/admin/users/${userId}`,
  )
  return response.data
}

export async function assignRole(
  userId: number,
  roleSlug: string,
): Promise<{ message: string; data: User & { roles: Role[] } }> {
  return apiRequest(`/admin/users/${userId}/roles`, {
    method: 'POST',
    body: JSON.stringify({ role: roleSlug }),
  })
}

export async function removeRole(
  userId: number,
  roleId: number,
): Promise<{ message: string }> {
  return apiRequest(`/admin/users/${userId}/roles/${roleId}`, {
    method: 'DELETE',
  })
}

// =========================================================================
// Roles Management
// =========================================================================

export async function getRoles(): Promise<(Role & { permissions: Permission[] })[]> {
  const response = await apiRequest<{ data: (Role & { permissions: Permission[] })[] }>('/admin/roles')
  return response.data
}

export async function createRole(data: { name: string }): Promise<Role> {
  const response = await apiRequest<{ data: Role }>('/admin/roles', {
    method: 'POST',
    body: JSON.stringify(data),
  })
  return response.data
}

export async function updateRolePermissions(
  roleId: number,
  permissionIds: number[],
): Promise<{ message: string; data: Role & { permissions: Permission[] } }> {
  return apiRequest(`/admin/roles/${roleId}/permissions`, {
    method: 'POST',
    body: JSON.stringify({ permissions: permissionIds }),
  })
}

// =========================================================================
// Permissions Management
// =========================================================================

export async function getPermissions(): Promise<Permission[]> {
  const response = await apiRequest<{ data: Permission[] }>('/admin/permissions')
  return response.data
}

// =========================================================================
// Impersonation
// =========================================================================

export async function impersonateUser(userId: number): Promise<{ data: User; message: string }> {
  return apiRequest(`/admin/impersonate/${userId}`, {
    method: 'POST',
  })
}

export async function stopImpersonating(): Promise<{ data: User; message: string }> {
  return apiRequest('/admin/stop-impersonate', {
    method: 'POST',
  })
}

// =========================================================================
// Posts (JSONPlaceholder - RBAC demo)
// =========================================================================

export interface Post {
  id: number
  userId: number
  title: string
  body: string
}

export async function getPosts(limit = 20): Promise<Post[]> {
  const response = await fetch(`https://jsonplaceholder.typicode.com/posts?_limit=${limit}`)
  return response.json()
}

export async function createPost(data: Omit<Post, 'id'>): Promise<Post> {
  const response = await fetch('https://jsonplaceholder.typicode.com/posts', {
    method: 'POST',
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  })
  return response.json()
}

export async function deletePost(id: number): Promise<void> {
  await fetch(`https://jsonplaceholder.typicode.com/posts/${id}`, { method: 'DELETE' })
}
