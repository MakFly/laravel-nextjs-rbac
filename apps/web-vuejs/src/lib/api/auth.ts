import type { User, LoginCredentials, RegisterData } from '@rbac/types'
import { apiRequest, initCsrf } from './client'

interface LaravelUserResponse {
  data: {
    user: User
  }
  message: string
}

export interface AuthResult {
  user: User
}

export async function login(credentials: LoginCredentials): Promise<AuthResult> {
  await initCsrf()
  const response = await apiRequest<LaravelUserResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  })
  return { user: response.data.user }
}

export async function register(data: RegisterData): Promise<AuthResult> {
  await initCsrf()
  const response = await apiRequest<LaravelUserResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  })
  return { user: response.data.user }
}

export async function logout(): Promise<void> {
  await apiRequest<{ message: string }>('/auth/logout', { method: 'POST' })
}

export async function getCurrentUser(): Promise<User> {
  const response = await apiRequest<{ data: User }>('/me')
  return response.data
}
