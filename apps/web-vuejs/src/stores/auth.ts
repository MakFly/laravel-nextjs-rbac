import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { User, PermissionAction, RoleSlug } from '@rbac/types'
import { hasPermission as checkPermission, hasRole as checkRole } from '@rbac/types'
import * as authApi from '@/lib/api/auth'
import { impersonateUser as impersonateApi, stopImpersonating as stopImpersonatingApi } from '@/lib/api/admin'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const isLoading = ref(false)
  const error = ref<string | null>(null)
  const initialized = ref(false)

  const isAuthenticated = computed(() => !!user.value)

  function hasPermission(resource: string, action: PermissionAction): boolean {
    if (!user.value) return false
    return checkPermission(user.value, resource, action)
  }

  function hasRole(roleSlug: RoleSlug): boolean {
    if (!user.value) return false
    return checkRole(user.value, roleSlug)
  }

  const isAdmin = computed(() => hasRole('admin'))
  const isImpersonating = computed(() => user.value?.is_impersonating ?? false)
  const impersonator = computed(() => user.value?.impersonator ?? null)
  const needsOnboarding = computed(() => !!user.value && user.value.onboarding_status !== 'completed')

  async function initialize() {
    if (initialized.value) return
    isLoading.value = true
    try {
      user.value = await authApi.getCurrentUser()
    } catch {
      user.value = null
    } finally {
      isLoading.value = false
      initialized.value = true
    }
  }

  async function refreshUser() {
    try {
      user.value = await authApi.getCurrentUser()
    } catch {
      user.value = null
    }
  }

  async function login(email: string, password: string) {
    isLoading.value = true
    error.value = null
    try {
      const response = await authApi.login({ email, password })
      user.value = response.user
      initialized.value = true
    } catch (err: unknown) {
      const apiErr = err as { message?: string }
      error.value = apiErr.message || 'Login failed'
      throw err
    } finally {
      isLoading.value = false
    }
  }

  async function register(name: string, email: string, password: string, password_confirmation: string) {
    isLoading.value = true
    error.value = null
    try {
      const response = await authApi.register({ name, email, password, password_confirmation })
      user.value = response.user
      initialized.value = true
    } catch (err: unknown) {
      const apiErr = err as { message?: string }
      error.value = apiErr.message || 'Registration failed'
      throw err
    } finally {
      isLoading.value = false
    }
  }

  async function logout() {
    try {
      await authApi.logout()
    } finally {
      user.value = null
      initialized.value = false
    }
  }

  async function impersonate(userId: number) {
    isLoading.value = true
    error.value = null
    try {
      const response = await impersonateApi(userId)
      user.value = response.data
      initialized.value = true
    } catch (err: unknown) {
      const apiErr = err as { message?: string }
      error.value = apiErr.message || 'Impersonation failed'
      throw err
    } finally {
      isLoading.value = false
    }
  }

  async function stopImpersonation() {
    isLoading.value = true
    error.value = null
    try {
      const response = await stopImpersonatingApi()
      user.value = response.data
      initialized.value = true
    } catch (err: unknown) {
      const apiErr = err as { message?: string }
      error.value = apiErr.message || 'Failed to stop impersonation'
      throw err
    } finally {
      isLoading.value = false
    }
  }

  return {
    user,
    isLoading,
    error,
    initialized,
    isAuthenticated,
    isAdmin,
    isImpersonating,
    impersonator,
    needsOnboarding,
    hasPermission,
    hasRole,
    initialize,
    refreshUser,
    login,
    register,
    logout,
    impersonate,
    stopImpersonation,
  }
})
