import { computed } from 'vue'
import type { PermissionAction, RoleSlug } from '@rbac/types'
import { useAuthStore } from '@/stores/auth'

export function usePermissions() {
  const authStore = useAuthStore()

  return {
    hasPermission: (resource: string, action: PermissionAction) =>
      authStore.hasPermission(resource, action),
    hasRole: (role: RoleSlug) => authStore.hasRole(role),
    isAdmin: computed(() => authStore.isAdmin),
    user: computed(() => authStore.user),
    isAuthenticated: computed(() => authStore.isAuthenticated),
  }
}
