<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { User, Role } from '@rbac/types'
import { getUsers, getRoles, assignRole, removeRole } from '@/lib/api/admin'
import { useAuthStore } from '@/stores/auth'
import AppSidebar from '@/components/AppSidebar.vue'
import SiteHeader from '@/components/SiteHeader.vue'
import { Button } from '@/components/ui/button'
import {
  SidebarInset,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { toast } from 'vue-sonner'
import { useRouter } from 'vue-router'

const auth = useAuthStore()
const router = useRouter()

const users = ref<(User & { roles: Role[] })[]>([])
const roles = ref<Role[]>([])
const isLoading = ref(true)

onMounted(async () => {
  try {
    const [usersData, rolesData] = await Promise.all([getUsers(), getRoles()])
    users.value = usersData
    roles.value = rolesData
  } catch (err) {
    toast.error('Failed to load users')
  } finally {
    isLoading.value = false
  }
})

async function handleAssignRole(userId: number, roleSlug: string) {
  try {
    const result = await assignRole(userId, roleSlug)
    const idx = users.value.findIndex(u => u.id === userId)
    if (idx !== -1) users.value[idx].roles = result.data.roles
    toast.success(result.message)
  } catch {
    toast.error('Failed to assign role')
  }
}

async function handleRemoveRole(userId: number, roleId: number) {
  try {
    const result = await removeRole(userId, roleId)
    const idx = users.value.findIndex(u => u.id === userId)
    if (idx !== -1) {
      users.value[idx].roles = users.value[idx].roles.filter(r => r.id !== roleId)
    }
    toast.success(result.message)
  } catch {
    toast.error('Failed to remove role')
  }
}

async function handleImpersonate(userId: number) {
  try {
    await auth.impersonate(userId)
    toast.success('Now impersonating user')
    router.push('/dashboard')
  } catch {
    toast.error('Failed to impersonate user')
  }
}

function canImpersonate(user: User & { roles: Role[] }): boolean {
  return auth.user?.id !== user.id && !user.roles.some(r => r.slug === 'admin')
}
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <SiteHeader />
      <div class="flex flex-1 flex-col gap-4 py-4 md:gap-6 md:py-6">
        <div class="flex flex-col gap-1 px-4 lg:px-6">
          <h1 class="text-3xl font-bold tracking-tight">Users</h1>
          <p class="text-muted-foreground">Manage user roles and permissions</p>
        </div>

        <div class="px-4 lg:px-6">
          <div v-if="isLoading" class="text-muted-foreground text-center py-8">Loading...</div>
          <div v-else class="rounded-xl border">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b bg-muted/50">
                  <th class="px-4 py-3 text-left font-medium">Name</th>
                  <th class="px-4 py-3 text-left font-medium">Email</th>
                  <th class="px-4 py-3 text-left font-medium">Roles</th>
                  <th class="px-4 py-3 text-left font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="user in users" :key="user.id" class="border-b last:border-0">
                  <td class="px-4 py-3 font-medium">{{ user.name }}</td>
                  <td class="px-4 py-3 text-muted-foreground">{{ user.email }}</td>
                  <td class="px-4 py-3">
                    <div class="flex flex-wrap gap-1">
                      <span
                        v-for="role in user.roles"
                        :key="role.id"
                        class="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary"
                      >
                        {{ role.name }}
                        <button
                          @click="handleRemoveRole(user.id, role.id)"
                          class="ml-1 hover:text-destructive"
                          title="Remove role"
                        >
                          &times;
                        </button>
                      </span>
                      <span v-if="!user.roles.length" class="text-muted-foreground text-xs">No roles</span>
                    </div>
                  </td>
                  <td class="px-4 py-3">
                    <div class="flex gap-1">
                      <Button
                        v-for="role in roles.filter(r => !user.roles.some(ur => ur.slug === r.slug))"
                        :key="role.id"
                        variant="outline"
                        size="sm"
                        @click="handleAssignRole(user.id, role.slug)"
                      >
                        + {{ role.name }}
                      </Button>
                      <Button
                        v-if="canImpersonate(user)"
                        variant="outline"
                        size="sm"
                        class="text-amber-600 border-amber-300 hover:bg-amber-50"
                        @click="handleImpersonate(user.id)"
                      >
                        Impersonate
                      </Button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </SidebarInset>
  </SidebarProvider>
</template>
