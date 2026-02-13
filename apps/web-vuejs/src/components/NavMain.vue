<script setup lang="ts">
import {
  IconDashboard,
  IconUsers,
  IconShield,
  IconLock,
  IconFileDescription,
  IconChartCandle,
} from "@tabler/icons-vue"

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { usePermissions } from '@/composables/usePermissions'
import { useAuthStore } from '@/stores/auth'
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { toast } from 'vue-sonner'

const { hasPermission, isAdmin } = usePermissions()
const authStore = useAuthStore()
const router = useRouter()

const navItems = computed(() => {
  const items = [
    {
      title: 'Dashboard',
      url: '/dashboard',
      icon: IconDashboard,
      visible: true,
    },
    {
      title: 'Users',
      url: '/dashboard/users',
      icon: IconUsers,
      visible: isAdmin.value || hasPermission('users', 'read'),
    },
    {
      title: 'Roles',
      url: '/dashboard/roles',
      icon: IconShield,
      visible: isAdmin.value,
    },
    {
      title: 'Permissions',
      url: '/dashboard/permissions',
      icon: IconLock,
      visible: isAdmin.value,
    },
    {
      title: 'Posts',
      url: '/dashboard/posts',
      icon: IconFileDescription,
      visible: hasPermission('posts', 'read') || isAdmin.value,
    },
    {
      title: 'OrderBook',
      url: '/dashboard/orderbook',
      icon: IconChartCandle,
      visible: true,
    },
  ]
  return items.filter(item => item.visible)
})

function navigate(item: { url: string; title: string }) {
  const isDashboard = item.url === '/dashboard'
  if (authStore.needsOnboarding && !isDashboard) {
    toast.info('Complete your onboarding first', {
      description: 'You need to finish setting up your profile to access this section.',
    })
    return
  }
  router.push(item.url)
}
</script>

<template>
  <SidebarGroup>
    <SidebarGroupContent class="flex flex-col gap-2">
      <SidebarMenu>
        <SidebarMenuItem v-for="item in navItems" :key="item.title">
          <SidebarMenuButton
            :tooltip="item.title"
            :class="{ 'opacity-50 cursor-not-allowed': authStore.needsOnboarding && item.url !== '/dashboard' }"
            @click="navigate(item)"
          >
            <component :is="item.icon" v-if="item.icon" />
            <span>{{ item.title }}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarGroupContent>
  </SidebarGroup>
</template>
