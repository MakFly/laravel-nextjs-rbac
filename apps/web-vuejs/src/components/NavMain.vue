<script setup lang="ts">
import {
  IconDashboard,
  IconUsers,
  IconShield,
  IconLock,
  IconFileDescription,
} from "@tabler/icons-vue"

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { usePermissions } from '@/composables/usePermissions'
import { computed } from 'vue'
import { useRouter } from 'vue-router'

const { hasPermission, isAdmin } = usePermissions()
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
  ]
  return items.filter(item => item.visible)
})

function navigate(url: string) {
  router.push(url)
}
</script>

<template>
  <SidebarGroup>
    <SidebarGroupContent class="flex flex-col gap-2">
      <SidebarMenu>
        <SidebarMenuItem v-for="item in navItems" :key="item.title">
          <SidebarMenuButton :tooltip="item.title" @click="navigate(item.url)">
            <component :is="item.icon" v-if="item.icon" />
            <span>{{ item.title }}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarGroupContent>
  </SidebarGroup>
</template>
