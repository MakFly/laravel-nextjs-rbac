<script setup lang="ts">
import {
  IconHelp,
  IconInnerShadowTop,
  IconSearch,
  IconSettings,
  IconUserCircle,
  IconArrowRight,
} from "@tabler/icons-vue"

import NavMain from '@/components/NavMain.vue'
import NavSecondary from '@/components/NavSecondary.vue'
import NavUser from '@/components/NavUser.vue'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { useAuthStore } from '@/stores/auth'
import { computed } from 'vue'

const authStore = useAuthStore()

const onboardingStep = computed(() => authStore.user?.onboarding_step ?? 1)
const completedSteps = computed(() => Math.max(onboardingStep.value - 1, 0))

const navSecondary = [
  { title: "Settings", url: "#", icon: IconSettings },
  { title: "Get Help", url: "#", icon: IconHelp },
  { title: "Search", url: "#", icon: IconSearch },
]
</script>

<template>
  <Sidebar collapsible="offcanvas" variant="inset">
    <SidebarHeader>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton
            as-child
            class="data-[slot=sidebar-menu-button]:!p-1.5"
          >
            <a href="/dashboard">
              <IconInnerShadowTop class="!size-5" />
              <span class="text-base font-semibold">Acme</span>
            </a>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarHeader>
    <SidebarContent>
      <!-- Onboarding Card -->
      <div v-if="authStore.needsOnboarding" class="px-3 pt-3">
        <router-link to="/onboarding" class="block">
          <div class="rounded-lg border border-amber-200 bg-gradient-to-br from-amber-50 to-orange-50 dark:from-amber-950/30 dark:to-orange-950/30 dark:border-amber-800 p-3 space-y-3 hover:shadow-md transition-shadow">
            <div class="flex items-center gap-2">
              <IconUserCircle class="size-5 text-amber-600 dark:text-amber-400" />
              <span class="text-sm font-medium text-amber-900 dark:text-amber-200">Complete your profile</span>
            </div>
            <div class="space-y-1.5">
              <div class="flex justify-between text-xs text-amber-700 dark:text-amber-300">
                <span>Progress</span>
                <span>{{ completedSteps }}/4 steps</span>
              </div>
              <div class="h-1.5 rounded-full bg-amber-200 dark:bg-amber-800 overflow-hidden">
                <div
                  class="h-full rounded-full bg-amber-500 transition-all"
                  :style="{ width: `${(completedSteps / 4) * 100}%` }"
                />
              </div>
            </div>
            <div class="flex items-center gap-1 text-xs font-medium text-amber-700 dark:text-amber-300 hover:text-amber-900 dark:hover:text-amber-100">
              Continue
              <IconArrowRight class="size-3" />
            </div>
          </div>
        </router-link>
      </div>

      <NavMain />
      <NavSecondary :items="navSecondary" class="mt-auto" />
    </SidebarContent>
    <SidebarFooter>
      <NavUser />
    </SidebarFooter>
  </Sidebar>
</template>
