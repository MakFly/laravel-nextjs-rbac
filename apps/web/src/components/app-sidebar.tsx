"use client"

import * as React from "react"
import Link from "next/link"
import {
  ShieldIcon,
  UsersIcon,
  KeyIcon,
  LayoutDashboardIcon,
  SettingsIcon,
  LogOutIcon,
  BarChart3Icon,
  CircleUserIcon,
  ArrowRightIcon,
} from "lucide-react"
import { toast } from "sonner"

import { NavMain } from "@/components/nav-main"
import { NavSecondary } from "@/components/nav-secondary"
import { NavUser } from "@/components/nav-user"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { useAuthStore } from "@/stores/auth-store"
import type { User, PermissionAction } from "@rbac/types"
import {
  hasPermission as checkHasPermission,
  isAdmin as checkIsAdmin,
} from "@rbac/types"

interface AppSidebarProps extends React.ComponentProps<typeof Sidebar> {
  initialUser?: User | null
}

export function AppSidebar({ initialUser, ...props }: AppSidebarProps) {
  const { user: storeUser, isHydrated, logout } = useAuthStore()

  // Utiliser le user du store si hydraté, sinon le user initial (SSR)
  const user = isHydrated ? storeUser : initialUser
  const needsOnboarding = user ? user.onboarding_status !== 'completed' : false
  const onboardingStep = user?.onboarding_step ?? 1

  // Helpers de permissions qui fonctionnent avec le user actuel (SSR ou hydraté)
  const userHasPermission = (resource: string, action: PermissionAction) => {
    if (!user) return false
    return checkHasPermission(user, resource, action)
  }

  const userIsAdmin = () => {
    if (!user) return false
    return checkIsAdmin(user)
  }

  // Items statiques (toujours visibles, ne dépendent pas des permissions)
  const staticNavItems = [
    {
      title: "Dashboard",
      url: "/dashboard",
      icon: LayoutDashboardIcon,
    },
    {
      title: "OrderBook",
      url: "/dashboard/orderbook",
      icon: BarChart3Icon,
    },
  ]

  // Items conditionnels (dépendent des permissions utilisateur)
  // Calculés immédiatement avec initialUser (SSR) ou storeUser (client)
  const conditionalNavItems = user
    ? [
        {
          title: "Users",
          url: "#",
          icon: UsersIcon,
          items: [
            { title: "All Users", url: "/dashboard/users" },
            { title: "Permissions", url: "/dashboard/permissions" },
          ],
          show: userHasPermission("users", "read") || userIsAdmin(),
        },
        {
          title: "Roles",
          url: "#",
          icon: ShieldIcon,
          items: [
            { title: "Manage Roles", url: "/dashboard/roles" },
            { title: "Role Permissions", url: "/dashboard/roles/permissions" },
          ],
          show: userIsAdmin(),
        },
        {
          title: "API Keys",
          url: "/dashboard/api-keys",
          icon: KeyIcon,
          show: userHasPermission("api", "manage") || userIsAdmin(),
        },
      ].filter((item) => item.show !== false)
    : []

  // Items secondaires statiques (toujours visibles)
  const navSecondary = [
    {
      title: "Settings",
      url: "/dashboard/settings",
      icon: SettingsIcon,
    },
    {
      title: "Logout",
      url: "#",
      icon: LogOutIcon,
      action: logout,
    },
  ]

  // User data pour NavUser
  const userData = user
    ? {
        name: user.name,
        email: user.email,
        avatar: user.avatar_url,
      }
    : null

  return (
    <Sidebar collapsible="icon" {...props}>
      {/* Header - TOUJOURS visible immédiatement */}
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              asChild
              className="data-[slot=sidebar-menu-button]:!p-1"
            >
              <Link href="/dashboard">
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-gradient-to-br from-violet-600 to-indigo-600 text-white shadow-lg">
                  <ShieldIcon className="size-4" />
                </div>
                <div className="flex flex-col gap-0.5 leading-none">
                  <span className="font-semibold text-base">Acme</span>
                  <span className="text-xs text-muted-foreground">
                    Admin Panel
                  </span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {/* Onboarding Card */}
        {needsOnboarding && (
          <div className="px-3 pt-3">
            <Link href="/onboarding" className="block">
              <div className="rounded-lg border border-amber-200 bg-gradient-to-br from-amber-50 to-orange-50 dark:from-amber-950/30 dark:to-orange-950/30 dark:border-amber-800 p-3 space-y-3 hover:shadow-md transition-shadow">
                <div className="flex items-center gap-2">
                  <CircleUserIcon className="h-5 w-5 text-amber-600 dark:text-amber-400" />
                  <span className="text-sm font-medium text-amber-900 dark:text-amber-200">Complete your profile</span>
                </div>
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs text-amber-700 dark:text-amber-300">
                    <span>Progress</span>
                    <span>{Math.max(onboardingStep - 1, 0)}/4 steps</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-amber-200 dark:bg-amber-800 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-amber-500 transition-all"
                      style={{ width: `${(Math.max(onboardingStep - 1, 0) / 4) * 100}%` }}
                    />
                  </div>
                </div>
                <div className="flex items-center gap-1 text-xs font-medium text-amber-700 dark:text-amber-300 hover:text-amber-900 dark:hover:text-amber-100">
                  Continue
                  <ArrowRightIcon className="h-3 w-3" />
                </div>
              </div>
            </Link>
          </div>
        )}

        {/* Items statiques avec Quick Create - TOUJOURS visibles */}
        <NavMain items={staticNavItems} showQuickCreate={true} disabled={needsOnboarding} />

        {/* Items conditionnels - Visibles immédiatement si user (SSR ou hydraté) */}
        {conditionalNavItems.length > 0 && (
          <NavMain items={conditionalNavItems} showQuickCreate={false} disabled={needsOnboarding} />
        )}

        {/* Secondary nav - TOUJOURS visible */}
        <NavSecondary items={navSecondary} className="mt-auto" />
      </SidebarContent>

      {/* Footer - Affiche le user si disponible */}
      <SidebarFooter>
        {userData && <NavUser user={userData} logout={logout} />}
      </SidebarFooter>
    </Sidebar>
  )
}
