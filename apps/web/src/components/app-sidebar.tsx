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
} from "lucide-react"

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
                  <span className="font-semibold text-base">RBAC</span>
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
        {/* Items statiques avec Quick Create - TOUJOURS visibles */}
        <NavMain items={staticNavItems} showQuickCreate={true} />

        {/* Items conditionnels - Visibles immédiatement si user (SSR ou hydraté) */}
        {conditionalNavItems.length > 0 && (
          <NavMain items={conditionalNavItems} showQuickCreate={false} />
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
