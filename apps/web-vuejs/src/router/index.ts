import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import type { PermissionAction } from '@rbac/types'

declare module 'vue-router' {
  interface RouteMeta {
    requiresAuth?: boolean
    role?: string
    permission?: { resource: string; action: PermissionAction }
    layout?: string
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    redirect: '/login',
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginPage.vue'),
    meta: { layout: 'none' },
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('@/views/RegisterPage.vue'),
    meta: { layout: 'none' },
  },
  {
    path: '/auth/callback',
    name: 'auth-callback',
    component: () => import('@/views/AuthCallbackPage.vue'),
    meta: { layout: 'none' },
  },
  {
    path: '/dashboard',
    name: 'dashboard',
    component: () => import('@/views/DashboardPage.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/dashboard/users',
    name: 'users',
    component: () => import('@/views/UsersPage.vue'),
    meta: { requiresAuth: true, role: 'admin' },
  },
  {
    path: '/dashboard/roles',
    name: 'roles',
    component: () => import('@/views/RolesPage.vue'),
    meta: { requiresAuth: true, role: 'admin' },
  },
  {
    path: '/dashboard/permissions',
    name: 'permissions',
    component: () => import('@/views/PermissionsPage.vue'),
    meta: { requiresAuth: true, role: 'admin' },
  },
  {
    path: '/dashboard/posts',
    name: 'posts',
    component: () => import('@/views/PostsPage.vue'),
    meta: { requiresAuth: true, permission: { resource: 'posts', action: 'read' } },
  },
  {
    path: '/onboarding',
    name: 'onboarding',
    component: () => import('@/views/OnboardingPage.vue'),
    meta: { requiresAuth: true, layout: 'none' },
  },
  {
    path: '/dashboard/orderbook',
    name: 'orderbook',
    component: () => import('@/views/OrderBookPage.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/dashboard/cache-debug',
    name: 'cache-debug',
    component: () => import('@/views/CacheDebugPage.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/404',
    name: 'not-found',
    component: () => import('@/views/NotFoundPage.vue'),
    meta: { layout: 'none' },
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/404',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(_to, _from, savedPosition) {
    if (savedPosition) return savedPosition
    return { top: 0 }
  },
})

router.beforeEach(async (to) => {
  const authStore = useAuthStore()

  // If route requires auth
  if (to.meta.requiresAuth) {
    // Try to initialize session (calls GET /me)
    if (!authStore.initialized) {
      await authStore.initialize()
    }

    // Not authenticated → redirect to login
    if (!authStore.user) {
      const redirectTo = to.fullPath !== '/dashboard' ? to.fullPath : undefined
      return { path: '/login', query: redirectTo ? { redirectTo } : undefined }
    }

    // Onboarding guard: allow dashboard, block other routes if onboarding incomplete
    if (authStore.needsOnboarding && to.path !== '/onboarding' && to.path !== '/dashboard') {
      return { path: '/dashboard' }
    }

    // If already onboarded, redirect away from onboarding page
    if (!authStore.needsOnboarding && to.path === '/onboarding') {
      return { path: '/dashboard' }
    }

    // Check role requirement
    if (to.meta.role && !authStore.hasRole(to.meta.role as 'admin' | 'moderator' | 'user')) {
      return { path: '/dashboard' }
    }

    // Check permission requirement
    if (to.meta.permission) {
      const { resource, action } = to.meta.permission
      if (!authStore.hasPermission(resource, action)) {
        return { path: '/dashboard' }
      }
    }
  }

  // If already authenticated, redirect away from login/register
  if (to.path === '/login' || to.path === '/register') {
    if (!authStore.initialized) {
      await authStore.initialize()
    }
    if (authStore.user) return '/dashboard'
  }
})

export default router
