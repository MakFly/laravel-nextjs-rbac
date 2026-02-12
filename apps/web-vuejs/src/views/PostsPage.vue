<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getPosts, type Post } from '@/lib/api/admin'
import { usePermissions } from '@/composables/usePermissions'
import AppSidebar from '@/components/AppSidebar.vue'
import SiteHeader from '@/components/SiteHeader.vue'
import { Button } from '@/components/ui/button'
import {
  SidebarInset,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { toast } from 'vue-sonner'

const { hasPermission, isAdmin } = usePermissions()
const posts = ref<Post[]>([])
const isLoading = ref(true)

const canCreate = hasPermission('posts', 'create') || isAdmin.value
const canDelete = hasPermission('posts', 'delete') || isAdmin.value

onMounted(async () => {
  try {
    posts.value = await getPosts(20)
  } catch {
    toast.error('Failed to load posts')
  } finally {
    isLoading.value = false
  }
})
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <SiteHeader />
      <div class="flex flex-1 flex-col gap-4 py-4 md:gap-6 md:py-6">
        <div class="flex items-center justify-between px-4 lg:px-6">
          <div class="flex flex-col gap-1">
            <h1 class="text-3xl font-bold tracking-tight">Posts</h1>
            <p class="text-muted-foreground">RBAC-protected resource demonstration</p>
          </div>
          <Button v-if="canCreate" disabled>
            Create Post
          </Button>
        </div>

        <div class="px-4 lg:px-6">
          <div v-if="isLoading" class="text-muted-foreground text-center py-8">Loading...</div>
          <div v-else class="rounded-xl border">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b bg-muted/50">
                  <th class="px-4 py-3 text-left font-medium w-12">#</th>
                  <th class="px-4 py-3 text-left font-medium">Title</th>
                  <th class="px-4 py-3 text-left font-medium hidden md:table-cell">Body</th>
                  <th v-if="canDelete" class="px-4 py-3 text-left font-medium w-24">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="post in posts" :key="post.id" class="border-b last:border-0">
                  <td class="px-4 py-3 text-muted-foreground">{{ post.id }}</td>
                  <td class="px-4 py-3 font-medium">{{ post.title }}</td>
                  <td class="px-4 py-3 text-muted-foreground hidden md:table-cell max-w-md truncate">
                    {{ post.body }}
                  </td>
                  <td v-if="canDelete" class="px-4 py-3">
                    <Button variant="ghost" size="sm" class="text-destructive" disabled>
                      Delete
                    </Button>
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
