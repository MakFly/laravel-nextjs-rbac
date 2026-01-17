"use client"

import { useAuthStore } from "@/stores/auth-store"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ShieldIcon, UsersIcon, KeyIcon, LockIcon, ChevronRightIcon } from "lucide-react"
import { Skeleton } from "@/components/ui/skeleton"

const features = [
  {
    icon: ShieldIcon,
    title: "Role-Based Access",
    description: "Granular permissions with role-based access control for your entire organization.",
  },
  {
    icon: UsersIcon,
    title: "User Management",
    description: "Comprehensive user management with teams, groups, and hierarchical structures.",
  },
  {
    icon: KeyIcon,
    title: "API Security",
    description: "Secure API endpoints with OAuth 2.0 and JWT token authentication.",
  },
  {
    icon: LockIcon,
    title: "Enterprise Security",
    description: "Bank-level security with audit logs, SSO integration, and compliance.",
  },
]

export default function Home() {
  const { user, isHydrated } = useAuthStore()
  const isAuthenticated = !!user

  if (!isHydrated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-violet-50/20 to-indigo-50/30">
        <div className="text-center space-y-4">
          <Skeleton className="h-16 w-16 rounded-2xl mx-auto" />
          <Skeleton className="h-8 w-48 mx-auto" />
          <Skeleton className="h-4 w-64 mx-auto" />
        </div>
      </div>
    )
  }

  if (isAuthenticated && user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-violet-50/20 to-indigo-50/30">
        {/* Hero Section */}
        <div className="relative overflow-hidden">
          {/* Background Pattern */}
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:14px_24px]" />
          <div className="absolute left-0 right-0 top-0 -z-10 m-auto h-[310px] w-[310px] rounded-full bg-violet-400/20 opacity-20 blur-[100px]" />

          <div className="container relative max-w-6xl mx-auto px-6 py-24 md:py-32">
            <div className="mx-auto max-w-3xl text-center space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-1000">
              {/* Welcome Badge */}
              <Badge className="px-4 py-1.5 text-sm bg-gradient-to-r from-violet-600 to-indigo-600 border-0 shadow-lg shadow-violet-500/20">
                Welcome back, {user.name.split(" ")[0]}!
              </Badge>

              <h1 className="text-4xl font-bold tracking-tight sm:text-6xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                Your Secure Dashboard
              </h1>

              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Manage your organization's access control, users, and permissions from one centralized platform.
              </p>

              <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
                <Button
                  asChild
                  size="lg"
                  className="group bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 shadow-lg shadow-violet-500/25"
                >
                  <Link href="/dashboard">
                    Go to Dashboard
                    <ChevronRightIcon className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
                  </Link>
                </Button>
                <Button variant="outline" size="lg" asChild>
                  <Link href={"/dashboard/settings" as any}>Settings</Link>
                </Button>
              </div>

              {/* Quick Stats */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-8 max-w-2xl mx-auto">
                <Card className="border-border/50 bg-background/50 backdrop-blur-sm">
                  <CardHeader className="p-4 pb-2">
                    <CardDescription className="text-xs">Roles</CardDescription>
                  </CardHeader>
                  <CardContent className="p-4 pt-0">
                    <p className="text-2xl font-bold">{user.roles.length}</p>
                  </CardContent>
                </Card>
                <Card className="border-border/50 bg-background/50 backdrop-blur-sm">
                  <CardHeader className="p-4 pb-2">
                    <CardDescription className="text-xs">Permissions</CardDescription>
                  </CardHeader>
                  <CardContent className="p-4 pt-0">
                    <p className="text-2xl font-bold">{user.permissions.length}</p>
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>
        </div>

        {/* Roles Section */}
        <div className="container max-w-6xl mx-auto px-6 py-16">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Your Roles</h2>
            <div className="flex flex-wrap gap-3">
              {user.roles.map((role) => (
                <Badge
                  key={role.id}
                  variant="secondary"
                  className="px-4 py-2 text-sm font-medium bg-gradient-to-r from-violet-100 to-indigo-100 text-violet-900 border-0"
                >
                  {role.name}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </div>
    )
  }

  // Landing page for non-authenticated users
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-violet-50/20 to-indigo-50/30">
      {/* Background Pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:14px_24px]" />
      <div className="absolute left-0 right-0 top-0 -z-10 m-auto h-[310px] w-[310px] rounded-full bg-violet-400/20 opacity-20 blur-[100px]" />

      {/* Hero Section */}
      <div className="container relative max-w-6xl mx-auto px-6 py-24 md:py-32">
        <div className="mx-auto max-w-3xl text-center space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-1000">
          <Badge className="px-4 py-1.5 text-sm bg-gradient-to-r from-violet-600 to-indigo-600 border-0 shadow-lg shadow-violet-500/20">
            Enterprise-Grade Security
          </Badge>

          <h1 className="text-4xl font-bold tracking-tight sm:text-6xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
            Secure Access Control
            <br />
            Made Simple
          </h1>

          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            A powerful RBAC system built with Laravel and Next.js. Manage users, roles, and permissions with ease.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
            <Button
              asChild
              size="lg"
              className="group bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 shadow-lg shadow-violet-500/25"
            >
              <Link href="/auth/register">
                Get Started
                <ChevronRightIcon className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
              </Link>
            </Button>
            <Button variant="outline" size="lg" asChild>
              <Link href="/auth/login">Sign In</Link>
            </Button>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="container max-w-6xl mx-auto px-6 py-16">
        <div className="grid md:grid-cols-2 gap-6">
          {features.map((feature, index) => (
            <Card
              key={feature.title}
              className="border-border/50 bg-background/50 backdrop-blur-sm hover:bg-background/80 transition-colors"
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <CardHeader>
                <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-violet-100 to-indigo-100 flex items-center justify-center mb-4">
                  <feature.icon className="h-6 w-6 text-violet-700" />
                </div>
                <CardTitle className="text-xl">{feature.title}</CardTitle>
                <CardDescription className="text-base">{feature.description}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      </div>

      {/* Tech Stack */}
      <div className="container max-w-6xl mx-auto px-6 py-16">
        <div className="text-center space-y-4">
          <p className="text-sm text-muted-foreground uppercase tracking-wider">Built with</p>
          <div className="flex flex-wrap justify-center gap-8 text-muted-foreground">
            <span className="font-semibold text-foreground">Laravel</span>
            <span>•</span>
            <span className="font-semibold text-foreground">Next.js 15</span>
            <span>•</span>
            <span className="font-semibold text-foreground">shadcn/ui</span>
            <span>•</span>
            <span className="font-semibold text-foreground">OAuth 2.0</span>
          </div>
        </div>
      </div>
    </div>
  )
}
