"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/stores/auth-store";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
  requiredPermission?: { resource: string; action: string };
  fallback?: React.ReactNode;
}

export function ProtectedRoute({
  children,
  requiredRole,
  requiredPermission,
  fallback,
}: ProtectedRouteProps) {
  const router = useRouter();
  const { user, isHydrated, hasRole, hasPermission } = useAuthStore();
  const isAuthenticated = !!user;

  useEffect(() => {
    if (isHydrated && !isAuthenticated) {
      router.push("/auth/login");
    }
  }, [isHydrated, isAuthenticated, router]);

  if (!isHydrated) {
    return (
      fallback || (
        <div className="min-h-screen flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900" />
        </div>
      )
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  // Check role requirement
  if (requiredRole && !hasRole(requiredRole as any)) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-red-600">Access Denied</h1>
          <p className="mt-2 text-gray-600">
            You need the "{requiredRole}" role to access this page.
          </p>
        </div>
      </div>
    );
  }

  // Check permission requirement
  if (
    requiredPermission &&
    !hasPermission(requiredPermission.resource, requiredPermission.action as any)
  ) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-red-600">Access Denied</h1>
          <p className="mt-2 text-gray-600">
            You need the "{requiredPermission.resource}.{requiredPermission.action}" permission.
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
