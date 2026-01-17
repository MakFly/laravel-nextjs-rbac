"use client";

import { useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuthStore } from "@/stores/auth-store";

function OAuthCallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { refreshUser } = useAuthStore();

  useEffect(() => {
    const handleCallback = async () => {
      const token = searchParams.get("token");
      const error = searchParams.get("error");

      if (error) {
        router.push(`/auth/login?error=${encodeURIComponent(error)}`);
        return;
      }

      if (token) {
        // Le token est maintenant géré côté serveur via cookie HttpOnly
        // On rafraîchit simplement l'utilisateur depuis le store
        try {
          await refreshUser();
          router.push("/dashboard");
        } catch {
          router.push("/auth/login?error=oauth_failed");
        }
      } else {
        router.push("/auth/login?error=oauth_failed");
      }
    };

    handleCallback();
  }, [router, searchParams, refreshUser]);

  return (
    <main className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-violet-600 mx-auto" />
        <p className="mt-4 text-gray-600">Completing authentication...</p>
      </div>
    </main>
  );
}

export default function OAuthCallbackPage() {
  return (
    <Suspense fallback={
      <main className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-violet-600 mx-auto" />
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </main>
    }>
      <OAuthCallbackContent />
    </Suspense>
  );
}
