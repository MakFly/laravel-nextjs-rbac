import type { Metadata } from "next";
import "./globals.css";
import { AuthInitializer } from "@/components/auth-initializer";
import { Toaster } from "@/components/ui/sonner";

export const metadata: Metadata = {
  title: "Laravel + Next.js RBAC",
  description: "Monorepo with OAuth + Role-Based Access Control",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <AuthInitializer>{children}</AuthInitializer>
        <Toaster />
      </body>
    </html>
  );
}
