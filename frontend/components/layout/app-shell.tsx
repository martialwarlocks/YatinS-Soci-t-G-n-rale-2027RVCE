"use client";

import { Sidebar } from "@/components/layout/sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen grid-bg">
      <Sidebar />
      <main className="ml-64 min-h-screen p-8">{children}</main>
    </div>
  );
}
