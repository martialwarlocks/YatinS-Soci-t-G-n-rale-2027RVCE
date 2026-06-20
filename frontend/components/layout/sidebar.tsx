"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  LayoutDashboard,
  Users,
  AlertTriangle,
  Shield,
  Network,
  LogOut,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";

const nav = [
  { href: "/", label: "Executive Dashboard", icon: LayoutDashboard },
  { href: "/leaderboard", label: "Risk Leaderboard", icon: Users },
  { href: "/incidents", label: "Incident Center", icon: AlertTriangle },
  { href: "/compliance", label: "Compliance", icon: Shield },
  { href: "/graph", label: "Attack Path Explorer", icon: Network },
];

export function Sidebar() {
  const pathname = usePathname();
  const [user, setUser] = useState<{ full_name?: string; role?: string } | null>(null);

  useEffect(() => {
    const raw = localStorage.getItem("user");
    if (raw) setUser(JSON.parse(raw));
  }, []);

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "/login";
  };

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col border-r border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border px-6 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/20">
          <Eye className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h1 className="text-sm font-bold tracking-wide">IdentityLens AI</h1>
          <p className="text-xs text-muted-foreground">Risk Intelligence</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 p-4">
        {nav.map((item) => {
          const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                active
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-secondary hover:text-foreground"
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border p-4">
        {user && (
          <div className="mb-3 px-3 text-xs">
            <p className="font-medium truncate">{user.full_name}</p>
            <p className="text-muted-foreground capitalize">{user.role}</p>
          </div>
        )}
        <button
          onClick={logout}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-secondary hover:text-foreground"
        >
          <LogOut className="h-4 w-4" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
