"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Eye, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { login } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const data = await login(username, password);
      localStorage.setItem("token", data.access_token);
      localStorage.setItem("user", JSON.stringify({ role: data.role, full_name: data.full_name }));
      router.push("/");
    } catch {
      setError("Invalid credentials. Try admin / admin123");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-accent/5" />
      <Card className="w-full max-w-md relative z-10">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-primary/20">
            <Eye className="h-7 w-7 text-primary" />
          </div>
          <CardTitle className="text-xl">IdentityLens AI</CardTitle>
          <p className="text-sm text-muted-foreground mt-2">
            Cross-Platform Identity Risk Intelligence
          </p>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Username</label>
              <Input value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Password</label>
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Authenticating..." : "Sign In"}
            </Button>
          </form>
          <div className="mt-6 rounded-lg border border-border bg-secondary/30 p-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-2">
              <Shield className="h-3 w-3" />
              Demo Credentials
            </div>
            <p className="text-xs font-mono">admin / admin123</p>
            <p className="text-xs font-mono">analyst / analyst123</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
