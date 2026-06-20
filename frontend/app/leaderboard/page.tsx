"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Search } from "lucide-react";
import { AppShell } from "@/components/layout/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch, riskColor, riskBg } from "@/lib/api";

interface Entry {
  unified_id: string;
  name: string;
  risk_score: number;
  department: string;
  platforms: string[];
  privileges: string[];
  status: string;
  is_anomaly: boolean;
}

export default function LeaderboardPage() {
  const router = useRouter();
  const [entries, setEntries] = useState<Entry[]>([]);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("risk_score");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!localStorage.getItem("token")) {
      router.push("/login");
      return;
    }
    loadEntries("");
  }, [router]);

  const loadEntries = (q: string) => {
    setLoading(true);
    apiFetch<Entry[]>(`/dashboard/leaderboard?limit=20&q=${encodeURIComponent(q)}&sort_by=${sortBy}`)
      .then(setEntries)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = setTimeout(() => loadEntries(search), 300);
    return () => clearTimeout(timer);
  }, [search, sortBy]);

  return (
    <AppShell>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Identity Risk Leaderboard</h1>
          <p className="text-muted-foreground mt-1">Top 20 highest-risk identities across all platforms</p>
        </div>
        <div className="flex gap-3">
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="h-10 rounded-md border border-border bg-secondary px-3 text-sm"
          >
            <option value="risk_score">Sort by Risk</option>
            <option value="name">Sort by Name</option>
            <option value="department">Sort by Department</option>
          </select>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search identities..."
              className="pl-9 w-64"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Risk Rankings</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-muted-foreground text-center py-8">Loading...</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-muted-foreground text-left">
                    <th className="pb-3 pr-4 font-medium">#</th>
                    <th className="pb-3 pr-4 font-medium">Name</th>
                    <th className="pb-3 pr-4 font-medium">Risk Score</th>
                    <th className="pb-3 pr-4 font-medium">Department</th>
                    <th className="pb-3 pr-4 font-medium">Platforms</th>
                    <th className="pb-3 pr-4 font-medium">Privileges</th>
                    <th className="pb-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry, i) => (
                    <tr
                      key={entry.unified_id}
                      className="border-b border-border/50 hover:bg-secondary/30 cursor-pointer"
                      onClick={() => router.push(`/identities/${entry.unified_id}`)}
                    >
                      <td className="py-3 pr-4 text-muted-foreground">{i + 1}</td>
                      <td className="py-3 pr-4">
                        <Link href={`/identities/${entry.unified_id}`} className="font-medium hover:text-primary">
                          {entry.name}
                          {entry.is_anomaly && (
                            <span className="ml-2 text-xs bg-accent/20 text-accent px-1.5 py-0.5 rounded">ML Anomaly</span>
                          )}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded border font-mono font-bold ${riskBg(entry.risk_score)} ${riskColor(entry.risk_score)}`}>
                          {entry.risk_score}
                        </span>
                      </td>
                      <td className="py-3 pr-4 text-muted-foreground">{entry.department}</td>
                      <td className="py-3 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {entry.platforms?.slice(0, 3).map((p) => (
                            <span key={p} className="text-xs bg-secondary px-1.5 py-0.5 rounded">{p.split(" ")[0]}</span>
                          ))}
                          {(entry.platforms?.length || 0) > 3 && (
                            <span className="text-xs text-muted-foreground">+{entry.platforms.length - 3}</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {entry.privileges?.map((p) => (
                            <span key={p} className="text-xs bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded">{p}</span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3">
                        <span className={`text-xs px-2 py-0.5 rounded ${entry.status === "active" ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}`}>
                          {entry.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </AppShell>
  );
}
