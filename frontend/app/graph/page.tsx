"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/layout/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { GraphViewer } from "@/components/graph/graph-viewer";
import { apiFetch } from "@/lib/api";

interface GraphStats {
  total_nodes?: number;
  total_edges?: number;
  node_types?: Record<string, number>;
}

export default function GraphExplorerPage() {
  const router = useRouter();
  const [graph, setGraph] = useState<{ nodes: []; edges: [] }>({ nodes: [], edges: [] });
  const [stats, setStats] = useState<GraphStats>({});

  useEffect(() => {
    if (!localStorage.getItem("token")) {
      router.push("/login");
      return;
    }
    apiFetch<{ graph: { nodes: []; edges: [] }; stats: GraphStats }>("/graph/global")
      .then((data) => {
        setGraph(data.graph);
        setStats(data.stats);
      })
      .catch(console.error);
  }, [router]);

  return (
    <AppShell>
      <div className="mb-8">
        <h1 className="text-2xl font-bold">Attack Path Explorer</h1>
        <p className="text-muted-foreground mt-1">
          Identity graph powered by NetworkX — users, groups, roles, resources, and tokens
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <Card><CardContent className="p-4"><p className="text-2xl font-bold">{stats.total_nodes ?? 0}</p><p className="text-xs text-muted-foreground">Total Nodes</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-2xl font-bold">{stats.total_edges ?? 0}</p><p className="text-xs text-muted-foreground">Total Edges</p></CardContent></Card>
        {stats.node_types &&
          Object.entries(stats.node_types).map(([type, count]) => (
          <Card key={type}><CardContent className="p-4"><p className="text-2xl font-bold">{count}</p><p className="text-xs text-muted-foreground">{type}s</p></CardContent></Card>
        ))}
      </div>

      <Card>
        <CardHeader><CardTitle className="text-base">Global Identity Graph</CardTitle></CardHeader>
        <CardContent>
          <GraphViewer graph={graph} height="600px" />
          <div className="flex flex-wrap gap-4 mt-4 text-xs">
            {[
              { color: "#3b82f6", label: "User" },
              { color: "#8b5cf6", label: "Group" },
              { color: "#f59e0b", label: "Role" },
              { color: "#ef4444", label: "Resource" },
              { color: "#06b6d4", label: "Platform" },
              { color: "#ec4899", label: "Token" },
            ].map((l) => (
              <div key={l.label} className="flex items-center gap-2">
                <div className="h-3 w-3 rounded" style={{ background: l.color }} />
                {l.label}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </AppShell>
  );
}
