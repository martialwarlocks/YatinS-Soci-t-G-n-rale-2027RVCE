"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { AppShell } from "@/components/layout/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiFetch, riskColor } from "@/lib/api";
import { AlertTriangle } from "lucide-react";

interface Incident {
  incident_id: string;
  unified_id: string;
  user_name: string;
  severity: string;
  status: string;
  findings: string[];
  risk_score: number;
  created_at: string;
  compliance_controls: string[];
}

export default function IncidentsPage() {
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!localStorage.getItem("token")) {
      router.push("/login");
      return;
    }
    apiFetch<Incident[]>("/incidents")
      .then(setIncidents)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [router]);

  return (
    <AppShell>
      <div className="mb-8">
        <h1 className="text-2xl font-bold">Incident Center</h1>
        <p className="text-muted-foreground mt-1">Clustered identity risk alerts requiring investigation</p>
      </div>

      {loading ? (
        <p className="text-muted-foreground text-center py-12">Loading incidents...</p>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {incidents.map((inc) => (
            <Link key={inc.incident_id} href={`/incidents/${inc.incident_id}`}>
              <Card className="hover:border-primary/40 transition-colors cursor-pointer h-full">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base font-mono">{inc.incident_id}</CardTitle>
                    <span className={`text-xs px-2 py-0.5 rounded uppercase font-medium ${
                      inc.severity === "critical" ? "bg-red-500/20 text-red-400" : "bg-orange-500/20 text-orange-400"
                    }`}>{inc.severity}</span>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="font-medium mb-1">{inc.user_name}</p>
                  <p className={`text-2xl font-bold font-mono mb-3 ${riskColor(inc.risk_score)}`}>
                    Risk: {inc.risk_score}/100
                  </p>
                  <ul className="space-y-1 mb-3">
                    {inc.findings?.slice(0, 4).map((f) => (
                      <li key={f} className="flex items-start gap-2 text-xs text-muted-foreground">
                        <AlertTriangle className="h-3 w-3 text-orange-400 mt-0.5 shrink-0" />
                        {f}
                      </li>
                    ))}
                  </ul>
                  <div className="flex flex-wrap gap-1">
                    {inc.compliance_controls?.map((c) => (
                      <span key={c} className="text-xs bg-secondary px-1.5 py-0.5 rounded font-mono">{c}</span>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </AppShell>
  );
}
