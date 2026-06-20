"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { AppShell } from "@/components/layout/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { GraphViewer } from "@/components/graph/graph-viewer";
import { apiFetch, riskColor } from "@/lib/api";
import { ArrowLeft, AlertTriangle } from "lucide-react";

interface IncidentDetail {
  incident_id: string;
  unified_id: string;
  user_name: string;
  severity: string;
  status: string;
  findings: string[];
  risk_score: number;
  created_at: string;
  compliance_controls: string[];
  identity: {
    full_name: string;
    department: string;
    platform_accounts: Record<string, unknown>;
    ai_summary: string;
    remediation_actions: { platform: string; priority: string; action: string }[];
  };
  attack_paths: { target: string; path: { label: string }[] }[];
  graph: { nodes: []; edges: [] };
}

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);

  useEffect(() => {
    if (!localStorage.getItem("token")) {
      router.push("/login");
      return;
    }
    apiFetch<IncidentDetail>(`/incidents/${params.incident_id}`)
      .then(setIncident)
      .catch(console.error);
  }, [params.incident_id, router]);

  if (!incident) {
    return (
      <AppShell>
        <div className="flex h-96 items-center justify-center text-muted-foreground">Loading investigation...</div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <Link href="/incidents" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground mb-6">
        <ArrowLeft className="h-4 w-4" /> Back to Incidents
      </Link>

      <div className="flex items-start justify-between mb-8">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-2xl font-bold font-mono">{incident.incident_id}</h1>
            <span className={`text-xs px-2 py-0.5 rounded uppercase ${
              incident.severity === "critical" ? "bg-red-500/20 text-red-400" : "bg-orange-500/20 text-orange-400"
            }`}>{incident.severity}</span>
          </div>
          <p className="text-lg">{incident.user_name} · {incident.identity.department}</p>
        </div>
        <div className="text-right">
          <p className={`text-3xl font-bold font-mono ${riskColor(incident.risk_score)}`}>{incident.risk_score}/100</p>
          <Link href={`/identities/${incident.unified_id}`} className="text-xs text-primary hover:underline">
            View Identity 360° →
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader><CardTitle className="text-base">Findings</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {incident.findings?.map((f) => (
                <li key={f} className="flex items-start gap-2 text-sm">
                  <AlertTriangle className="h-4 w-4 text-orange-400 mt-0.5" />
                  {f}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">AI Analysis</CardTitle></CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed">{incident.identity.ai_summary}</p>
          </CardContent>
        </Card>
      </div>

      <Card className="mb-6">
        <CardHeader><CardTitle className="text-base">Attack Path Analysis</CardTitle></CardHeader>
        <CardContent>
          <GraphViewer graph={incident.graph} height="400px" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Remediation Actions</CardTitle></CardHeader>
        <CardContent>
          <div className="space-y-3">
            {incident.identity.remediation_actions?.map((a, i) => (
              <div key={i} className="rounded-lg border border-border p-3 flex items-start gap-3">
                <span className="text-xs bg-secondary px-2 py-0.5 rounded">{a.platform}</span>
                <p className="text-sm">{a.action}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </AppShell>
  );
}
