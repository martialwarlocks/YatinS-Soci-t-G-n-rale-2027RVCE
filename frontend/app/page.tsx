"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/layout/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  RiskTrendChart,
  DepartmentRiskChart,
  PlatformPieChart,
  DormancyChart,
  PrivilegeHeatmap,
  RiskTimelineChart,
} from "@/components/charts/dashboard-charts";
import { AccessMatrix, KpiLink } from "@/components/dashboard/access-matrix";
import { PipelineBanner } from "@/components/pipeline/pipeline-banner";
import { apiFetch, riskColor } from "@/lib/api";
import { AlertTriangle, Brain, Key, ShieldAlert, Users, UserX, Zap } from "lucide-react";
import Link from "next/link";

interface KPIs {
  total_identities: number;
  high_risk_users: number;
  orphaned_accounts: number;
  dormant_admins: number;
  active_tokens: number;
  critical_incidents: number;
  ml_anomalies: number;
}

interface LeaderboardEntry {
  unified_id: string;
  name: string;
  risk_score: number;
  department: string;
  platforms: string[];
  privileges: string[];
  status: string;
}

export default function DashboardPage() {
  const router = useRouter();
  const [kpis, setKpis] = useState<KPIs | null>(null);
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [riskTrend, setRiskTrend] = useState([]);
  const [riskTimeline, setRiskTimeline] = useState([]);
  const [deptRisk, setDeptRisk] = useState([]);
  const [platforms, setPlatforms] = useState([]);
  const [dormancy, setDormancy] = useState([]);
  const [heatmap, setHeatmap] = useState([]);
  const [accessMatrix, setAccessMatrix] = useState<{ departments: string[]; platforms: string[]; data: Record<string, string | number>[] } | null>(null);
  const [dataQuality, setDataQuality] = useState<{ overall_score: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadData = useCallback(() => {
    setError("");
    Promise.all([
      apiFetch<KPIs>("/dashboard/kpis"),
      apiFetch<LeaderboardEntry[]>("/dashboard/leaderboard?limit=10"),
      apiFetch("/dashboard/risk-trend"),
      apiFetch("/dashboard/risk-timeline"),
      apiFetch("/dashboard/department-risk"),
      apiFetch("/dashboard/platform-distribution"),
      apiFetch("/dashboard/dormancy-distribution"),
      apiFetch("/dashboard/privilege-heatmap"),
      apiFetch("/dashboard/access-matrix"),
      apiFetch<{ overall_score: number }>("/pipeline/data-quality"),
    ])
      .then(([k, lb, rt, rtl, dr, pl, dm, hm, am, dq]) => {
        setKpis(k);
        setLeaderboard(lb);
        setRiskTrend(rt as never);
        setRiskTimeline(rtl as never);
        setDeptRisk(dr as never);
        setPlatforms(pl as never);
        setDormancy(dm as never);
        setHeatmap(hm as never);
        setAccessMatrix(am as never);
        setDataQuality(dq);
      })
      .catch(() => setError("Unable to reach IdentityLens API. Ensure backend is running on port 8000."))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("token")) {
      router.push("/login");
      return;
    }
    loadData();
  }, [router, loadData]);

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-96 items-center justify-center text-muted-foreground">
          Running intelligence engines...
        </div>
      </AppShell>
    );
  }

  if (error) {
    return (
      <AppShell>
        <div className="flex h-96 flex-col items-center justify-center gap-4 text-center">
          <p className="text-destructive">{error}</p>
          <button onClick={loadData} className="text-sm text-primary underline">Retry</button>
        </div>
      </AppShell>
    );
  }

  const kpiCards = [
    { label: "Total Identities", value: kpis?.total_identities, icon: Users, color: "text-blue-400", href: "/leaderboard" },
    { label: "High Risk Users", value: kpis?.high_risk_users, icon: ShieldAlert, color: "text-red-400", href: "/leaderboard" },
    { label: "ML Anomalies", value: kpis?.ml_anomalies, icon: Brain, color: "text-accent", href: "/leaderboard" },
    { label: "Orphaned Accounts", value: kpis?.orphaned_accounts, icon: UserX, color: "text-orange-400", href: "/compliance" },
    { label: "Dormant Admins", value: kpis?.dormant_admins, icon: AlertTriangle, color: "text-yellow-400", href: "/leaderboard" },
    { label: "Critical Incidents", value: kpis?.critical_incidents, icon: Zap, color: "text-red-500", href: "/incidents" },
  ];

  return (
    <AppShell>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Executive Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Cross-platform identity risk intelligence · Data quality score:{" "}
            <span className="text-primary font-semibold">{dataQuality?.overall_score ?? "—"}%</span>
          </p>
        </div>
      </div>

      <PipelineBanner onComplete={loadData} />

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-8">
        {kpiCards.map((kpi) => (
          <KpiLink key={kpi.label} href={kpi.href}>
            <Card className="h-full hover:border-primary/40 transition-colors">
              <CardContent className="p-4">
                <kpi.icon className={`h-4 w-4 ${kpi.color} mb-2`} />
                <p className="text-2xl font-bold">{kpi.value?.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground mt-1">{kpi.label}</p>
              </CardContent>
            </Card>
          </KpiLink>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader><CardTitle className="text-base">Security Event Timeline (30 days)</CardTitle></CardHeader>
          <CardContent><RiskTimelineChart data={riskTimeline as never} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">Risk Score Distribution</CardTitle></CardHeader>
          <CardContent><RiskTrendChart data={riskTrend} /></CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader><CardTitle className="text-base">Cross-Platform Access Matrix</CardTitle></CardHeader>
          <CardContent>{accessMatrix && <AccessMatrix matrix={accessMatrix} />}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">Platform Access Distribution</CardTitle></CardHeader>
          <CardContent><PlatformPieChart data={platforms} /></CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardHeader><CardTitle className="text-base">Department Risk Ranking</CardTitle></CardHeader>
          <CardContent><DepartmentRiskChart data={deptRisk} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">Dormancy Distribution</CardTitle></CardHeader>
          <CardContent><DormancyChart data={dormancy} /></CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader><CardTitle className="text-base">Privilege Heatmap</CardTitle></CardHeader>
          <CardContent><PrivilegeHeatmap data={heatmap as never} /></CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">Top Risk Identities</CardTitle>
            <Link href="/leaderboard" className="text-xs text-primary hover:underline">View all →</Link>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {leaderboard.map((entry, i) => (
                <Link
                  key={entry.unified_id}
                  href={`/identities/${entry.unified_id}`}
                  className="flex items-center justify-between rounded-lg border border-border p-3 hover:bg-secondary/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-5">{i + 1}</span>
                    <div>
                      <p className="text-sm font-medium">{entry.name}</p>
                      <p className="text-xs text-muted-foreground">{entry.department}</p>
                    </div>
                  </div>
                  <span className={`text-lg font-bold font-mono ${riskColor(entry.risk_score)}`}>{entry.risk_score}</span>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
