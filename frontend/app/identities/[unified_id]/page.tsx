"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { AppShell } from "@/components/layout/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { GraphViewer } from "@/components/graph/graph-viewer";
import {
  ExecutiveBriefingPanel,
  IdentityHero,
  ViewToggle,
} from "@/components/identity/identity-hero";
import { apiFetch } from "@/lib/api";
import { AlertTriangle, ArrowLeft, Bot, CheckCircle2, Clock, Key, Shield } from "lucide-react";

interface HeroBriefing {
  severity_label: string;
  risk_score: number;
  critical_privileges: string[];
  token_alert: string | null;
  dormancy_alert: string | null;
  accessible_resources: string[];
  blast_radius_records: number;
  blast_radius_label: string;
  potential_impact_label: string;
  mitre_techniques: { id: string; name: string }[];
  recommended_actions: string[];
  attack_chain: { label: string; type: string; records?: number }[];
}

interface ExecutiveContext {
  high_risk_identities: number;
  potential_data_exposure_records: number;
  potential_data_exposure_label: string;
  dormant_admins: number;
  offboarding_gaps: number;
  critical_findings: number;
}

interface IdentityProfile {
  unified_id: string;
  employee_id: string;
  full_name: string;
  email: string;
  department: string;
  role: string;
  manager: string;
  employment_status: string;
  platform_accounts: Record<string, { username: string; account_status: string; privilege_level: string; last_login: string }>;
  direct_privileges: { platform: string; privilege: string }[];
  effective_privileges: { platform: string; privilege: string; inherited_groups: string[]; paths: string[] }[];
  risk_score: number;
  risk_factors: string[];
  risk_breakdown: Record<string, number>;
  ai_summary: string;
  ai_analysis?: { root_causes: string[]; attack_narrative: string };
  resolution_map?: { platform: string; username: string; email: string }[];
  remediation_actions: { id?: string; platform: string; priority: string; action: string; status?: string }[];
  compliance_mappings: { framework: string; control: string; title: string }[];
  access_timeline: { timestamp: string; event_type: string; platform: string; details: string; severity: string; geo_location: string }[];
  tokens: { token_name: string; platform: string; age_days: number; rotation_status: string; permissions: string[] }[];
  attack_paths: { target: string; path: { label: string; type: string }[] }[];
  graph: { nodes: []; edges: [] };
  hero_briefing: HeroBriefing;
  executive_context: ExecutiveContext;
}

export default function IdentityProfilePage() {
  const params = useParams();
  const router = useRouter();
  const unifiedId = params.unified_id as string;
  const [profile, setProfile] = useState<IdentityProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"executive" | "technical">("technical");

  useEffect(() => {
    if (!localStorage.getItem("token")) {
      router.push("/login");
      return;
    }
    if (!unifiedId) return;

    setLoading(true);
    setError(null);
    setProfile(null);

    apiFetch<IdentityProfile>(`/identities/${encodeURIComponent(unifiedId)}`)
      .then(setProfile)
      .catch((err) => {
        console.error(err);
        setError("Unable to load identity analysis. Check that the backend is running on port 8000.");
      })
      .finally(() => setLoading(false));
  }, [unifiedId, router]);

  const approveAction = async (actionId: string) => {
    await apiFetch(`/identities/${unifiedId}/remediation/${actionId}`, {
      method: "PATCH",
      body: JSON.stringify({ status: "approved" }),
    });
    setProfile((p) =>
      p
        ? {
            ...p,
            remediation_actions: p.remediation_actions.map((a) =>
              a.id === actionId ? { ...a, status: "approved" } : a
            ),
          }
        : p
    );
  };

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-96 items-center justify-center text-muted-foreground">
          Building Identity 360° intelligence...
        </div>
      </AppShell>
    );
  }

  if (error || !profile) {
    return (
      <AppShell>
        <div className="flex h-96 flex-col items-center justify-center gap-4 text-center px-6">
          <AlertTriangle className="h-10 w-10 text-red-400" />
          <p className="text-muted-foreground max-w-md">{error || "Identity not found."}</p>
          <div className="flex gap-3">
            <Button variant="outline" onClick={() => router.push("/leaderboard")}>
              Back to Leaderboard
            </Button>
            <Button onClick={() => window.location.reload()}>Retry</Button>
          </div>
        </div>
      </AppShell>
    );
  }

  const briefing = profile.hero_briefing ?? {
    severity_label: profile.risk_score >= 85 ? "CRITICAL IDENTITY" : "HIGH RISK IDENTITY",
    risk_score: profile.risk_score,
    critical_privileges: profile.effective_privileges?.slice(0, 3).map(
      (ep) => `${ep.privilege} (${ep.platform.split(" ")[0]})`
    ) ?? [],
    token_alert: profile.tokens?.[0] ? `${profile.tokens[0].age_days}-day-old API Token` : null,
    dormancy_alert: null,
    accessible_resources: [],
    blast_radius_records: 0,
    blast_radius_label: "—",
    potential_impact_label: "Risk assessment pending",
    mitre_techniques: [{ id: "T1078", name: "Valid Accounts" }],
    recommended_actions: profile.remediation_actions?.slice(0, 3).map((a) => a.action) ?? [],
    attack_chain: [],
  };

  const breakdownLabels: Record<string, string> = {
    privilege_risk: "Privilege Risk",
    dormancy_risk: "Dormancy Risk",
    offboarding_risk: "Offboarding Risk",
    token_risk: "Token Risk",
    behavior_risk: "Behavior Risk",
    escalation_risk: "Escalation Risk",
    platform_spread_risk: "Platform Spread",
  };

  return (
    <AppShell>
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <Link
          href="/leaderboard"
          className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to Leaderboard
        </Link>
        <ViewToggle view={view} onChange={setView} />
      </div>

      <IdentityHero
        name={profile.full_name}
        role={profile.role}
        department={profile.department}
        employeeId={profile.employee_id}
        briefing={briefing}
      />

      {view === "executive" ? (
        <>
          <ExecutiveBriefingPanel context={profile.executive_context} />
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Bot className="h-4 w-4 text-primary" /> AI Risk Summary
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm leading-relaxed">{profile.ai_summary}</p>
              {profile.risk_factors?.length > 0 && (
                <ul className="mt-4 space-y-2">
                  {profile.risk_factors.map((factor) => (
                    <li key={factor} className="text-sm text-red-300 flex items-center gap-2">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                      {factor}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Identity Graph & Attack Paths</CardTitle>
              </CardHeader>
              <CardContent>
                <GraphViewer graph={profile.graph} height="380px" />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Shield className="h-4 w-4" /> Effective Permissions
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {profile.effective_privileges?.map((ep) => (
                  <div key={ep.platform} className="border-b border-border/40 pb-3 last:border-0">
                    <div className="flex justify-between text-sm mb-1">
                      <span>{ep.platform}</span>
                      <span className="font-mono text-red-400">{ep.privilege}</span>
                    </div>
                    {ep.paths?.slice(0, 2).map((path) => (
                      <p key={path} className="text-xs font-mono text-muted-foreground ml-2">
                        {path}
                      </p>
                    ))}
                  </div>
                ))}
                <div className="pt-2">
                  <p className="text-xs text-muted-foreground mb-2">Direct Privileges</p>
                  {profile.direct_privileges?.map((dp) => (
                    <div key={dp.platform} className="flex justify-between text-xs py-1">
                      <span>{dp.platform}</span>
                      <span className="font-mono">{dp.privilege}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Clock className="h-4 w-4" /> Audit Logs (90 days)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="max-h-96 overflow-y-auto space-y-2">
                  {profile.access_timeline?.slice(0, 25).map((event, i) => (
                    <div key={i} className="flex items-start gap-3 text-xs border-b border-border/30 pb-2">
                      <span className="text-muted-foreground font-mono shrink-0 w-24">
                        {new Date(event.timestamp).toLocaleDateString()}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded shrink-0 ${
                          event.severity === "critical" ? "bg-red-500/10 text-red-400" : "bg-secondary"
                        }`}
                      >
                        {event.event_type}
                      </span>
                      <span className="text-muted-foreground flex-1">{event.details}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Key className="h-4 w-4" /> Tokens & Platform Accounts
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {profile.tokens?.map((token) => (
                  <div key={token.token_name} className="rounded-lg border border-border p-3">
                    <div className="flex justify-between text-sm">
                      <span className="font-medium">{token.token_name}</span>
                      <span className="text-red-400">{token.age_days} days</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {token.platform} · {token.permissions?.join(", ")}
                    </p>
                  </div>
                ))}
                {Object.entries(profile.platform_accounts || {}).map(([platform, acct]) => (
                  <div key={platform} className="flex justify-between text-sm border-t border-border/40 pt-2">
                    <span>{platform}</span>
                    <span className="font-mono text-xs">{acct.username}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <Bot className="h-4 w-4 text-primary" /> AI Copilot Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm leading-relaxed">{profile.ai_summary}</p>
              {profile.ai_analysis?.attack_narrative && (
                <p className="text-sm text-muted-foreground mt-3">{profile.ai_analysis.attack_narrative}</p>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Risk Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                {Object.entries(profile.risk_breakdown || {}).map(([key, value]) => (
                  <div key={key} className="mb-3">
                    <div className="flex justify-between text-sm mb-1">
                      <span>{breakdownLabels[key] || key}</span>
                      <span className="font-mono">{value}</span>
                    </div>
                    <div className="h-2 rounded-full bg-secondary overflow-hidden">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${Math.min(Number(value) * 2.5, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-400" /> Remediation Queue
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {profile.remediation_actions?.map((action, i) => (
                  <div key={action.id || i} className="rounded-lg border border-border p-3 flex justify-between gap-3">
                    <div>
                      <p className="text-sm">{action.action}</p>
                      <p className="text-xs text-muted-foreground mt-1">{action.platform}</p>
                    </div>
                    {action.status === "approved" ? (
                      <span className="text-xs text-green-400 shrink-0">Approved</span>
                    ) : action.id ? (
                      <Button size="sm" variant="outline" className="h-7 text-xs shrink-0" onClick={() => approveAction(action.id!)}>
                        Approve
                      </Button>
                    ) : null}
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {profile.resolution_map && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Cross-Platform Identity Resolution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {profile.resolution_map.map((r) => (
                    <div key={r.platform} className="rounded-lg border border-border p-3">
                      <p className="text-xs text-muted-foreground">{r.platform}</p>
                      <p className="font-mono text-sm mt-1">{r.username}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </AppShell>
  );
}
