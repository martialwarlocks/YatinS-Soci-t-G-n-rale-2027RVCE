"use client";

import { cn } from "@/lib/utils";
import { riskColor } from "@/lib/api";
import {
  AlertTriangle,
  ArrowRight,
  Database,
  Key,
  Shield,
  Target,
  Zap,
} from "lucide-react";

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

export function ViewToggle({
  view,
  onChange,
}: {
  view: "executive" | "technical";
  onChange: (v: "executive" | "technical") => void;
}) {
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="inline-flex rounded-lg border border-border bg-secondary/50 p-1">
        {(["technical", "executive"] as const).map((mode) => (
          <button
            key={mode}
            onClick={() => onChange(mode)}
            className={cn(
              "px-4 py-2 text-sm font-medium rounded-md transition-all capitalize",
              view === mode
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            {mode} View
          </button>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        {view === "technical" ? "Graphs · Permissions · Logs" : "CISO org-wide metrics"}
      </p>
    </div>
  );
}

export function IdentityHero({
  name,
  role,
  department,
  employeeId,
  briefing,
}: {
  name: string;
  role: string;
  department: string;
  employeeId: string;
  briefing: HeroBriefing;
}) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-red-500/30 bg-gradient-to-br from-red-950/40 via-background to-background mb-8">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_rgba(239,68,68,0.15),_transparent_60%)]" />
      <div className="relative p-6 md:p-8">
        <div className="flex flex-wrap items-start justify-between gap-6 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-red-500/40 bg-red-500/10 px-3 py-1 text-xs font-bold tracking-wider text-red-400 mb-4">
              <AlertTriangle className="h-3.5 w-3.5" />
              {briefing.severity_label}
            </div>
            <h1 className="text-3xl md:text-4xl font-bold tracking-tight">{name}</h1>
            <p className="text-muted-foreground mt-2">
              {role} · {department} · {employeeId}
            </p>
          </div>
          <div className="text-center rounded-2xl border border-red-500/40 bg-red-500/5 px-8 py-5 min-w-[140px]">
            <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">Risk Score</p>
            <p className={cn("text-5xl font-bold font-mono tabular-nums", riskColor(briefing.risk_score))}>
              {Math.round(briefing.risk_score)}
            </p>
            <p className="text-sm text-muted-foreground">/100</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="space-y-4">
            <Section title="Elevated Privileges" icon={Shield}>
              <ul className="space-y-2">
                {briefing.critical_privileges.map((p) => (
                  <li key={p} className="flex items-center gap-2 text-sm font-mono text-red-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-red-400 shrink-0" />
                    {p}
                  </li>
                ))}
              </ul>
            </Section>

            <div className="space-y-2">
              {briefing.token_alert && (
                <AlertPill icon={Key} text={briefing.token_alert} variant="warning" />
              )}
              {briefing.dormancy_alert && (
                <AlertPill icon={Zap} text={briefing.dormancy_alert} variant="danger" />
              )}
            </div>
          </div>

          <div className="space-y-4">
            <Section title="Access To" icon={Database}>
              <ul className="space-y-2">
                {briefing.accessible_resources.map((r) => (
                  <li key={r} className="text-sm flex items-center gap-2">
                    <ArrowRight className="h-3.5 w-3.5 text-orange-400" />
                    {r}
                  </li>
                ))}
              </ul>
            </Section>

            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4">
              <p className="text-xs uppercase tracking-wider text-red-400 mb-1">Potential Blast Radius</p>
              <p className="text-3xl font-bold font-mono text-red-300">{briefing.blast_radius_label}</p>
            </div>
          </div>

          <div className="space-y-4">
            <Section title="MITRE ATT&CK" icon={Target}>
              <div className="flex flex-wrap gap-2">
                {briefing.mitre_techniques.map((m) => (
                  <span
                    key={m.id}
                    className="rounded-lg border border-border bg-secondary/80 px-3 py-2 text-xs font-mono"
                  >
                    <span className="text-primary">{m.id}</span>
                    <span className="text-muted-foreground ml-2">{m.name}</span>
                  </span>
                ))}
              </div>
            </Section>

            <Section title="Recommended Actions">
              <ul className="space-y-2">
                {briefing.recommended_actions.map((a) => (
                  <li key={a} className="flex items-center gap-2 text-sm">
                    <span className="flex h-5 w-5 items-center justify-center rounded bg-green-500/20 text-green-400 text-xs">✓</span>
                    {a}
                  </li>
                ))}
              </ul>
            </Section>
          </div>
        </div>

        {briefing.attack_chain.length > 0 && (
          <div className="mt-8 pt-6 border-t border-border/50">
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-4">Attack Path</p>
            <div className="flex flex-wrap items-center gap-2 md:gap-0">
              {briefing.attack_chain.map((step, i) => (
                <div key={`${step.label}-${i}`} className="flex items-center">
                  <div
                    className={cn(
                      "rounded-lg border px-4 py-3 text-sm font-medium",
                      step.type === "Impact"
                        ? "border-red-500/50 bg-red-500/15 text-red-300 font-mono"
                        : step.type === "Role"
                          ? "border-orange-500/40 bg-orange-500/10 text-orange-300"
                          : "border-border bg-secondary/60"
                    )}
                  >
                    {step.label}
                  </div>
                  {i < briefing.attack_chain.length - 1 && (
                    <ArrowRight className="h-5 w-5 text-muted-foreground mx-2 md:mx-4 shrink-0" />
                  )}
                </div>
              ))}
            </div>
            <div className="mt-6 rounded-xl border border-red-500/40 bg-gradient-to-r from-red-500/20 to-transparent p-5">
              <p className="text-xs uppercase tracking-wider text-red-400 mb-1">Potential Impact</p>
              <p className="text-2xl md:text-3xl font-bold text-red-200">{briefing.potential_impact_label}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function ExecutiveBriefingPanel({ context }: { context: ExecutiveContext }) {
  const metrics = [
    { label: "High Risk Identities", value: context.high_risk_identities, accent: "text-red-400" },
    { label: "Potential Data Exposure", value: context.potential_data_exposure_label, accent: "text-orange-400" },
    { label: "Dormant Admins", value: context.dormant_admins, accent: "text-yellow-400" },
    { label: "Offboarding Gaps", value: context.offboarding_gaps, accent: "text-purple-400" },
    { label: "Critical Findings", value: context.critical_findings, accent: "text-red-500" },
  ];

  return (
    <div className="rounded-2xl border border-border bg-card/50 p-6 md:p-8 mb-8">
      <h2 className="text-lg font-semibold mb-1">Executive Risk Summary</h2>
      <p className="text-sm text-muted-foreground mb-6">Organization-wide exposure if this identity class is left unremediated</p>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {metrics.map((m) => (
          <div key={m.label} className="rounded-xl border border-border bg-secondary/30 p-4 text-center">
            <p className={cn("text-2xl md:text-3xl font-bold font-mono tabular-nums", m.accent)}>{m.value}</p>
            <p className="text-xs text-muted-foreground mt-2 leading-snug">{m.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function Section({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon?: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="text-xs uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
        {Icon && <Icon className="h-3.5 w-3.5" />}
        {title}
      </h3>
      {children}
    </div>
  );
}

function AlertPill({
  icon: Icon,
  text,
  variant,
}: {
  icon: React.ComponentType<{ className?: string }>;
  text: string;
  variant: "warning" | "danger";
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-lg border px-3 py-2 text-sm",
        variant === "danger"
          ? "border-red-500/30 bg-red-500/10 text-red-300"
          : "border-yellow-500/30 bg-yellow-500/10 text-yellow-300"
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      {text}
    </div>
  );
}
