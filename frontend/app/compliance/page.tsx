"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { AppShell } from "@/components/layout/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiFetch, riskColor } from "@/lib/api";
import { Shield } from "lucide-react";

interface ComplianceReport {
  total_identities_assessed: number;
  identities_with_findings: number;
  compliance_score: number;
  framework_summary: Record<string, number>;
  findings: {
    identity: string;
    unified_id: string;
    framework: string;
    control: string;
    title: string;
    risk_score: number;
  }[];
}

export default function CompliancePage() {
  const router = useRouter();
  const [report, setReport] = useState<ComplianceReport | null>(null);

  useEffect(() => {
    if (!localStorage.getItem("token")) {
      router.push("/login");
      return;
    }
    apiFetch<ComplianceReport>("/compliance/report").then(setReport).catch(console.error);
  }, [router]);

  if (!report) {
    return (
      <AppShell>
        <div className="flex h-96 items-center justify-center text-muted-foreground">Generating compliance report...</div>
      </AppShell>
    );
  }

  const frameworkKeys: Record<string, string> = {
    "NIST AC-2": "NIST",
    "NIST AC-6": "NIST",
    "MITRE ATT&CK": "MITRE ATT&CK",
    "GDPR Art. 5": "GDPR",
    "GDPR Art. 32": "GDPR",
    "CIS Controls 5 & 6": "CIS",
  };

  const frameworks = [
    { name: "NIST AC-2", desc: "Account Management" },
    { name: "NIST AC-6", desc: "Least Privilege" },
    { name: "MITRE ATT&CK", desc: "Valid Accounts / Credential Access" },
    { name: "GDPR Art. 5", desc: "Principles of Processing" },
    { name: "GDPR Art. 32", desc: "Security of Processing" },
    { name: "CIS Controls 5 & 6", desc: "Account & Access Control Management" },
  ];

  return (
    <AppShell>
      <div className="mb-8">
        <h1 className="text-2xl font-bold">Compliance Module</h1>
        <p className="text-muted-foreground mt-1">Automated mapping to NIST, MITRE ATT&CK, GDPR, and CIS Controls</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-primary">{report.compliance_score}%</p>
            <p className="text-xs text-muted-foreground mt-1">Compliance Score</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{report.total_identities_assessed}</p>
            <p className="text-xs text-muted-foreground mt-1">Identities Assessed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-orange-400">{report.identities_with_findings}</p>
            <p className="text-xs text-muted-foreground mt-1">With Findings</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{Object.keys(report.framework_summary).length}</p>
            <p className="text-xs text-muted-foreground mt-1">Frameworks Mapped</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
        {frameworks.map((fw) => (
          <Card key={fw.name}>
            <CardContent className="p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-primary" />
                <p className="text-sm font-medium">{fw.name}</p>
              </div>
              <p className="text-xs text-muted-foreground">{fw.desc}</p>
              <p className="text-lg font-bold mt-2">
                {report.framework_summary[frameworkKeys[fw.name]] ?? 0} findings
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader><CardTitle className="text-base">Control Findings</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-left">
                  <th className="pb-3 pr-4">Identity</th>
                  <th className="pb-3 pr-4">Framework</th>
                  <th className="pb-3 pr-4">Control</th>
                  <th className="pb-3 pr-4">Title</th>
                  <th className="pb-3">Risk</th>
                </tr>
              </thead>
              <tbody>
                {report.findings.slice(0, 50).map((f, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-secondary/20">
                    <td className="py-2 pr-4">
                      <Link href={`/identities/${f.unified_id}`} className="hover:text-primary">{f.identity}</Link>
                    </td>
                    <td className="py-2 pr-4 text-xs">{f.framework}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{f.control}</td>
                    <td className="py-2 pr-4 text-muted-foreground">{f.title}</td>
                    <td className={`py-2 font-mono font-bold ${riskColor(f.risk_score)}`}>{f.risk_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </AppShell>
  );
}
