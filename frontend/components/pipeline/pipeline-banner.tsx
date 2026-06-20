"use client";

import { useEffect, useState } from "react";
import { Activity, Cpu, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { apiFetch } from "@/lib/api";

interface PipelineStatus {
  last_run: string | null;
  identities_processed: number;
  audit_events: number;
  open_incidents: number;
  engines: { name: string; status: string; description: string }[];
}

export function PipelineBanner({ onComplete }: { onComplete?: () => void }) {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [running, setRunning] = useState(false);

  const load = () => apiFetch<PipelineStatus>("/pipeline/status").then(setStatus).catch(console.error);

  useEffect(() => {
    load();
  }, []);

  const runPipeline = async () => {
    setRunning(true);
    try {
      await apiFetch("/pipeline/run", { method: "POST" });
      await load();
      onComplete?.();
    } catch (e) {
      console.error(e);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="glass-panel rounded-lg p-4 mb-6 border border-primary/20">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/20">
            <Cpu className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h2 className="text-sm font-semibold flex items-center gap-2">
              Intelligence Pipeline
              <span className="inline-flex h-2 w-2 rounded-full bg-green-400 animate-pulse" />
            </h2>
            <p className="text-xs text-muted-foreground">
              {status
                ? `${status.identities_processed} identities · ${status.audit_events} audit events · ${status.open_incidents} open incidents`
                : "Loading pipeline status..."}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {status?.engines.slice(0, 3).map((e) => (
            <span key={e.name} className="hidden md:inline text-xs bg-secondary px-2 py-1 rounded">
              {e.name.split(" ")[0]}
            </span>
          ))}
          <Button size="sm" variant="outline" onClick={runPipeline} disabled={running}>
            {running ? (
              <><RefreshCw className="h-3 w-3 mr-1 animate-spin" /> Running...</>
            ) : (
              <><Activity className="h-3 w-3 mr-1" /> Recompute Intelligence</>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
