"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  CartesianGrid,
} from "recharts";

const COLORS = ["#22c55e", "#eab308", "#f97316", "#ef4444"];
const PLATFORM_COLORS = ["#3b82f6", "#8b5cf6", "#06b6d4", "#f59e0b", "#ec4899", "#10b981"];

interface ChartProps {
  data: Record<string, unknown>[];
}

export function RiskTrendChart({ data }: ChartProps) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="range" stroke="#94a3b8" fontSize={12} />
        <YAxis stroke="#94a3b8" fontSize={12} />
        <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((_, i) => (
            <Cell key={i} fill={COLORS[i % COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function DepartmentRiskChart({ data }: ChartProps) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={data} layout="vertical">
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis type="number" stroke="#94a3b8" fontSize={12} domain={[0, 100]} />
        <YAxis dataKey="department" type="category" stroke="#94a3b8" fontSize={11} width={100} />
        <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} />
        <Bar dataKey="avg_risk" fill="#3b82f6" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function PlatformPieChart({ data }: ChartProps) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={data}
          dataKey="count"
          nameKey="platform"
          cx="50%"
          cy="50%"
          outerRadius={80}
          label={({ platform, count }) => `${platform?.split(" ")[0]}: ${count}`}
          labelLine={false}
          fontSize={10}
        >
          {data.map((_, i) => (
            <Cell key={i} fill={PLATFORM_COLORS[i % PLATFORM_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function DormancyChart({ data }: ChartProps) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="range" stroke="#94a3b8" fontSize={11} />
        <YAxis stroke="#94a3b8" fontSize={12} />
        <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} />
        <Area type="monotone" dataKey="count" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.3} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function RiskTimelineChart({ data }: { data: { date: string; events: number }[] }) {
  const formatted = data.map((d) => ({
    ...d,
    label: new Date(d.date).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
  }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={formatted}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="label" stroke="#94a3b8" fontSize={10} interval={4} />
        <YAxis stroke="#94a3b8" fontSize={12} />
        <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} />
        <Area type="monotone" dataKey="events" stroke="#ef4444" fill="#ef4444" fillOpacity={0.25} name="High-severity events" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function PrivilegeHeatmap({ data }: { data: { platform: string; privilege: string; count: number }[] }) {
  const platforms = Array.from(new Set(data.map((d) => d.platform)));
  const privileges = Array.from(new Set(data.map((d) => d.privilege))).slice(0, 8);
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  const getCount = (platform: string, privilege: string) =>
    data.find((d) => d.platform === platform && d.privilege === privilege)?.count || 0;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr>
            <th className="p-2 text-left text-muted-foreground">Platform</th>
            {privileges.map((p) => (
              <th key={p} className="p-2 text-center text-muted-foreground font-normal">
                {p.replace(" Admin", "").slice(0, 12)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {platforms.map((platform) => (
            <tr key={platform}>
              <td className="p-2 font-medium">{platform.split(" ")[0]}</td>
              {privileges.map((priv) => {
                const count = getCount(platform, priv);
                const intensity = count / maxCount;
                return (
                  <td key={priv} className="p-1">
                    <div
                      className="flex h-8 items-center justify-center rounded text-xs font-mono"
                      style={{
                        background: count
                          ? `rgba(59, 130, 246, ${0.15 + intensity * 0.7})`
                          : "transparent",
                      }}
                    >
                      {count || ""}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
