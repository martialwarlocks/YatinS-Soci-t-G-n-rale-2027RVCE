"use client";

import Link from "next/link";

interface MatrixData {
  departments: string[];
  platforms: string[];
  data: Record<string, string | number>[];
}

export function AccessMatrix({ matrix }: { matrix: MatrixData }) {
  if (!matrix?.platforms?.length) return null;

  const maxVal = Math.max(
    ...matrix.data.flatMap((row) =>
      matrix.platforms.map((p) => Number(row[p] || 0))
    ),
    1
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr>
            <th className="p-2 text-left text-muted-foreground">Department</th>
            {matrix.platforms.map((p) => (
              <th key={p} className="p-2 text-center text-muted-foreground font-normal">
                {p.split(" ")[0]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.data.slice(0, 10).map((row) => (
            <tr key={String(row.department)} className="border-t border-border/40">
              <td className="p-2 font-medium">{row.department as string}</td>
              {matrix.platforms.map((p) => {
                const count = Number(row[p] || 0);
                const intensity = count / maxVal;
                return (
                  <td key={p} className="p-1">
                    <div
                      className="flex h-8 items-center justify-center rounded font-mono"
                      style={{
                        background: count
                          ? `rgba(139, 92, 246, ${0.12 + intensity * 0.65})`
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

export function KpiLink({
  href,
  children,
  className = "",
}: {
  href: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Link href={href} className={`block transition-transform hover:scale-[1.02] ${className}`}>
      {children}
    </Link>
  );
}
