"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { FindingsTrend, Severity } from "@/lib/types";

// Worst-first stacking order, matching SEVERITY_ORDER in
// app/core/dashboard/queries.py — the reading order for someone deciding
// what to look at first.
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "hsl(var(--severity-critical))",
  HIGH: "hsl(var(--severity-high))",
  MEDIUM: "hsl(var(--severity-medium))",
  LOW: "hsl(var(--severity-low))",
  INFORMATIONAL: "hsl(var(--severity-info))",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFORMATIONAL: "Informational",
};

type ChartRow = { day: string } & Record<Severity, number>;

/**
 * Fills every day in the window, not just the ones with a row — a day with
 * nothing new is a fact (zero), not a gap a chart library should have to
 * guess about. Mirrors the "zero and unknown are different" rule
 * `app/core/dashboard/queries.py` states for the rest of this dashboard.
 */
function toChartRows(trend: FindingsTrend): ChartRow[] {
  const byDay = new Map<string, Partial<Record<Severity, number>>>();
  for (const point of trend.points) {
    const existing = byDay.get(point.day) ?? {};
    existing[point.severity] = point.count;
    byDay.set(point.day, existing);
  }

  const today = new Date();
  const rows: ChartRow[] = [];
  for (let offset = trend.days - 1; offset >= 0; offset -= 1) {
    const date = new Date(today);
    date.setUTCDate(date.getUTCDate() - offset);
    const day = date.toISOString().slice(0, 10);
    const counts = byDay.get(day) ?? {};
    rows.push({
      day,
      CRITICAL: counts.CRITICAL ?? 0,
      HIGH: counts.HIGH ?? 0,
      MEDIUM: counts.MEDIUM ?? 0,
      LOW: counts.LOW ?? 0,
      INFORMATIONAL: counts.INFORMATIONAL ?? 0,
    });
  }
  return rows;
}

function formatDay(day: string): string {
  return new Date(`${day}T00:00:00Z`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

export function FindingsTrendChart({ trend }: { trend: FindingsTrend }) {
  const rows = toChartRows(trend);
  const hasAny = rows.some((row) => SEVERITIES.some((severity) => row[severity] > 0));

  if (!hasAny) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">
        No findings first observed in the last {trend.days} days.
      </p>
    );
  }

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
          <XAxis
            dataKey="day"
            tickFormatter={formatDay}
            tick={{ fontSize: 11 }}
            className="fill-muted-foreground"
            minTickGap={24}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fontSize: 11 }}
            className="fill-muted-foreground"
            width={32}
          />
          <Tooltip
            labelFormatter={(day) => formatDay(String(day))}
            contentStyle={{
              background: "hsl(var(--card))",
              border: "1px solid hsl(var(--border))",
              borderRadius: "0.5rem",
              fontSize: "0.8125rem",
            }}
          />
          <Legend formatter={(value: string) => SEVERITY_LABEL[value as Severity] ?? value} />
          {SEVERITIES.map((severity) => (
            <Area
              key={severity}
              type="monotone"
              dataKey={severity}
              name={severity}
              stackId="severity"
              stroke={SEVERITY_COLOR[severity]}
              fill={SEVERITY_COLOR[severity]}
              fillOpacity={0.5}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
