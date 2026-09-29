import { type HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react";

import { cn } from "@/lib/cn";

export const alertVariants = cva(
  "flex items-start gap-2.5 rounded-lg border px-3.5 py-3 text-sm leading-relaxed animate-fade-in",
  {
    variants: {
      tone: {
        destructive: "border-destructive/20 bg-destructive/10 text-destructive",
        warning: "border-warning/25 bg-warning/10 text-warning",
        success: "border-success/20 bg-success/10 text-success",
        info: "border-primary/20 bg-primary/10 text-primary",
      },
    },
    defaultVariants: {
      tone: "info",
    },
  },
);

const ICONS = {
  destructive: XCircle,
  warning: AlertTriangle,
  success: CheckCircle2,
  info: Info,
} as const;

export interface AlertProps extends HTMLAttributes<HTMLDivElement>, VariantProps<typeof alertVariants> {}

export function Alert({ className, tone, role, children, ...props }: AlertProps) {
  const resolvedTone = tone ?? "info";
  const Icon = ICONS[resolvedTone];
  return (
    <div
      className={cn(alertVariants({ tone: resolvedTone, className }))}
      role={role ?? (resolvedTone === "destructive" || resolvedTone === "warning" ? "alert" : "status")}
      {...props}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <div className="min-w-0">{children}</div>
    </div>
  );
}
