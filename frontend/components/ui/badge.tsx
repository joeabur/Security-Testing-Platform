import { type HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/cn";

export const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium leading-5 transition-colors",
  {
    variants: {
      tone: {
        neutral: "border-transparent bg-muted text-muted-foreground",
        outline: "border-dashed border-border bg-transparent text-muted-foreground",
        primary: "border-transparent bg-primary/10 text-primary",
        success: "border-transparent bg-success/10 text-success",
        warning: "border-transparent bg-warning/10 text-warning",
        destructive: "border-transparent bg-destructive/10 text-destructive",
        critical: "border-transparent bg-severity-critical/10 text-severity-critical",
        high: "border-transparent bg-severity-high/10 text-severity-high",
        medium: "border-transparent bg-severity-medium/10 text-severity-medium",
        low: "border-transparent bg-severity-low/10 text-severity-low",
        info: "border-transparent bg-severity-info/10 text-severity-info",
      },
    },
    defaultVariants: {
      tone: "neutral",
    },
  },
);

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {
  dot?: boolean;
}

export function Badge({ className, tone, dot, children, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ tone, className }))} {...props}>
      {dot ? <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" aria-hidden /> : null}
      {children}
    </span>
  );
}
