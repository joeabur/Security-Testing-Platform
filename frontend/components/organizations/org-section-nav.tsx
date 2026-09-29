"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Bot,
  Crosshair,
  GitBranch,
  LayoutDashboard,
  PlayCircle,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/cn";

const SECTIONS: { slug: string; label: string; icon: LucideIcon }[] = [
  { slug: "", label: "Overview", icon: LayoutDashboard },
  { slug: "targets", label: "Targets", icon: Crosshair },
  { slug: "repositories", label: "Repositories", icon: GitBranch },
  { slug: "workflows", label: "Workflows", icon: Workflow },
  { slug: "runs", label: "Runs", icon: PlayCircle },
  { slug: "findings", label: "Findings", icon: ShieldAlert },
  { slug: "agent", label: "Agent", icon: Bot },
];

export function OrgSectionNav({ organizationId }: { organizationId: string }) {
  const pathname = usePathname();
  const base = `/organizations/${organizationId}`;

  return (
    <nav
      className="scrollbar-thin -mx-1 flex gap-1 overflow-x-auto border-b border-border px-1 pb-px"
      aria-label="Organization sections"
    >
      {SECTIONS.map(({ slug, label, icon: Icon }) => {
        const href = slug ? `${base}/${slug}` : base;
        // The overview tab (empty slug, `href === base`) is active only on
        // an exact match — `startsWith` would also match every subpage's
        // URL, since they all begin with `base` too.
        const active = slug ? pathname === href || pathname.startsWith(`${href}/`) : pathname === href;
        return (
          <Link
            key={slug || "overview"}
            href={href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "relative flex items-center gap-1.5 whitespace-nowrap rounded-t-md px-3 py-2.5 text-sm font-medium transition-colors",
              active ? "text-primary" : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="h-4 w-4" aria-hidden />
            {label}
            <span
              className={cn(
                "absolute inset-x-1 -bottom-px h-0.5 rounded-full bg-primary transition-opacity",
                active ? "opacity-100" : "opacity-0",
              )}
              aria-hidden
            />
          </Link>
        );
      })}
    </nav>
  );
}
