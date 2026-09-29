"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Bot, Crosshair, GitBranch, PlayCircle, Workflow } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/cn";

const SECTIONS: { slug: string; label: string; icon: LucideIcon }[] = [
  { slug: "targets", label: "Targets", icon: Crosshair },
  { slug: "repositories", label: "Repositories", icon: GitBranch },
  { slug: "workflows", label: "Workflows", icon: Workflow },
  { slug: "runs", label: "Runs", icon: PlayCircle },
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
        const href = `${base}/${slug}`;
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={slug}
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
