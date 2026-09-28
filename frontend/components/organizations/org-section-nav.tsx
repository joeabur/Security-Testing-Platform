"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/cn";

const SECTIONS = [
  { slug: "targets", label: "Targets" },
  { slug: "repositories", label: "Repositories" },
  { slug: "workflows", label: "Workflows" },
  { slug: "runs", label: "Runs" },
];

export function OrgSectionNav({ organizationId }: { organizationId: string }) {
  const pathname = usePathname();
  const base = `/organizations/${organizationId}`;

  return (
    <nav className="flex flex-wrap gap-1 border-b border-border">
      {SECTIONS.map((section) => {
        const href = `${base}/${section.slug}`;
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={section.slug}
            href={href}
            className={cn(
              "rounded-t-md px-3 py-2 text-sm font-medium",
              active
                ? "border-b-2 border-primary text-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {section.label}
          </Link>
        );
      })}
    </nav>
  );
}
