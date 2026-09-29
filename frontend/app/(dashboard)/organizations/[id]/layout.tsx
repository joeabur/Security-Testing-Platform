import { notFound } from "next/navigation";
import { Building2 } from "lucide-react";

import { OrgSectionNav } from "@/components/organizations/org-section-nav";
import { Badge } from "@/components/ui/badge";
import { serverApiFetch } from "@/lib/api-server";
import type { Organization } from "@/lib/types";

function formatRole(role: string): string {
  return role
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export default async function OrganizationLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const organizations = await serverApiFetch<Organization[]>("/organizations");
  const organization = organizations.find((org) => org.id === id);
  if (!organization) {
    notFound();
  }

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
            <Building2 className="h-5 w-5" aria-hidden />
          </span>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{organization.name}</h1>
            <p className="text-sm text-muted-foreground">Organization workspace</p>
          </div>
        </div>
        <Badge tone="primary">{formatRole(organization.role)}</Badge>
      </div>
      <OrgSectionNav organizationId={id} />
      {children}
    </div>
  );
}
