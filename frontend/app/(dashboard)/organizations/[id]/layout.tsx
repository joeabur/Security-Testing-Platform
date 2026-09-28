import { notFound } from "next/navigation";

import { OrgSectionNav } from "@/components/organizations/org-section-nav";
import { serverApiFetch } from "@/lib/api-server";
import type { Organization } from "@/lib/types";

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
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{organization.name}</h1>
        <p className="text-sm text-muted-foreground">Your role: {organization.role}</p>
      </div>
      <OrgSectionNav organizationId={id} />
      {children}
    </div>
  );
}
