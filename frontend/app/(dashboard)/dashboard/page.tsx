import type { Metadata } from "next";
import Link from "next/link";
import { Building2, ExternalLink, Plus } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PUBLIC_APP_BASE_URL } from "@/lib/config";
import { serverApiFetch } from "@/lib/api-server";
import { cn } from "@/lib/cn";
import type { Organization } from "@/lib/types";

export const metadata: Metadata = { title: "Dashboard — Kervy Security" };

export default async function DashboardPage() {
  const organizations = await serverApiFetch<Organization[]>("/organizations");

  return (
    <div className="flex animate-fade-in flex-col gap-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">Your organizations and their assessment activity.</p>
      </div>

      {organizations.length === 0 ? (
        <Card className="border-dashed shadow-none">
          <CardHeader className="items-center py-12 text-center">
            <span className="flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
              <Building2 className="h-7 w-7" aria-hidden />
            </span>
            <CardTitle className="mt-2">No organizations yet</CardTitle>
            <CardDescription>
              Create an organization to register an asset and run an authorized assessment.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center pb-10">
            <Link href="/organizations/new">
              <Button>
                <Plus className="h-4 w-4" aria-hidden />
                Create organization
              </Button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {organizations.map((org) => (
            <Card key={org.id} className="flex flex-col transition-all duration-150 hover:-translate-y-0.5 hover:shadow-elevated">
              <CardHeader>
                <div className="flex items-start justify-between gap-2">
                  <CardTitle>{org.name}</CardTitle>
                  <Badge tone="primary">{formatRole(org.role)}</Badge>
                </div>
              </CardHeader>
              <CardContent className="flex flex-1 flex-col justify-between gap-4">
                <p className="text-sm text-muted-foreground">
                  Add targets and repositories, start runs, and trigger workflows.
                </p>
                <div className="flex flex-wrap gap-2">
                  <Link
                    href={`/organizations/${org.id}`}
                    className={cn(buttonVariants({ size: "sm" }), "self-start")}
                  >
                    Manage
                  </Link>
                  <a
                    href={`${PUBLIC_APP_BASE_URL}/app/organizations/${org.id}`}
                    className={cn(buttonVariants({ variant: "outline", size: "sm" }), "self-start")}
                  >
                    Findings &amp; reports
                    <ExternalLink className="h-3.5 w-3.5" aria-hidden />
                  </a>
                </div>
              </CardContent>
            </Card>
          ))}
          <Link href="/organizations/new">
            <Card className="flex h-full min-h-[140px] items-center justify-center border-dashed text-muted-foreground shadow-none transition-colors hover:border-primary hover:bg-primary/[0.03] hover:text-primary">
              <div className="flex flex-col items-center gap-2 p-6">
                <Plus className="h-6 w-6" aria-hidden />
                <span className="text-sm font-medium">New organization</span>
              </div>
            </Card>
          </Link>
        </div>
      )}
    </div>
  );
}

function formatRole(role: string): string {
  return role
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
