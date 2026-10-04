import type { Metadata } from "next";
import { Mail, Users } from "lucide-react";

import { InviteMemberForm } from "@/components/organizations/invite-member-form";
import { MemberRoleForm } from "@/components/organizations/member-role-form";
import { RemoveMemberButton } from "@/components/organizations/remove-member-button";
import { RevokeInvitationButton } from "@/components/organizations/revoke-invitation-button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Membership, Organization, OrganizationInvitation } from "@/lib/types";

export const metadata: Metadata = { title: "Members — Kervy Security" };

// Mirrors Role.seniority_order in app/models/organization.py — used only to
// decide which controls this page shows; the backend re-checks every one of
// these rules itself on each write, so a stale or tampered value here can
// make a button disappear, never grant an action it wouldn't already allow.
const ROLE_SENIORITY: Record<string, number> = {
  viewer: 0,
  analyst: 1,
  security_engineer: 2,
  admin: 3,
  owner: 4,
};

function atLeast(role: string, minimum: string): boolean {
  return (ROLE_SENIORITY[role] ?? 0) >= (ROLE_SENIORITY[minimum] ?? 0);
}

function formatRole(role: string): string {
  return role
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export default async function MembersPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const organization = await serverApiFetch<Organization>(`/organizations/${id}`);
  const members = await serverApiFetch<Membership[]>(`/organizations/${id}/members`);

  const canManage = atLeast(organization.role, "admin");
  const callerIsOwner = atLeast(organization.role, "owner");
  const invitations = canManage
    ? await serverApiFetch<OrganizationInvitation[]>(`/organizations/${id}/invitations`)
    : [];

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle>Invite a member</CardTitle>
            <CardDescription>
              Add someone by email. If they already have an account they&apos;re added right away;
              otherwise a pending invitation is created and emailed to them.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <InviteMemberForm organizationId={id} callerIsOwner={callerIsOwner} />
          </CardContent>
        </Card>
      )}

      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Members</h2>
        {members.length === 0 ? (
          <Card className="border-dashed shadow-none">
            <CardHeader className="items-center py-10 text-center">
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <Users className="h-6 w-6" aria-hidden />
              </span>
              <CardDescription className="mt-1">No members yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          members.map((member) => {
            const canEditThisMember = canManage && (member.role !== "owner" || callerIsOwner);
            return (
              <Card key={member.id} className="transition-shadow duration-150 hover:shadow-elevated">
                <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                  <div>
                    <p className="font-medium">{member.full_name}</p>
                    <p className="text-sm text-muted-foreground">{member.email}</p>
                  </div>
                  {canEditThisMember ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <MemberRoleForm
                        organizationId={id}
                        member={member}
                        callerIsOwner={callerIsOwner}
                      />
                      <RemoveMemberButton
                        organizationId={id}
                        memberId={member.id}
                        email={member.email}
                      />
                    </div>
                  ) : (
                    <Badge tone="primary">{formatRole(member.role)}</Badge>
                  )}
                </CardContent>
              </Card>
            );
          })
        )}
      </div>

      {canManage && (
        <div className="flex flex-col gap-3">
          <h2 className="text-lg font-semibold">Pending invitations</h2>
          {invitations.length === 0 ? (
            <Card className="border-dashed shadow-none">
              <CardHeader className="items-center py-8 text-center">
                <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                  <Mail className="h-6 w-6" aria-hidden />
                </span>
                <CardDescription className="mt-1">No pending invitations.</CardDescription>
              </CardHeader>
            </Card>
          ) : (
            invitations.map((invitation) => (
              <Card key={invitation.id}>
                <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                  <div>
                    <p className="font-medium">{invitation.email}</p>
                    <p className="text-sm text-muted-foreground">
                      {formatRole(invitation.role)} · expires{" "}
                      {new Date(invitation.expires_at).toLocaleDateString()}
                    </p>
                  </div>
                  <RevokeInvitationButton
                    organizationId={id}
                    invitationId={invitation.id}
                    email={invitation.email}
                  />
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  );
}
