import type { Metadata } from "next";

import { TwoFactorSettings } from "@/components/account/two-factor-settings";
import { serverApiFetch } from "@/lib/api-server";
import type { User } from "@/lib/types";

export const metadata: Metadata = { title: "Security — Kervy Security" };

export default async function AccountSecurityPage() {
  const user = await serverApiFetch<User>("/auth/me");

  return (
    <div className="flex max-w-2xl animate-fade-in flex-col gap-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
        <p className="text-sm text-muted-foreground">
          Manage how you sign in to {user.email}.
        </p>
      </div>
      <TwoFactorSettings initialEnabled={user.totp_enabled} />
    </div>
  );
}
