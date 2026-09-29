import { redirect } from "next/navigation";

import { TopNav } from "@/components/nav/top-nav";
import { serverApiFetch } from "@/lib/api-server";
import { ApiError } from "@/lib/errors";
import type { User } from "@/lib/types";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  let user: User;
  try {
    user = await serverApiFetch<User>("/auth/me");
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      redirect("/login");
    }
    throw error;
  }

  return (
    <div className="min-h-screen bg-background">
      <TopNav user={user} />
      <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-10">{children}</main>
    </div>
  );
}
