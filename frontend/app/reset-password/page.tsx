import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import { ResetPasswordForm } from "@/components/auth/reset-password-form";
import { ThemeToggle } from "@/components/nav/theme-toggle";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { isAuthenticated } from "@/lib/api-server";

export const metadata: Metadata = { title: "Reset password — Kervy Security" };

export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  if (await isAuthenticated()) {
    redirect("/dashboard");
  }

  const { token } = await searchParams;

  return (
    <main className="bg-hero-fade relative flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-12">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <div className="flex animate-fade-up items-center gap-2 text-foreground">
        <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-elevated">
          <ShieldCheck className="h-5 w-5" aria-hidden />
        </span>
        <span className="text-xl font-semibold tracking-tight">
          Kervy Security
        </span>
      </div>
      <Card className="w-full max-w-sm animate-fade-up shadow-elevated">
        <CardHeader>
          <CardTitle>Choose a new password</CardTitle>
          <CardDescription>This link can only be used once.</CardDescription>
        </CardHeader>
        <CardContent>
          <ResetPasswordForm token={token} />
        </CardContent>
      </Card>
    </main>
  );
}
