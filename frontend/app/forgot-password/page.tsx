import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import { ForgotPasswordForm } from "@/components/auth/forgot-password-form";
import { ThemeToggle } from "@/components/nav/theme-toggle";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { isAuthenticated } from "@/lib/api-server";

export const metadata: Metadata = { title: "Forgot password — Kervy Security" };

export default async function ForgotPasswordPage() {
  if (await isAuthenticated()) {
    redirect("/dashboard");
  }

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
          <CardTitle>Forgot your password?</CardTitle>
          <CardDescription>
            Enter the email on your account and we&apos;ll send you a reset
            link.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ForgotPasswordForm />
        </CardContent>
      </Card>
    </main>
  );
}
