import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import { RegisterForm } from "@/components/auth/register-form";
import { ThemeToggle } from "@/components/nav/theme-toggle";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { isAuthenticated } from "@/lib/api-server";

export const metadata: Metadata = { title: "Register — Aegis AI Security" };

export default async function RegisterPage() {
  if (await isAuthenticated()) {
    redirect("/dashboard");
  }

  return (
    <main className="relative flex min-h-screen flex-col items-center justify-center gap-6 px-4">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <div className="flex items-center gap-2 text-foreground">
        <ShieldCheck className="h-7 w-7 text-primary" aria-hidden />
        <span className="text-xl font-semibold tracking-tight">Aegis AI Security</span>
      </div>
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Create an account</CardTitle>
          <CardDescription>
            For authorized security assessment of Generative AI applications only.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RegisterForm />
        </CardContent>
      </Card>
    </main>
  );
}
