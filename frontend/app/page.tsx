import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import {
  ShieldCheck,
  Bot,
  Radar,
  FileSearch,
  GitBranch,
  ShieldAlert,
  ClipboardCheck,
} from "lucide-react";

import { ThemeToggle } from "@/components/nav/theme-toggle";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { isAuthenticated } from "@/lib/api-server";

const TITLE = "AI Security Testing & AI Red Teaming Platform | Aegis AI Security";
const DESCRIPTION =
  "Aegis AI Security is an authorized AI security testing and AI red teaming platform for generative AI applications, LLM agents, and the APIs behind them. Run repeatable AI risk assessments, adversarial prompt testing, and application security scans from one place.";
const SITE_URL = "https://YOUR-DOMAIN.com";

export const metadata: Metadata = {
  title: TITLE,
  description: DESCRIPTION,
  alternates: { canonical: SITE_URL },
  keywords: [
    "AI security testing",
    "AI red teaming",
    "generative AI risk assessment",
    "LLM security testing",
    "LLM red teaming",
    "AI agent security",
    "prompt injection testing",
  ],
  openGraph: {
    title: TITLE,
    description: DESCRIPTION,
    url: SITE_URL,
    siteName: "Aegis AI Security",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
  },
};

const JSON_LD = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "Aegis AI Security",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Web",
  description: DESCRIPTION,
  url: SITE_URL,
};

const CAPABILITIES = [
  {
    icon: Bot,
    title: "AI red teaming",
    description:
      "Adversarial testing against LLM applications and agents — prompt injection, jailbreaks, data exfiltration, and unsafe tool use — run against your own authorized targets.",
  },
  {
    icon: Radar,
    title: "Generative AI risk assessment",
    description:
      "Structured, repeatable risk assessments for generative AI systems, mapped to findings you can triage, remediate, and retest.",
  },
  {
    icon: FileSearch,
    title: "Application security scanning",
    description:
      "SAST, software composition analysis, secrets detection, and infrastructure-as-code scanning for the applications and APIs behind your AI features.",
  },
  {
    icon: GitBranch,
    title: "Repository scanning",
    description:
      "Connect a source repository directly and scan it for security issues without standing up a full live-target authorization workflow.",
  },
  {
    icon: ShieldAlert,
    title: "Findings & remediation",
    description:
      "Every run produces findings with severity, evidence, and remediation guidance — tracked to closure, not just a one-time report.",
  },
  {
    icon: ClipboardCheck,
    title: "Authorized by design",
    description:
      "Every assessment runs under explicit authorization and a recorded rules-of-engagement scope, so testing stays scoped to what you actually own and approved.",
  },
];

export default async function LandingPage() {
  if (await isAuthenticated()) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen flex-col">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }}
      />

      <header className="flex items-center justify-between px-6 py-4 sm:px-10">
        <div className="flex items-center gap-2 text-foreground">
          <ShieldCheck className="h-6 w-6 text-primary" aria-hidden />
          <span className="text-lg font-semibold tracking-tight">Aegis AI Security</span>
        </div>
        <div className="flex items-center gap-3">
          <ThemeToggle />
          <Link href="/login" className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
            Sign in
          </Link>
          <Link href="/register" className={cn(buttonVariants({ size: "sm" }))}>
            Get started
          </Link>
        </div>
      </header>

      <section className="mx-auto flex max-w-3xl flex-col items-center gap-6 px-6 py-16 text-center sm:py-24">
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
          AI security testing and AI red teaming, in one platform
        </h1>
        <p className="max-w-2xl text-lg text-muted-foreground">
          Aegis AI Security helps teams run authorized security assessments of generative AI
          applications, LLM agents, and their supporting APIs — combining AI red teaming with
          traditional application security scanning, so you find AI-specific and code-level risk
          in the same place.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          <Link href="/register" className={cn(buttonVariants({ size: "lg" }))}>
            Start an assessment
          </Link>
          <Link href="/login" className={cn(buttonVariants({ variant: "outline", size: "lg" }))}>
            Sign in
          </Link>
        </div>
      </section>

      <section className="mx-auto grid w-full max-w-5xl grid-cols-1 gap-4 px-6 pb-20 sm:grid-cols-2 sm:px-10 lg:grid-cols-3">
        {CAPABILITIES.map(({ icon: Icon, title, description }) => (
          <Card key={title}>
            <CardHeader>
              <Icon className="h-6 w-6 text-primary" aria-hidden />
              <CardTitle className="mt-2 text-base">{title}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </CardHeader>
            <CardContent />
          </Card>
        ))}
      </section>

      <footer className="border-t border-border px-6 py-6 text-center text-sm text-muted-foreground sm:px-10">
        Aegis AI Security — authorized AI security testing and AI red teaming.
      </footer>
    </main>
  );
}
