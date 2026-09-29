import Link from "next/link";
import { KeyRound, ShieldCheck } from "lucide-react";

import { SignOutButton } from "@/components/nav/sign-out-button";
import { ThemeToggle } from "@/components/nav/theme-toggle";
import type { User } from "@/lib/types";

export function TopNav({ user }: { user: User }) {
  return (
    <header className="sticky top-0 z-40 border-b border-border bg-card/85 shadow-xs backdrop-blur supports-[backdrop-filter]:bg-card/70">
      <div className="mx-auto flex h-16 max-w-6xl flex-wrap items-center justify-between gap-2 px-4 sm:px-6">
        <Link
          href="/dashboard"
          className="flex items-center gap-2 rounded-md py-1 transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-soft">
            <ShieldCheck className="h-[18px] w-[18px]" aria-hidden />
          </span>
          <span className="font-semibold tracking-tight">Kervy Security</span>
        </Link>
        <div className="flex items-center gap-1 sm:gap-3">
          <span className="hidden text-sm text-muted-foreground sm:inline">{user.full_name}</span>
          <Link
            href="/account/security"
            className="inline-flex h-10 w-10 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            aria-label="Security settings"
          >
            <KeyRound className="h-[18px] w-[18px]" aria-hidden />
          </Link>
          <div className="mx-1 hidden h-5 w-px bg-border sm:block" aria-hidden />
          <ThemeToggle />
          <SignOutButton />
        </div>
      </div>
    </header>
  );
}
