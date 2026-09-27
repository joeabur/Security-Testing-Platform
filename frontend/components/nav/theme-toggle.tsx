"use client";

import { useSyncExternalStore } from "react";
import { Moon, Sun } from "lucide-react";

import { Button } from "@/components/ui/button";

type Theme = "light" | "dark";

function systemPrefersLight(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: light)").matches;
}

function currentTheme(): Theme {
  const explicit = document.documentElement.getAttribute("data-theme");
  if (explicit === "light" || explicit === "dark") return explicit;
  return systemPrefersLight() ? "light" : "dark";
}

// This component is the only thing that ever changes `data-theme`
// (`toggle` below), so a hand-rolled single-listener store is enough —
// `useSyncExternalStore` is used instead of `useEffect` + `useState`
// specifically so the DOM read happens on demand rather than needing a
// post-mount effect to avoid a hydration mismatch (the server has no
// theme opinion; `getServerSnapshot` reflects that).
let listener: (() => void) | null = null;

function subscribe(callback: () => void): () => void {
  listener = callback;
  return () => {
    listener = null;
  };
}

function getServerSnapshot(): Theme | null {
  return null;
}

/**
 * `globals.css` already keys every color on `[data-theme]` (built ahead of
 * this component, unused until now); this is only the control that sets
 * the attribute and remembers the choice. `app/layout.tsx` has the
 * matching inline script that applies a stored choice before first paint,
 * so toggling here never causes a flash on the next page load.
 */
export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribe, currentTheme, getServerSnapshot);

  function toggle() {
    const next: Theme = currentTheme() === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("aegis-theme", next);
    } catch {
      // Private mode / storage disabled: the choice still applies to this
      // page view, just is not remembered for the next one.
    }
    listener?.();
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={toggle}
      aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
    >
      {theme === "light" ? <Moon className="h-4 w-4" aria-hidden /> : <Sun className="h-4 w-4" aria-hidden />}
    </Button>
  );
}
