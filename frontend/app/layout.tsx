import type { Metadata } from "next";

import { Providers } from "@/components/providers";

import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis AI Security",
  description:
    "Authorized security assessment platform for Generative AI applications, agents, and their supporting APIs.",
  // No icon file is served, and none should be fetched from anywhere else.
  // Without this, every browser issues its own GET /favicon.ico, which
  // 404s and surfaces as a console error on first load.
  icons: { icon: "data:," },
};

// Applied before first paint, synchronously — the one place this app needs
// a blocking inline script rather than a `useEffect`, so a stored theme
// preference (set by components/nav/theme-toggle.tsx) never flashes the
// other theme for a frame while React hydrates. `suppressHydrationWarning`
// on <html> above is what lets this script's synchronous DOM write and
// the server-rendered markup differ without React complaining.
const THEME_INIT_SCRIPT = `
(function () {
  try {
    var stored = localStorage.getItem("aegis-theme");
    if (stored === "light" || stored === "dark") {
      document.documentElement.setAttribute("data-theme", stored);
    }
  } catch (e) {}
})();
`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body className="min-h-screen antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
