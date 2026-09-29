import type { SVGProps } from "react";

import { Github } from "lucide-react";

import { buttonVariants } from "@/components/ui/button";
import { PUBLIC_API_BASE_URL } from "@/lib/config";
import { cn } from "@/lib/cn";
import type { OAuthProviders } from "@/lib/types";

/**
 * Plain `<a>` tags, not a client-side submit: this is a full browser
 * navigation to the backend's `/authorize` endpoint, which redirects on to
 * the provider — there is no JSON response for a fetch to consume.
 * `PUBLIC_API_BASE_URL` (not the server-only internal URL) because the
 * browser, not this Next.js server, is what has to reach it.
 */
export function OAuthButtons({ providers }: { providers: OAuthProviders }) {
  if (!providers.google && !providers.github) {
    return null;
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-2">
        {providers.google && (
          <a
            href={`${PUBLIC_API_BASE_URL}/auth/oauth/google/authorize`}
            className={cn(buttonVariants({ variant: "outline" }), "w-full")}
          >
            <GoogleGlyph className="h-4 w-4" aria-hidden />
            Continue with Google
          </a>
        )}
        {providers.github && (
          <a
            href={`${PUBLIC_API_BASE_URL}/auth/oauth/github/authorize`}
            className={cn(buttonVariants({ variant: "outline" }), "w-full")}
          >
            <Github className="h-4 w-4" aria-hidden />
            Continue with GitHub
          </a>
        )}
      </div>
      <div className="flex items-center gap-3 text-xs uppercase tracking-wide text-muted-foreground">
        <span className="h-px flex-1 bg-border" />
        or
        <span className="h-px flex-1 bg-border" />
      </div>
    </div>
  );
}

// lucide-react has no Google mark (it is a registered trademark, not an
// open icon); a minimal four-color "G" glyph, inline so no extra asset or
// dependency is needed for one icon.
function GoogleGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" {...props}>
      <path
        fill="#4285F4"
        d="M23.49 12.27c0-.79-.07-1.54-.2-2.27H12v4.3h6.47c-.28 1.5-1.13 2.77-2.4 3.62v3h3.88c2.27-2.09 3.54-5.17 3.54-8.65z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3c-1.08.72-2.45 1.15-4.05 1.15-3.11 0-5.75-2.1-6.69-4.93H1.3v3.09C3.26 21.3 7.31 24 12 24z"
      />
      <path
        fill="#FBBC05"
        d="M5.31 14.31c-.24-.72-.38-1.49-.38-2.31s.14-1.59.38-2.31V6.6H1.3A11.98 11.98 0 0 0 0 12c0 1.93.46 3.76 1.3 5.4z"
      />
      <path
        fill="#EA4335"
        d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.44-3.44C17.94 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.3 6.6l4.01 3.09C6.25 6.85 8.89 4.75 12 4.75z"
      />
    </svg>
  );
}
