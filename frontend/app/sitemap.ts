import type { MetadataRoute } from "next";

// Placeholder until a real production domain exists — see docs/seo.md for
// every other place this same URL needs to be swapped in before deploying.
const SITE_URL = "https://YOUR-DOMAIN.com";

// Only the public, unauthenticated landing page belongs here. Everything
// else in this app (dashboard, organizations, login, register) sits behind
// auth and is excluded from crawling by public/robots.txt — listing it in
// a sitemap would just have search engines repeatedly hit a login redirect.
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: SITE_URL,
      lastModified: new Date(),
      changeFrequency: "monthly",
      priority: 1,
    },
  ];
}
