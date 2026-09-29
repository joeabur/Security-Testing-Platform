"""The lab's classic web app: pages, links, and forms nothing should submit.

This exists so the DAST engine has something to crawl end to end, and it is
shaped around the two properties Phase 15 has to demonstrate:

* **It links off-site.** `/` links to `https://tracker.invalid/pixel` and
  `https://partner.invalid/sso`, neither of which is in any sensible rules of
  engagement. The crawler must refuse both *before queueing them*, and the
  acceptance test asserts exactly that. `.invalid` is reserved by RFC 2606 and
  never resolves, so even a total failure of the control cannot reach anything
  real — but the test asserts the URL never entered the queue, not that the
  request failed.
* **It has state-changing forms.** `/orders` offers a POST that deletes an
  order. The crawler records the action and never submits it; only an active
  scanner may, and only when `allow_state_mutation` is set.

There is also a link loop (`/a` ↔ `/b`) and a deep chain (`/deep/1` … `/deep/9`)
so the visited-set and depth bounds are exercised against real responses rather
than only in unit tests.

Like the rest of the lab: intentionally weak, no real data, no egress.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse

from lab.isolation import announce

#: Hosts under `.invalid` (RFC 2606) never resolve, so a link here cannot reach
#: anything even if every control failed.
OFF_SITE_LINKS = (
    "https://tracker.invalid/pixel",
    "https://partner.invalid/sso?return=/",
)

DEEP_CHAIN_LENGTH = 9


def _page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body>{body}</body></html>"
    )


def create_app() -> FastAPI:
    announce("web-app")
    app = FastAPI(
        title="Kervy Lab — classic web application",
        description="Do not deploy. Built to be crawled.",
        version="0.1.0",
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        # SEEDED FLAW: links to two off-site hosts. The crawler must refuse both
        # before queueing them (KERVY-DAST-001).
        off_site = "".join(f'<a href="{url}">off-site</a>' for url in OFF_SITE_LINKS)
        return _page(
            "Kervy Lab",
            "<h1>Kervy Lab</h1>"
            '<a href="/about">About</a>'
            '<a href="/orders">Orders</a>'
            '<a href="/a">A</a>'
            '<a href="/deep/1">Deep</a>'
            '<a href="/search?q=test">Search</a>'
            # Not followable: no host to check and no request to make.
            '<a href="mailto:support@example.invalid">Email</a>'
            '<a href="javascript:void(0)">JS</a>'
            '<img src="/static/logo.png">'
            f"{off_site}",
        )

    @app.get("/about", response_class=HTMLResponse)
    def about() -> HTMLResponse:
        return _page("About", '<p>About the lab.</p><a href="/">Home</a>')

    @app.get("/orders", response_class=HTMLResponse)
    def orders() -> HTMLResponse:
        # SEEDED FLAW: a destructive form. Recorded by the crawler
        # (KERVY-DAST-002), never submitted by it.
        return _page(
            "Orders",
            "<h1>Orders</h1>"
            '<form action="/orders/delete" method="post">'
            '<input type="hidden" name="id" value="ord-5001">'
            '<button type="submit">Delete order</button>'
            "</form>"
            '<a href="/">Home</a>',
        )

    @app.post("/orders/delete", response_class=PlainTextResponse)
    def delete_order() -> PlainTextResponse:
        # Deliberately does nothing destructive — the lab holds no real state.
        # It exists so that *if* something submitted the form, the test would
        # see the request rather than a 405.
        return PlainTextResponse("deleted (not really)")

    @app.get("/a", response_class=HTMLResponse)
    def page_a() -> HTMLResponse:
        # A link loop, so the visited set is exercised: without one the crawl
        # would not terminate.
        return _page("A", '<a href="/b">B</a><a href="/">Home</a>')

    @app.get("/b", response_class=HTMLResponse)
    def page_b() -> HTMLResponse:
        return _page("B", '<a href="/a">A</a>')

    @app.get("/deep/{step}", response_class=HTMLResponse)
    def deep(step: int) -> HTMLResponse:
        # A chain, so the depth bound is exercised against real responses.
        if step >= DEEP_CHAIN_LENGTH:
            return _page(f"Deep {step}", "<p>end of the chain</p>")
        return _page(f"Deep {step}", f'<a href="/deep/{step + 1}">next</a>')

    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = "") -> HTMLResponse:
        # SEEDED FLAW: reflects the query without escaping. A DAST scanner's
        # reflected-input rules have something to find; the platform's own
        # probes do not test this, which is honest about the division of work.
        return _page("Search", f"<p>Results for {q}</p><a href='/'>Home</a>")

    return app
