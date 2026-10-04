import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

const fetchMock = vi.fn();
const downloadMock = vi.fn();
vi.mock("@/lib/api-client", () => ({
  clientApiFetch: (...args: unknown[]) => fetchMock(...args),
  clientApiDownload: (...args: unknown[]) => downloadMock(...args),
}));

import { EvidencePanel } from "@/components/evidence/evidence-panel";
import type { EvidenceManifestEntry, EvidenceVerification } from "@/lib/types";

const manifest: EvidenceManifestEntry[] = [
  {
    sequence: 1,
    digest: "sha256:" + "a".repeat(64),
    previous: "sha256:" + "0".repeat(64),
    chain: "sha256:" + "b".repeat(64),
    probe_id: "ai.injection.direct",
    created_at: "2026-01-01T00:00:00Z",
  },
];

describe("EvidencePanel", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    downloadMock.mockReset();
  });

  it("loads and lists the manifest on request, not automatically", async () => {
    fetchMock.mockResolvedValueOnce(manifest);
    render(<EvidencePanel organizationId="org-1" runId="run-1" />);

    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /load manifest/i }));

    expect(await screen.findByText("ai.injection.direct")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/organizations/org-1/runs/run-1/evidence");
  });

  it("shows no fabricated 'ok' before verification — and the real result after", async () => {
    const verification: EvidenceVerification = { ok: true, entries: 3, problems: [] };
    fetchMock.mockResolvedValueOnce(verification);
    render(<EvidencePanel organizationId="org-1" runId="run-1" />);

    expect(screen.queryByText(/chain intact/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /verify chain/i }));

    expect(await screen.findByText(/chain intact \(3 entries\)/i)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/organizations/org-1/runs/run-1/evidence/verify");
  });

  it("surfaces chain problems rather than hiding them behind a plain failure", async () => {
    const verification: EvidenceVerification = {
      ok: false,
      entries: 2,
      problems: ["entry 2: digest mismatch"],
    };
    fetchMock.mockResolvedValueOnce(verification);
    render(<EvidencePanel organizationId="org-1" runId="run-1" />);

    fireEvent.click(screen.getByRole("button", { name: /verify chain/i }));

    expect(await screen.findByText("entry 2: digest mismatch")).toBeInTheDocument();
  });

  it("downloads one bundle by its digest", async () => {
    // jsdom has no object-URL implementation; the component only needs to
    // call it, not resolve a real blob URL.
    URL.createObjectURL = vi.fn(() => "blob:mock");
    URL.revokeObjectURL = vi.fn();

    fetchMock.mockResolvedValueOnce(manifest);
    downloadMock.mockResolvedValueOnce({
      blob: new Blob(["{}"], { type: "application/json" }),
      filename: "evidence-aaaaaaaaaaaaaaaa.json",
    });
    render(<EvidencePanel organizationId="org-1" runId="run-1" />);

    fireEvent.click(screen.getByRole("button", { name: /load manifest/i }));
    await screen.findByText("ai.injection.direct");

    fireEvent.click(screen.getByRole("button", { name: /download/i }));

    await waitFor(() =>
      expect(downloadMock).toHaveBeenCalledWith(
        `/organizations/org-1/runs/run-1/evidence/${encodeURIComponent(manifest[0].digest)}`,
      ),
    );
  });
});
