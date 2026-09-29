# Releasing, and how to verify a release

A release is the one moment this project hands somebody an artifact they will
run against their own systems. Everything below exists so a consumer does not
have to take that on trust.

## Cutting one

```bash
git tag -s v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

The tag triggers `.github/workflows/release.yml`, which does three things in
order and stops at the first failure:

1. **Verifies.** The full suite, ruff, mypy, bandit and the platform's own
   Semgrep rules run again *on the tag itself*. A tag can be moved, so trusting
   the CI run that happened on the branch would be trusting something that may
   no longer be the same commit.
2. **Builds and signs.** A wheel, an sdist, a CycloneDX SBOM of what was
   actually installed, and `SHA256SUMS`. Every file is signed with Sigstore,
   and SLSA build provenance is attested for each.
3. **Publishes.** The signed artifacts are attached to the GitHub release.

## Signing is keyless, and that is the point

There is no signing key in a repository secret. A long-lived key is a
credential that can be stolen and then used forever, and rotating one means
every consumer has to learn the new one.

Instead the workflow exchanges its OIDC identity for a short-lived Sigstore
certificate. The certificate records *which repository, which workflow, and
which run* produced the signature, and expires minutes later. So the thing you
verify is not "somebody who had the key", which is unfalsifiable, but "this
repository's release workflow", which is checkable.

## Verifying before you run anything

```bash
pip install sigstore

sigstore verify identity kervy_ai-0.2.0-py3-none-any.whl \
  --cert-identity "https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform/.github/workflows/release.yml@refs/tags/v0.2.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

`--cert-identity` is the part that matters. Verifying only that *a* valid
Sigstore signature exists proves nothing — anyone can sign anything. Pinning
the identity to this workflow at this tag is what makes the check mean
something.

Provenance, using the GitHub CLI:

```bash
gh attestation verify kervy_ai-0.2.0-py3-none-any.whl \
  --repo joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform
```

And the checksums:

```bash
sha256sum -c SHA256SUMS
```

## What a release does not promise

Stated here rather than left to be assumed:

- **No release has been cut yet.** The workflow is written and its structure is
  asserted by `backend/tests/test_ci_workflows.py`, but nothing in CI has run
  it end to end, because doing so means publishing a real tag. The first real
  release is where its behaviour gets proved, and `docs/roadmap.md` records
  that.
- **The SBOM describes the build environment**, not a transitive guarantee.
  It lists what was installed when the wheel was built, which is the honest
  scope of a CycloneDX environment report.
- **Container images are not signed.** `container.yml` scans them; nothing
  signs or publishes them. There is no published image today.
- **Provenance is GitHub's attestation**, which is SLSA build level 2 in
  practice — it attests what built the artifact, not that the build was
  hermetic or reproducible. This project does not claim reproducible builds.
