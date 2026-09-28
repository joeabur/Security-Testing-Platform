"""Parsing an image reference and gating which registry it may be pulled
from (pentest module Phase 3). Mirrors `test_repositories_checkout.py`'s
shape for the analogous git checks in `app/core/appsec/checkout.py`.
"""

import pytest

from app.core.container.pull import (
    ContainerPullError,
    check_registry_allowed,
    parse_image_ref,
    pull_image,
)

# --- parse_image_ref ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "registry", "repository", "tag", "digest"),
    [
        ("nginx", "docker.io", "library/nginx", None, None),
        ("nginx:1.25", "docker.io", "library/nginx", "1.25", None),
        ("myorg/myapp", "docker.io", "myorg/myapp", None, None),
        ("myorg/myapp:v2", "docker.io", "myorg/myapp", "v2", None),
        ("ghcr.io/org/app:tag", "ghcr.io", "org/app", "tag", None),
        # A registry port must not be read as a tag.
        ("registry.internal:5000/app", "registry.internal:5000", "app", None, None),
        ("registry.internal:5000/app:v2", "registry.internal:5000", "app", "v2", None),
        ("localhost:5000/app:v2", "localhost:5000", "app", "v2", None),
        (
            "gcr.io/project/app@sha256:"
            + "a" * 64,
            "gcr.io",
            "project/app",
            None,
            "sha256:" + "a" * 64,
        ),
    ],
)
def test_image_references_are_parsed_correctly(
    raw: str, registry: str, repository: str, tag: str | None, digest: str | None
) -> None:
    ref = parse_image_ref(raw)
    assert ref.registry == registry
    assert ref.repository == repository
    assert ref.tag == tag
    assert ref.digest == digest
    assert ref.raw == raw


def test_an_unqualified_name_resolves_docker_hub_through_its_real_endpoint() -> None:
    """"docker.io" in a reference is not the host actually dialed — Docker
    Hub's registry lives at a different, specific hostname."""
    ref = parse_image_ref("nginx:1.25")
    assert ref.registry == "docker.io"
    assert ref.resolve_host == "registry-1.docker.io"


def test_a_qualified_registry_resolves_its_own_host_without_the_port() -> None:
    ref = parse_image_ref("registry.internal:5000/app:v2")
    assert ref.resolve_host == "registry.internal"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "nginx :1.25",
        "gcr.io/project/app@sha256:not-a-real-digest",
        "gcr.io/project/app@sha256:" + "a" * 63,  # one short
    ],
)
def test_a_malformed_reference_is_refused(raw: str) -> None:
    with pytest.raises(ContainerPullError):
        parse_image_ref(raw)


# --- check_registry_allowed ---------------------------------------------------


def _resolver_returning(*addresses: str):
    def resolver(_host: str) -> list[str]:
        return list(addresses)

    return resolver


def test_an_empty_allowlist_refuses_everything() -> None:
    ref = parse_image_ref("ghcr.io/org/app:tag")
    with pytest.raises(ContainerPullError, match="no registries are allowlisted"):
        check_registry_allowed(ref, (), resolver=_resolver_returning("203.0.113.10"))


def test_a_registry_outside_the_allowlist_is_refused() -> None:
    ref = parse_image_ref("ghcr.io/org/app:tag")
    with pytest.raises(ContainerPullError, match="not in asset_scope.allowed_registries"):
        check_registry_allowed(
            ref, ("docker.io",), resolver=_resolver_returning("203.0.113.10")
        )


def test_a_registry_resolving_to_a_blocked_address_is_refused() -> None:
    ref = parse_image_ref("ghcr.io/org/app:tag")
    with pytest.raises(ContainerPullError, match="blocked address"):
        check_registry_allowed(ref, ("ghcr.io",), resolver=_resolver_returning("127.0.0.1"))


def test_a_registry_resolving_to_the_cloud_metadata_address_is_refused_even_if_allowlisted() -> (
    None
):
    ref = parse_image_ref("ghcr.io/org/app:tag")
    with pytest.raises(ContainerPullError, match="blocked address"):
        check_registry_allowed(
            ref,
            ("ghcr.io",),
            allowed_ip_ranges=("0.0.0.0/0",),
            resolver=_resolver_returning("169.254.169.254"),
        )


def test_an_allowlisted_registry_resolving_to_a_public_address_is_permitted() -> None:
    ref = parse_image_ref("ghcr.io/org/app:tag")
    check_registry_allowed(ref, ("ghcr.io",), resolver=_resolver_returning("140.82.121.34"))


def test_a_wildcard_pattern_matches_a_registry_subdomain() -> None:
    ref = parse_image_ref("registry.internal:5000/app:v2")
    check_registry_allowed(
        ref,
        ("*.internal",),
        allowed_ip_ranges=("10.0.0.0/8",),
        resolver=_resolver_returning("10.1.2.3"),
    )


# --- pull_image / remove_image ------------------------------------------------


async def test_pull_image_reports_a_missing_docker_binary_without_crashing(monkeypatch) -> None:
    # `pull_image` goes through `app.core.appsec.tooling.run_tool`, which
    # checks binary availability via `shutil.which` in that module.
    monkeypatch.setattr("app.core.appsec.tooling.shutil.which", lambda _binary: None)
    ref = parse_image_ref("nginx:1.25")
    result = await pull_image(ref)
    assert not result.ran
    assert "docker" in result.reason


async def test_remove_image_is_offline() -> None:
    """`docker rmi` never needs `NetworkUse.DECLARED_SERVICE` — the image is
    already local by the time cleanup runs."""
    import inspect

    from app.core.container import pull as pull_module

    source = inspect.getsource(pull_module.remove_image)
    assert "NetworkUse.OFFLINE" in source
