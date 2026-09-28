"""`app.core.scope.asset_scope` — the fail-closed resolvers for the
CONTAINER/CLOUD_ACCOUNT/VIRTUAL_MACHINE/DOMAIN asset kinds' RoE scope
(the security-assessment-and-pentest module's foundation phase).

Same discipline as `test_scope_controls.py`: every refusal case gets its own
test, an unstated boundary is never treated as permissive, and a resolver
that accepted a stored document unchanged is the regression these guard
against.
"""

import pytest

# Aliased on import so pytest's "class starting with Test" collection heuristic
# does not try (and warn on failing) to collect this StrEnum as a test class.
from app.core.scope.asset_scope import TestDepth as Depth
from app.core.scope.asset_scope import (
    resolve_cloud_scope,
    resolve_container_scope,
    resolve_domain_scope,
    resolve_pentest_scope,
    resolve_vm_scope,
)
from app.core.scope.errors import AssetScopeValidationError

# --- container -----------------------------------------------------------


def test_container_scope_requires_allowed_registries() -> None:
    with pytest.raises(AssetScopeValidationError, match="allowed_registries"):
        resolve_container_scope({"image_ref": "registry.example.test/app:latest"})


def test_container_scope_resolves_with_a_declared_registry() -> None:
    scope = resolve_container_scope(
        {
            "image_ref": "registry.example.test/app:latest",
            "allowed_registries": ["registry.example.test"],
        }
    )
    assert scope.allowed_registries == ["registry.example.test"]
    assert scope.allow_live_pull is False


def test_container_scope_is_absent_by_default() -> None:
    with pytest.raises(AssetScopeValidationError, match="required"):
        resolve_container_scope(None)


# --- cloud -----------------------------------------------------------------


def test_cloud_scope_refuses_a_write_capable_declaration() -> None:
    with pytest.raises(AssetScopeValidationError, match="read_only"):
        resolve_cloud_scope(
            {
                "provider": "aws",
                "account_ref": "123456789012",
                "credential_env_var": "AEGIS_CLOUD_AWS_TOKEN",
                "read_only": False,
            }
        )


def test_cloud_scope_resolves_read_only() -> None:
    scope = resolve_cloud_scope(
        {
            "provider": "aws",
            "account_ref": "123456789012",
            "credential_env_var": "AEGIS_CLOUD_AWS_TOKEN",
        }
    )
    assert scope.read_only is True
    assert scope.provider == "aws"


def test_cloud_scope_rejects_an_unknown_provider() -> None:
    with pytest.raises(AssetScopeValidationError):
        resolve_cloud_scope(
            {
                "provider": "digitalocean",
                "account_ref": "abc",
                "credential_env_var": "AEGIS_CLOUD_TOKEN",
            }
        )


# --- vm ----------------------------------------------------------------


def test_vm_scope_requires_allowed_ports() -> None:
    with pytest.raises(AssetScopeValidationError, match="allowed_ports"):
        resolve_vm_scope({"host": "10.0.0.5"})


def test_vm_scope_resolves_with_declared_ports() -> None:
    scope = resolve_vm_scope({"host": "10.0.0.5", "allowed_ports": [22, 443]})
    assert scope.allowed_ports == [22, 443]
    assert scope.ssh_credential_env_var is None


# --- domain --------------------------------------------------------------


def test_domain_scope_defaults_to_no_subdomain_patterns() -> None:
    scope = resolve_domain_scope({"root_domain": "example.test"})
    assert scope.allowed_subdomain_patterns == []


def test_domain_scope_is_required() -> None:
    with pytest.raises(AssetScopeValidationError):
        resolve_domain_scope(None)


# --- pentest depth ---------------------------------------------------------


def test_test_depth_ordering() -> None:
    assert Depth.EXPLOITATION.at_least(Depth.DISCOVERY)
    assert not Depth.DISCOVERY.at_least(Depth.VALIDATION)
    assert Depth.VALIDATION.at_least(Depth.VALIDATION)


def test_pentest_scope_defaults_to_discovery_only() -> None:
    scope = resolve_pentest_scope(None)
    assert scope.max_depth is Depth.DISCOVERY
    assert scope.approved_modules == []


def test_pentest_scope_exploitation_requires_approved_modules() -> None:
    with pytest.raises(AssetScopeValidationError, match="approved_modules"):
        resolve_pentest_scope({"max_depth": "exploitation"})


def test_pentest_scope_exploitation_resolves_with_approved_modules() -> None:
    scope = resolve_pentest_scope(
        {"max_depth": "exploitation", "approved_modules": ["exploit/example/module"]}
    )
    assert scope.max_depth is Depth.EXPLOITATION
    assert scope.approved_modules == ["exploit/example/module"]
