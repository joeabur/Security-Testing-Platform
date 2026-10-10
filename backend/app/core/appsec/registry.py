"""The AppSec engine set (docs/BUILD_SPEC.md §26 Phase 14).

Explicit registration, same as the API and AI registries: an engine that is
not deliberately listed here does not run.
"""

from app.core.appsec.container.trivy_engine import ContainerScanEngine
from app.core.appsec.contract import AppSecEngine
from app.core.appsec.iac.checkov_engine import CheckovEngine
from app.core.appsec.osv.engine import OsvEngine, OsvPypiEngine
from app.core.appsec.sast.bandit_engine import BanditEngine
from app.core.appsec.sast.semgrep_engine import SemgrepEngine
from app.core.appsec.sca.pip_audit_engine import PipAuditEngine
from app.core.appsec.secrets.engine import SecretScanEngine
from app.core.appsec.secrets.gitleaks_engine import GitleaksEngine
from app.core.appsec.supplychain.eol_engine import EndOfLifeRuntimeEngine
from app.core.appsec.supplychain.license_engine import LicenseRiskEngine
from app.core.appsec.supplychain.malware_engine import MaliciousPackageEngine
from app.core.appsec.supplychain.typosquat_engine import NameConfusionEngine


def appsec_engines(*, allow_advisory_lookup: bool = False) -> list[AppSecEngine]:
    return [
        SemgrepEngine(),
        BanditEngine(),
        PipAuditEngine(allow_advisory_lookup=allow_advisory_lookup),
        # Same disclosure consent pip-audit's own lookup requires, since this
        # also sends the resolved dependency list to a third party — but the
        # party is osv.dev itself, called directly, rather than delegated to
        # a subprocess's own embedded advisory matching.
        OsvEngine(allow_advisory_lookup=allow_advisory_lookup),
        # A second, live source for Python dependencies, alongside pip-audit
        # above — not a replacement for it. pip-audit still resolves the
        # inventory that feeds the SBOM and can audit constraints this direct
        # query cannot (see `pypi_requirements.py`).
        OsvPypiEngine(allow_advisory_lookup=allow_advisory_lookup),
        SecretScanEngine(),
        # Two secrets engines on purpose: the one above reads the working tree,
        # this one reads the git history. A credential removed in a later commit
        # is still in the history, and one that was ever pushed is compromised.
        GitleaksEngine(),
        CheckovEngine(),
        # Supply-chain analysis. None of these reach the network, and all four
        # answer questions an advisory database cannot: an end-of-life runtime
        # has no CVE, a licence obligation is not a vulnerability, "is this the
        # package you meant" has no advisory behind it at all, and a vendored
        # malware match is checked against a snapshot rather than a live feed.
        EndOfLifeRuntimeEngine(),
        LicenseRiskEngine(),
        NameConfusionEngine(),
        MaliciousPackageEngine(),
        # Filesystem mode, not `docker pull`: see the module docstring for why
        # pulling a base image is not something this engine does on its own.
        ContainerScanEngine(),
    ]
