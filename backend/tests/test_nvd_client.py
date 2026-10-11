"""The NVD CVE API 2.0 client (`app/core/appsec/enrichment/nvd_client.py`):
request shape, response parsing (CVSS v3.1 present / v3.0-only / no v3 data
at all), HTTP error, malformed JSON, and the real scope engine proving this
context can reach exactly `services.nvd.nist.gov`. `FakeTransport` mirrors
`tests/test_osv_client.py`'s own.
"""

import json

import httpx
import pytest
import respx

from app.core.appsec.enrichment.egress import NVD_HOST, nvd_egress_context
from app.core.appsec.enrichment.nvd_client import (
    NvdClient,
    NvdClientError,
    cvss_v3_detail,
    english_description,
)
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, Observation, ScopeBlockedError
from tests.security.conftest import FakeDnsResolver


class FakeTransport:
    def __init__(self, responses: list[tuple[int, object]]) -> None:
        self._responses = responses
        self.calls: list[dict[str, object]] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append(kwargs)
        status, body = self._responses.pop(0)
        return Observation(
            method=str(kwargs.get("method")),
            url=str(kwargs.get("url")),
            status_code=status,
            headers={},
            elapsed_ms=1.0,
            body=json.dumps(body).encode("utf-8") if body is not None else b"",
        )


def _client(responses: list[tuple[int, object]]) -> tuple[NvdClient, FakeTransport]:
    transport = FakeTransport(responses)
    return NvdClient(transport=transport), transport  # type: ignore[arg-type]


_CVE_V31 = {
    "id": "CVE-2024-1234",
    "descriptions": [{"lang": "en", "value": "A critical thing happens."}],
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N",
                }
            }
        ]
    },
}


async def test_a_known_cve_is_returned() -> None:
    client, _ = _client([(200, {"vulnerabilities": [{"cve": _CVE_V31}]})])
    ctx = nvd_egress_context()

    cve = await client.get_cve(ctx, "CVE-2024-1234")

    assert cve is not None
    assert cve["id"] == "CVE-2024-1234"


async def test_the_request_names_the_cve_id() -> None:
    client, transport = _client([(200, {"vulnerabilities": [{"cve": _CVE_V31}]})])
    ctx = nvd_egress_context()

    await client.get_cve(ctx, "CVE-2024-1234")

    assert "cveId=CVE-2024-1234" in str(transport.calls[0]["url"])


async def test_an_unknown_cve_returns_none() -> None:
    client, _ = _client([(200, {"vulnerabilities": []})])
    ctx = nvd_egress_context()

    assert await client.get_cve(ctx, "CVE-9999-0001") is None


async def test_a_404_returns_none_rather_than_raising() -> None:
    client, _ = _client([(404, {})])
    ctx = nvd_egress_context()

    assert await client.get_cve(ctx, "CVE-9999-0001") is None


async def test_an_http_error_raises_nvd_client_error() -> None:
    client, _ = _client([(500, {"error": "boom"})])
    ctx = nvd_egress_context()

    with pytest.raises(NvdClientError):
        await client.get_cve(ctx, "CVE-2024-1234")


async def test_a_non_json_body_raises_nvd_client_error() -> None:
    class _BadBodyTransport(FakeTransport):
        async def send(self, ctx: object, **kwargs: object) -> Observation:
            return Observation(
                method="GET",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                status_code=200,
                headers={},
                elapsed_ms=1.0,
                body=b"not json",
            )

    client = NvdClient(transport=_BadBodyTransport([]))  # type: ignore[arg-type]
    ctx = nvd_egress_context()

    with pytest.raises(NvdClientError):
        await client.get_cve(ctx, "CVE-2024-1234")


def test_cvss_v3_1_detail_is_read() -> None:
    assert cvss_v3_detail(_CVE_V31) == (9.8, "CRITICAL", "CVSS:3.1/AV:N")


def test_cvss_v3_0_detail_is_read_when_v3_1_is_absent() -> None:
    cve = {
        "metrics": {
            "cvssMetricV30": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.0/AV:N",
                    }
                }
            ]
        }
    }
    assert cvss_v3_detail(cve) == (7.5, "HIGH", "CVSS:3.0/AV:N")


def test_a_v2_only_record_has_no_v3_detail() -> None:
    cve = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}}
    assert cvss_v3_detail(cve) is None


def test_a_record_with_no_metrics_has_no_v3_detail() -> None:
    assert cvss_v3_detail({}) is None


def test_the_english_description_is_selected() -> None:
    cve = {
        "descriptions": [
            {"lang": "es", "value": "cosa mala"},
            {"lang": "en", "value": "a bad thing"},
        ]
    }
    assert english_description(cve) == "a bad thing"


def test_no_description_at_all_returns_none() -> None:
    assert english_description({}) is None


# --- end to end: the real scope engine, not a stand-in ----------------------


@respx.mock
async def test_the_real_scope_engine_permits_exactly_nvd() -> None:
    route = respx.get(
        f"https://{NVD_HOST}/rest/json/cves/2.0", params={"cveId": "CVE-2024-1234"}
    ).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
    client = NvdClient(
        transport=GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({NVD_HOST: ["203.0.113.60"]})
        )
    )
    ctx = nvd_egress_context()

    result = await client.get_cve(ctx, "CVE-2024-1234")

    assert result is None
    assert route.called


async def test_the_real_scope_engine_refuses_every_other_host() -> None:
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({"evil.example.test": ["203.0.113.9"]})
    )
    ctx = nvd_egress_context()

    with pytest.raises(ScopeBlockedError):
        await transport.send(ctx, method="GET", url="https://evil.example.test/")
