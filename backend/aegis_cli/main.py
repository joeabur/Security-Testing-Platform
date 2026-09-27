"""`aegis-ai` — the command set from docs/BUILD_SPEC.md §20.

Every command is a REST call. Nothing here reaches a target directly, so
`--safe` is not enforced by the CLI: it is passed to the API, which is where
safe mode actually lives. A flag the CLI honoured by itself would be a second,
weaker gate.

Commands the platform cannot yet back are absent rather than stubbed. A
command that prints "not implemented" is still a command someone scripts
against, and `aegis-ai probes list` returning nothing would read as "this
build has no probes".
"""

import argparse
import getpass
import json
import sys
import time
from pathlib import Path
from typing import Any

from aegis_cli.client import ApiClient, CliError
from aegis_cli.config import Profile
from app.core.gate.evaluate import evaluate, load_config
from app.core.gate.model import ExitCode, GateConfigError, GateDecision, GateFinding

TERMINAL_STATUSES = {"completed", "failed", "cancelled", "expired"}


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return int(ExitCode.CONFIG_ERROR)

    profile = Profile.load()
    try:
        return int(args.handler(args, profile))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(exc.exit_code)
    except GateConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return int(ExitCode.CONFIG_ERROR)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return int(ExitCode.CONFIG_ERROR)


# --- plumbing -------------------------------------------------------------


def _client(profile: Profile) -> ApiClient:
    return ApiClient(profile.base_url, profile.token)


def _org(args: argparse.Namespace, profile: Profile) -> str:
    organization = getattr(args, "organization", None) or profile.organization_id
    if not organization:
        raise CliError(
            "no organization selected: pass --organization, set AEGIS_ORGANIZATION, "
            "or run `aegis-ai login`",
            ExitCode.CONFIG_ERROR,
        )
    return str(organization)


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"could not read {path}: {exc}", ExitCode.CONFIG_ERROR) from exc


def _read_yaml(path: str) -> dict[str, Any]:
    import yaml

    try:
        document = yaml.safe_load(_read_file(path)) or {}
    except yaml.YAMLError as exc:
        raise CliError(f"could not parse {path}: {exc}", ExitCode.CONFIG_ERROR) from exc
    if not isinstance(document, dict):
        raise CliError(f"{path} must contain a mapping", ExitCode.CONFIG_ERROR)
    return document


# --- commands -------------------------------------------------------------


def cmd_login(args: argparse.Namespace, profile: Profile) -> ExitCode:
    password = args.password or getpass.getpass("password: ")
    client = ApiClient(args.base_url or profile.base_url, None)
    cookie_name, anon_token = client.fetch_anon_csrf_token()
    payload = client.request(
        "POST",
        "/auth/login",
        json_body={"email": args.email, "password": password},
        authenticated=False,
        extra_headers={"X-CSRF-Token": anon_token},
        extra_cookies={cookie_name: anon_token},
    )
    token = payload.get("access_token")
    if not token:
        raise CliError("login succeeded but returned no token", ExitCode.AUTH_ERROR)

    profile.base_url = args.base_url or profile.base_url
    profile.token = token
    if args.organization:
        profile.organization_id = args.organization
    path = profile.save()
    print(f"logged in as {args.email}; credentials written to {path}")
    return ExitCode.PASS


def cmd_whoami(args: argparse.Namespace, profile: Profile) -> ExitCode:
    _emit(_client(profile).request("GET", "/auth/me"))
    return ExitCode.PASS


def cmd_orgs(args: argparse.Namespace, profile: Profile) -> ExitCode:
    _emit(_client(profile).request("GET", "/organizations"))
    return ExitCode.PASS


def cmd_target_list(args: argparse.Namespace, profile: Profile) -> ExitCode:
    _emit(_client(profile).request("GET", f"/organizations/{_org(args, profile)}/targets"))
    return ExitCode.PASS


def cmd_target_show(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(_client(profile).request("GET", f"/organizations/{org}/targets/{args.target}"))
    return ExitCode.PASS


# --- repositories -----------------------------------------------------------
# The fast path onto the code-scanning engines: a URL, a branch, and an
# affirmation of the right to have it scanned — no YAML, no separate
# Rules-of-Engagement/Authorization commands. See
# app/core/repositories/service.py for what this composes underneath.


def cmd_repo_add(args: argparse.Namespace, profile: Profile) -> ExitCode:
    if not args.authorized:
        raise CliError(
            "--authorized is required: pass it to affirm you have the right to have "
            "this repository scanned",
            ExitCode.CONFIG_ERROR,
        )
    org = _org(args, profile)
    body = {
        "name": args.name,
        "url": args.url,
        "branch": args.branch,
        "authorized": args.authorized,
    }
    if args.environment:
        body["environment"] = args.environment
    if args.language:
        body["languages"] = args.language
    if args.allowed_path:
        body["allowed_paths"] = args.allowed_path
    if args.excluded_path:
        body["excluded_paths"] = args.excluded_path
    if args.max_repo_size_mb:
        body["max_repo_size_mb"] = args.max_repo_size_mb
    _emit(_client(profile).request("POST", f"/organizations/{org}/repositories", json_body=body))
    return ExitCode.PASS


def cmd_repo_list(args: argparse.Namespace, profile: Profile) -> ExitCode:
    _emit(_client(profile).request("GET", f"/organizations/{_org(args, profile)}/repositories"))
    return ExitCode.PASS


def cmd_repo_show(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(_client(profile).request("GET", f"/organizations/{org}/repositories/{args.repository}"))
    return ExitCode.PASS


def cmd_repo_scan(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "POST",
            f"/organizations/{org}/repositories/{args.repository}/scan",
            json_body={"safe_mode": not args.unsafe},
        )
    )
    return ExitCode.PASS


def cmd_repo_remove(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _client(profile).request(
        "DELETE", f"/organizations/{org}/repositories/{args.repository}", expect_json=False
    )
    print(f"removed {args.repository}")
    return ExitCode.PASS


def cmd_target_add(args: argparse.Namespace, profile: Profile) -> ExitCode:
    _emit(
        _client(profile).request(
            "POST",
            f"/organizations/{_org(args, profile)}/targets",
            json_body=_read_yaml(args.config),
        )
    )
    return ExitCode.PASS


def cmd_target_roe(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "PUT",
            f"/organizations/{org}/targets/{args.target}/rules-of-engagement",
            json_body=_read_yaml(args.file),
        )
    )
    return ExitCode.PASS


def cmd_target_adapter(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "PUT",
            f"/organizations/{org}/targets/{args.target}/adapter",
            json_body=_read_yaml(args.file),
        )
    )
    return ExitCode.PASS


def cmd_target_code(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "PUT",
            f"/organizations/{org}/targets/{args.target}/code",
            json_body=_read_yaml(args.file),
        )
    )
    return ExitCode.PASS


def cmd_target_runtime_protection(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "PUT",
            f"/organizations/{org}/targets/{args.target}/runtime-protection",
            json_body=_read_yaml(args.file),
        )
    )
    return ExitCode.PASS


def cmd_auth_grant(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "POST",
            f"/organizations/{org}/targets/{args.target}/authorization",
            json_body=_read_yaml(args.file),
        )
    )
    return ExitCode.PASS


def cmd_auth_verify(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request("GET", f"/organizations/{org}/targets/{args.target}/authorization")
    )
    return ExitCode.PASS


def cmd_scope_validate(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "GET", f"/organizations/{org}/targets/{args.target}/rules-of-engagement"
        )
    )
    return ExitCode.PASS


def cmd_scope_explain(args: argparse.Namespace, profile: Profile) -> ExitCode:
    """The dry run. Exits 4 when the engine refuses, so a pipeline can check
    its scope configuration without launching a scan."""
    org = _org(args, profile)
    decision = _client(profile).request(
        "POST",
        f"/organizations/{org}/targets/{args.target}/scope/explain",
        json_body={"url": args.url, "method": args.method},
    )
    _emit(decision)
    return ExitCode.PASS if decision.get("allowed") else ExitCode.SCOPE_VIOLATION


def cmd_discover(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "PUT",
            f"/organizations/{org}/targets/{args.target}/openapi",
            json_body={"document": _read_file(args.file)},
        )
    )
    return ExitCode.PASS


def cmd_scan(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    client = _client(profile)
    if args.dry_run:
        # A dry run must not create anything, so it reports what would be
        # exercised rather than queueing work.
        _emit(client.request("GET", f"/organizations/{org}/targets/{args.target}/surface"))
        return ExitCode.PASS

    run = client.request(
        "POST",
        f"/organizations/{org}/runs",
        json_body={
            "target_id": args.target,
            "authorization_confirmed": True,
            "profile": args.profile,
            "safe_mode": not args.unsafe,
        },
    )
    if args.wait:
        run = _await_run(client, org, str(run["id"]), args.timeout)
    _emit(run)
    return ExitCode.PASS


def cmd_runs_list(args: argparse.Namespace, profile: Profile) -> ExitCode:
    _emit(_client(profile).request("GET", f"/organizations/{_org(args, profile)}/runs"))
    return ExitCode.PASS


def cmd_runs_show(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(_client(profile).request("GET", f"/organizations/{org}/runs/{args.run}"))
    return ExitCode.PASS


def cmd_kill(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(_client(profile).request("POST", f"/organizations/{org}/runs/{args.run}/cancel"))
    return ExitCode.PASS


def cmd_findings_list(args: argparse.Namespace, profile: Profile) -> ExitCode:
    params: dict[str, Any] = {}
    if args.severity:
        params["severity"] = args.severity.upper()
    if args.status:
        params["finding_status"] = args.status
    if args.run:
        params["run_id"] = args.run
    _emit(
        _client(profile).request(
            "GET", f"/organizations/{_org(args, profile)}/findings", params=params
        )
    )
    return ExitCode.PASS


def cmd_findings_set_status(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "POST",
            f"/organizations/{org}/findings/{args.id}/status",
            json_body={"status": args.status, "note": args.note},
        )
    )
    return ExitCode.PASS


def cmd_retest(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    client = _client(profile)
    run = client.request(
        "POST",
        f"/organizations/{org}/retests",
        json_body={
            "target_id": args.target,
            "finding_ids": args.finding,
            "authorization_confirmed": True,
        },
    )
    if args.wait:
        _await_run(client, org, str(run["id"]), args.timeout)
        _emit(client.request("GET", f"/organizations/{org}/runs/{run['id']}/retest-results"))
        return ExitCode.PASS
    _emit(run)
    return ExitCode.PASS


def cmd_report(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    client = _client(profile)
    destination = Path(args.output) if args.output else None
    if destination is not None:
        destination.mkdir(parents=True, exist_ok=True)

    for fmt in [item.strip() for item in args.format.split(",") if item.strip()]:
        response = client.request(
            "GET",
            f"/organizations/{org}/runs/{args.run}/report",
            params={"report_format": fmt, "template": args.template},
            expect_json=False,
        )
        if destination is None:
            sys.stdout.write(response.text)
            continue
        name = _filename_of(response) or f"aegis-report-{args.run}-{args.template}.{fmt}"
        path = destination / name
        path.write_bytes(response.content)
        print(f"wrote {path}")
    return ExitCode.PASS


def cmd_evidence_list(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(_client(profile).request("GET", f"/organizations/{org}/runs/{args.run}/evidence"))
    return ExitCode.PASS


def cmd_evidence_verify(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    result = _client(profile).request(
        "GET", f"/organizations/{org}/runs/{args.run}/evidence/verify"
    )
    _emit(result)
    # A broken chain is a failure, not information: it means the evidence
    # behind a report cannot be trusted.
    return ExitCode.PASS if result.get("ok") else ExitCode.GATE_FAILED


def cmd_channels_list(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(_client(profile).request("GET", f"/organizations/{org}/notification-channels"))
    return ExitCode.PASS


def cmd_channels_add(args: argparse.Namespace, profile: Profile) -> ExitCode:
    """Create a channel.

    Note that no secret is passed on the command line — `--endpoint-env-var`
    names the variable that holds the webhook URL. A CLI that took the URL
    would put it in the operator's shell history.
    """
    org = _org(args, profile)
    payload: dict[str, object] = {
        "name": args.name,
        "kind": args.kind,
        "events": args.event,
    }
    if args.endpoint_env_var:
        payload["endpoint_env_var"] = args.endpoint_env_var
    if args.signing_secret_env_var:
        payload["signing_secret_env_var"] = args.signing_secret_env_var
    if args.min_severity:
        payload["min_severity"] = args.min_severity
    _emit(
        _client(profile).request(
            "POST", f"/organizations/{org}/notification-channels", json_body=payload
        )
    )
    return ExitCode.PASS


def cmd_channels_test(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    result = _client(profile).request(
        "POST", f"/organizations/{org}/notification-channels/{args.channel}/test"
    )
    _emit(result)
    # A channel that cannot deliver is a failure: silence during an incident is
    # the outcome this command exists to rule out.
    return ExitCode.PASS if result.get("delivered") else ExitCode.GATE_FAILED


def cmd_channels_deliveries(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "GET", f"/organizations/{org}/notification-channels/{args.channel}/deliveries"
        )
    )
    return ExitCode.PASS


def cmd_pr_publish(args: argparse.Namespace, profile: Profile) -> ExitCode:
    """Post a run's findings to a pull request as a check run.

    Exits non-zero when the check run concluded `failure`, so a CI job can use
    this in place of a separate gate step and get one verdict rather than two
    that could disagree.
    """
    org = _org(args, profile)
    result = _client(profile).request(
        "POST",
        f"/organizations/{org}/vcs-connections/{args.connection}/publish",
        json_body={
            "repo_owner": args.owner,
            "repo_name": args.repo,
            "pull_number": args.pr,
            "head_sha": args.sha,
            "run_id": args.run,
        },
    )
    _emit(result)
    return ExitCode.GATE_FAILED if result.get("conclusion") == "failure" else ExitCode.PASS


def cmd_pr_posts(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    _emit(
        _client(profile).request(
            "GET", f"/organizations/{org}/vcs-connections/{args.connection}/posts"
        )
    )
    return ExitCode.PASS


def cmd_gate(args: argparse.Namespace, profile: Profile) -> ExitCode:
    org = _org(args, profile)
    client = _client(profile)
    config = load_config(_read_file(args.config)) if args.config else load_config("")

    payload = client.request("GET", f"/organizations/{org}/findings", params={"run_id": args.run})
    decision = evaluate([GateFinding.from_api(item) for item in payload], config)
    _print_decision(decision)
    return decision.exit_code


def cmd_ci(args: argparse.Namespace, profile: Profile) -> ExitCode:
    """Scan, wait, then gate — the whole pipeline step in one command."""
    org = _org(args, profile)
    client = _client(profile)
    config = load_config(_read_file(args.config)) if args.config else load_config("")
    if args.fail_on:
        config = load_config(
            "security_gate:\n  fail_on: ["
            + ", ".join(item.strip() for item in args.fail_on.split(","))
            + "]\n"
        )

    run = client.request(
        "POST",
        f"/organizations/{org}/runs",
        json_body={
            "target_id": args.target,
            "authorization_confirmed": True,
            "profile": args.profile,
            "safe_mode": not args.unsafe,
        },
    )
    run = _await_run(client, org, str(run["id"]), args.timeout)

    # A run that halted did not finish looking, so its findings are not a
    # basis for passing a build. Reported as a scope violation rather than a
    # pass, because that is what "we were stopped" means to a pipeline.
    if run.get("halted_reason"):
        print(
            f"run {run['id']} halted: {run['halted_reason']}",
            file=sys.stderr,
        )
        return ExitCode.SCOPE_VIOLATION

    payload = client.request("GET", f"/organizations/{org}/findings", params={"run_id": run["id"]})
    decision = evaluate([GateFinding.from_api(item) for item in payload], config)
    _print_decision(decision)
    return decision.exit_code


# --- helpers --------------------------------------------------------------


def _await_run(client: ApiClient, org: str, run_id: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        run = client.request("GET", f"/organizations/{org}/runs/{run_id}")
        if str(run.get("status")) in TERMINAL_STATUSES:
            return dict(run)
        if time.monotonic() >= deadline:
            raise CliError(
                f"run {run_id} did not finish within {timeout:.0f}s (status "
                f"{run.get('status')}); it is still running — check it with "
                "`aegis-ai runs show`",
                ExitCode.CONFIG_ERROR,
            )
        time.sleep(2.0)


def _filename_of(response: Any) -> str | None:
    disposition = response.headers.get("content-disposition", "")
    marker = 'filename="'
    if marker not in disposition:
        return None
    return disposition.split(marker, 1)[1].split('"', 1)[0] or None


def _print_decision(decision: GateDecision) -> None:
    """Everything the gate decided, including what it skipped.

    §23: a gate nobody can argue with is a gate people bypass. The excluded
    list is printed for that reason — "why did this not fail?" has to be
    answerable from the CI log alone.
    """
    print("security gate: " + ("PASS" if decision.passed else "FAIL"))
    print(
        "counts: "
        + ", ".join(f"{name.lower()}={count}" for name, count in sorted(decision.counts.items()))
    )
    for reason in decision.reasons:
        print(f"  ! {reason}")
    for finding in decision.blocking:
        print(f"  [{finding.severity.value}] {finding.title}  {finding.fingerprint}")
    if decision.excluded:
        print(f"not counted ({len(decision.excluded)}):")
        for item in decision.excluded:
            print(f"  - [{item.finding.severity.value}] {item.finding.title}: {item.reason}")


# --- argument parsing -----------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-ai",
        description="Aegis AI Security — every command is a call to the same REST API "
        "the web UI uses.",
    )
    parser.add_argument("--organization", help="organization id (or AEGIS_ORGANIZATION)")
    subparsers = parser.add_subparsers(dest="command")

    login = subparsers.add_parser("login", help="authenticate and store a token")
    login.add_argument("--email", required=True)
    login.add_argument("--password", help="prompted for if omitted")
    login.add_argument("--base-url")
    login.set_defaults(handler=cmd_login)

    subparsers.add_parser("whoami", help="show the authenticated user").set_defaults(
        handler=cmd_whoami
    )
    subparsers.add_parser("orgs", help="list organizations").set_defaults(handler=cmd_orgs)

    target = subparsers.add_parser("target", help="targets").add_subparsers(dest="action")
    target.add_parser("list").set_defaults(handler=cmd_target_list)
    show = target.add_parser("show")
    show.add_argument("target")
    show.set_defaults(handler=cmd_target_show)
    add = target.add_parser("add")
    add.add_argument("--config", required=True, help="YAML describing the target")
    add.set_defaults(handler=cmd_target_add)
    roe = target.add_parser("roe", help="set rules of engagement")
    roe.add_argument("--target", required=True)
    roe.add_argument("--file", required=True, help="YAML rules-of-engagement record")
    roe.set_defaults(handler=cmd_target_roe)
    adapter = target.add_parser("adapter", help="set which adapter speaks to this target")
    adapter.add_argument("--target", required=True)
    adapter.add_argument("--file", required=True, help="YAML adapter configuration")
    adapter.set_defaults(handler=cmd_target_adapter)
    code = target.add_parser("code", help="declare the source-code surface (admin)")
    code.add_argument("--target", required=True)
    code.add_argument("--file", required=True, help="YAML code-scope configuration")
    code.set_defaults(handler=cmd_target_code)
    runtime_protection = target.add_parser(
        "runtime-protection", help="declare claimed runtime controls (admin)"
    )
    runtime_protection.add_argument("--target", required=True)
    runtime_protection.add_argument("--file", required=True, help="YAML runtime-protection record")
    runtime_protection.set_defaults(handler=cmd_target_runtime_protection)

    repo = subparsers.add_parser(
        "repo", help="connect a repository for code scanning (SAST/SCA/secrets/IaC)"
    ).add_subparsers(dest="action")
    repo_add = repo.add_parser("add", help="connect a repository")
    repo_add.add_argument("--name", required=True)
    repo_add.add_argument(
        "--url", required=True, help="repository URL, e.g. https://host/org/repo.git"
    )
    repo_add.add_argument("--branch")
    repo_add.add_argument(
        "--authorized",
        action="store_true",
        help="affirm you have the right to have this repository scanned (required)",
    )
    repo_add.add_argument(
        "--environment", choices=["staging", "test", "dev", "production"], default=None
    )
    repo_add.add_argument("--language", action="append", help="repeatable")
    repo_add.add_argument(
        "--allowed-path", action="append", help="glob, repeatable; defaults to everything"
    )
    repo_add.add_argument("--excluded-path", action="append", help="glob, repeatable")
    repo_add.add_argument("--max-repo-size-mb", type=int)
    repo_add.set_defaults(handler=cmd_repo_add)
    repo.add_parser("list").set_defaults(handler=cmd_repo_list)
    repo_show = repo.add_parser("show")
    repo_show.add_argument("repository")
    repo_show.set_defaults(handler=cmd_repo_show)
    repo_scan = repo.add_parser("scan")
    repo_scan.add_argument("repository")
    repo_scan.add_argument(
        "--unsafe",
        action="store_true",
        help="disable safe mode; the API decides what that permits, not the CLI",
    )
    repo_scan.set_defaults(handler=cmd_repo_scan)
    repo_remove = repo.add_parser("remove")
    repo_remove.add_argument("repository")
    repo_remove.set_defaults(handler=cmd_repo_remove)

    auth = subparsers.add_parser("auth", help="authorization grants").add_subparsers(dest="action")
    grant = auth.add_parser("grant")
    grant.add_argument("--target", required=True)
    grant.add_argument("--file", required=True, help="YAML authorization record")
    grant.set_defaults(handler=cmd_auth_grant)
    verify = auth.add_parser("verify")
    verify.add_argument("--target", required=True)
    verify.set_defaults(handler=cmd_auth_verify)

    scope = subparsers.add_parser("scope", help="scope configuration").add_subparsers(dest="action")
    validate = scope.add_parser("validate")
    validate.add_argument("target")
    validate.set_defaults(handler=cmd_scope_validate)
    explain = scope.add_parser("explain", help="dry-run one URL against the scope engine")
    explain.add_argument("target")
    explain.add_argument("--url", required=True)
    explain.add_argument("--method", default="GET")
    explain.set_defaults(handler=cmd_scope_explain)

    discover = subparsers.add_parser("discover", help="upload an OpenAPI document")
    discover.add_argument("target")
    discover.add_argument("--file", required=True)
    discover.set_defaults(handler=cmd_discover)

    scan = subparsers.add_parser("scan", help="start an assessment")
    scan.add_argument("target")
    scan.add_argument("--profile", default="full", choices=["ai", "api", "full", "connectivity"])
    scan.add_argument(
        "--unsafe",
        action="store_true",
        help="disable safe mode; the API decides what that permits, not the CLI",
    )
    scan.add_argument("--dry-run", action="store_true", help="show the surface, queue nothing")
    scan.add_argument("--wait", action="store_true")
    scan.add_argument("--timeout", type=float, default=1800.0)
    scan.set_defaults(handler=cmd_scan)

    runs = subparsers.add_parser("runs", help="assessment runs").add_subparsers(dest="action")
    runs.add_parser("list").set_defaults(handler=cmd_runs_list)
    run_show = runs.add_parser("show")
    run_show.add_argument("run")
    run_show.set_defaults(handler=cmd_runs_show)

    kill = subparsers.add_parser("kill", help="cancel a running assessment")
    kill.add_argument("--run", required=True)
    kill.set_defaults(handler=cmd_kill)

    findings = subparsers.add_parser("findings", help="findings").add_subparsers(dest="action")
    listing = findings.add_parser("list")
    listing.add_argument("--severity")
    listing.add_argument("--status")
    listing.add_argument("--run")
    listing.set_defaults(handler=cmd_findings_list)
    set_status = findings.add_parser("set-status")
    set_status.add_argument("id")
    set_status.add_argument("--status", required=True)
    set_status.add_argument("--note")
    set_status.set_defaults(handler=cmd_findings_set_status)

    retest = subparsers.add_parser("retest", help="re-check specific findings")
    retest.add_argument("target")
    retest.add_argument("--finding", action="append", required=True, help="repeatable")
    retest.add_argument("--wait", action="store_true")
    retest.add_argument("--timeout", type=float, default=1800.0)
    retest.set_defaults(handler=cmd_retest)

    report = subparsers.add_parser("report", help="download a report")
    report.add_argument("--run", required=True)
    report.add_argument("--format", default="markdown", help="comma-separated")
    report.add_argument(
        "--template",
        default="technical",
        choices=["technical", "executive", "developer", "compliance"],
    )
    report.add_argument("--output", help="directory; prints to stdout if omitted")
    report.set_defaults(handler=cmd_report)

    evidence = subparsers.add_parser("evidence", help="evidence").add_subparsers(dest="action")
    ev_list = evidence.add_parser("list")
    ev_list.add_argument("--run", required=True)
    ev_list.set_defaults(handler=cmd_evidence_list)
    ev_verify = evidence.add_parser("verify")
    ev_verify.add_argument("--run", required=True)
    ev_verify.set_defaults(handler=cmd_evidence_verify)

    channels = subparsers.add_parser("channels", help="notification channels").add_subparsers(
        dest="action"
    )
    channels.add_parser("list").set_defaults(handler=cmd_channels_list)
    ch_add = channels.add_parser("add")
    ch_add.add_argument("--name", required=True)
    ch_add.add_argument(
        "--kind",
        required=True,
        choices=["slack_webhook", "msteams_webhook", "generic_webhook", "email_smtp"],
    )
    ch_add.add_argument(
        "--event", action="append", required=True, help="repeatable; an event type to subscribe to"
    )
    ch_add.add_argument(
        "--endpoint-env-var", help="name of the variable holding the webhook URL (not the URL)"
    )
    ch_add.add_argument("--signing-secret-env-var")
    ch_add.add_argument("--min-severity")
    ch_add.set_defaults(handler=cmd_channels_add)
    ch_test = channels.add_parser("test")
    ch_test.add_argument("--channel", required=True)
    ch_test.set_defaults(handler=cmd_channels_test)
    ch_deliveries = channels.add_parser("deliveries")
    ch_deliveries.add_argument("--channel", required=True)
    ch_deliveries.set_defaults(handler=cmd_channels_deliveries)

    pr = subparsers.add_parser("pr", help="pull requests").add_subparsers(dest="action")
    pr_publish = pr.add_parser("publish")
    pr_publish.add_argument("--connection", required=True, help="code host connection id")
    pr_publish.add_argument("--owner", required=True)
    pr_publish.add_argument("--repo", required=True)
    pr_publish.add_argument("--pr", required=True, type=int)
    pr_publish.add_argument("--sha", required=True, help="the pull request's head commit")
    pr_publish.add_argument("--run", required=True, help="the run whose findings to publish")
    pr_publish.set_defaults(handler=cmd_pr_publish)
    pr_posts = pr.add_parser("posts")
    pr_posts.add_argument("--connection", required=True)
    pr_posts.set_defaults(handler=cmd_pr_posts)

    gate = subparsers.add_parser("gate", help="apply a security gate to a finished run")
    gate.add_argument("--run", required=True)
    gate.add_argument("--config", help="security-gate.yaml; defaults apply if omitted")
    gate.set_defaults(handler=cmd_gate)

    ci = subparsers.add_parser("ci", help="scan, wait, and gate in one step")
    ci.add_argument("--target", required=True)
    ci.add_argument("--config")
    ci.add_argument("--fail-on", help="comma-separated severities; overrides the config file")
    ci.add_argument("--profile", default="full", choices=["ai", "api", "full", "connectivity"])
    ci.add_argument("--unsafe", action="store_true")
    ci.add_argument("--timeout", type=float, default=1800.0)
    ci.set_defaults(handler=cmd_ci)

    return parser


if __name__ == "__main__":  # pragma: no cover - exercised as a console script
    raise SystemExit(main())
