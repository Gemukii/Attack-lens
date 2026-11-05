"""Audit support: a scope that is enforced, and a report that can be handed over.

In audit mode, a target has to resolve inside the scope of an active engagement. The
check runs on the resolved address, because a name can point anywhere.
"""

import hashlib
import ipaddress
import os
import socket
from datetime import UTC, datetime
from html import escape
from typing import Any

from attacklens import __version__


class OutOfScope(Exception):
    """The target is not covered by an active engagement."""


def audit_mode_enabled() -> bool:
    """Return whether scans must stay inside an engagement."""
    return os.getenv("ATTACKLENS_AUDIT_MODE", "").strip().lower() in {"1", "true", "yes"}


def parse_scope(entries: list[str]) -> list[str]:
    """Normalize a scope and reject anything that is not a network or an address."""
    networks = []
    for entry in entries:
        try:
            networks.append(str(ipaddress.ip_network(entry.strip(), strict=False)))
        except ValueError as error:
            raise ValueError(f"Invalid scope entry: {entry}") from error
    if not networks:
        raise ValueError("A scope needs at least one network.")
    return networks


def resolved_addresses(target: str) -> set[str]:
    """Return every address a target resolves to."""
    try:
        return {info[4][0].split("%")[0] for info in socket.getaddrinfo(target, None)}
    except (OSError, UnicodeError) as error:
        raise OutOfScope(f"Unable to resolve '{target}'.") from error


def is_in_scope(addresses: set[str], networks: list[str]) -> bool:
    """A target is in scope only if all its addresses are."""
    parsed = [ipaddress.ip_network(network) for network in networks]
    return bool(addresses) and all(
        any(ipaddress.ip_address(address) in network for network in parsed)
        for address in addresses
    )


def enforce_scope(target: str, engagements: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the engagement covering a target, or refuse the scan."""
    now = datetime.now(UTC).isoformat()
    active = [item for item in engagements if item["starts_at"] <= now <= item["ends_at"]]
    if not active:
        raise OutOfScope("Audit mode is on and no engagement is active.")
    addresses = resolved_addresses(target)
    for engagement in active:
        if is_in_scope(addresses, engagement["scope"]):
            return engagement
    raise OutOfScope(f"'{target}' is outside the scope of the active engagements.")


def _rows(findings: list[dict[str, Any]]) -> str:
    """Render findings, most urgent first. Every value comes from a scan: escape it all."""
    ordered = sorted(findings, key=lambda item: -item.get("risk", {}).get("score", 0))
    return "".join(
        "<tr>"
        f"<td>{escape(str(item.get('risk', {}).get('priority', '-')))}</td>"
        f"<td>{escape(str(item.get('severity', '-')))}</td>"
        f"<td>{escape(str(item.get('title', '')))}</td>"
        f"<td>{escape(str(item.get('evidence', '')))}</td>"
        f"<td>{escape(str(item.get('verification') or '-'))}</td>"
        f"<td>{escape(str(item.get('remediation', '')))}</td>"
        "</tr>"
        for item in ordered
    )


def _paths(paths: dict[str, Any]) -> str:
    """Render the attack paths."""
    if not paths["paths"]:
        return "<p>No complete attack path was identified.</p>"
    items = "".join(
        f"<li><strong>{escape(path['title'])}</strong> ({escape(path['certainty'])}): "
        + " &rarr; ".join(escape(step["label"]) for step in path["steps"])
        + "</li>"
        for path in paths["paths"]
    )
    return f"<ol>{items}</ol>"


def render_report(
    target: str,
    network: dict[str, Any] | None,
    host: dict[str, Any] | None,
    paths: dict[str, Any],
    engagement: dict[str, Any] | None,
) -> str:
    """Build a self-contained, printable report."""
    findings = [*(network or {}).get("findings", []), *(host or {}).get("findings", [])]
    active = [item for item in findings if item.get("triage_status", "open") == "open"]
    dismissed = [item for item in findings if item.get("triage_status", "open") != "open"]
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")

    context = ""
    if engagement:
        context = (
            f"<p>Engagement: {escape(engagement['name'])}. "
            f"Authorized by {escape(engagement['authorized_by'])} "
            f"(reference {escape(engagement['reference'])}). "
            f"Scope: {escape(', '.join(engagement['scope']))}.</p>"
        )
    body = (
        f"<h1>Security assessment of {escape(target)}</h1>{context}"
        f"<p>Generated {generated_at} by AttackLens {escape(__version__)}.</p>"
        f"<p>Network scan: {escape(str((network or {}).get('completed_at', 'none')))}. "
        f"Host report: {escape(str((host or {}).get('completed_at', 'none')))}.</p>"
        f"<h2>Attack paths</h2>{_paths(paths)}"
        f"<h2>Findings ({len(active)})</h2>"
        "<table><tr><th>Priority</th><th>Severity</th><th>Finding</th><th>Evidence</th>"
        f"<th>Check</th><th>Remediation</th></tr>{_rows(active)}</table>"
        f"<h2>Accepted or dismissed ({len(dismissed)})</h2>"
        "<table><tr><th>Priority</th><th>Severity</th><th>Finding</th><th>Evidence</th>"
        f"<th>Check</th><th>Remediation</th></tr>{_rows(dismissed)}</table>"
        "<h2>Limits</h2><p>This report describes what was observed at the times above. "
        "It is not proof that no other weakness exists.</p>"
    )
    digest = hashlib.sha256(body.encode()).hexdigest()
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>AttackLens report: {escape(target)}</title><style>"
        "body{font:14px/1.5 Georgia,serif;color:#15120e;max-width:960px;margin:40px auto;"
        "padding:0 16px}h1,h2{font-family:Arial Narrow,Arial,sans-serif}"
        "table{border-collapse:collapse;width:100%;font-size:12px}"
        "th,td{border-bottom:1px solid #bbb;padding:6px;text-align:left;vertical-align:top}"
        "footer{margin-top:32px;font-size:11px;color:#555;word-break:break-all}"
        f"</style></head><body>{body}<footer>SHA-256 of this report: {digest}</footer>"
        "</body></html>"
    )
