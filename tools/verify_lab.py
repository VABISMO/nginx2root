#!/usr/bin/env python3
"""CI gate: assert that the lab behaves exactly as advertised.

Expected behaviour of the two lab containers:

  https://localhost:8443  ->  nginx/1.31.8, HTTP/2, verdict EXPOSED     (exit 2)
  https://localhost:9443  ->  nginx/1.31.9, HTTP/2, verdict NOT EXPOSED (exit 0)

The script waits for both endpoints, runs the real checker against them, and
fails loudly on any mismatch. Every asserted value is first printed by the
checker, so the output is self-explanatory — no hidden assumptions.

Environment overrides:
  VULN_URL, PATCHED_URL, LAB_TIMEOUT  (see defaults below)
"""

from __future__ import annotations

import os
import sys
import time

from check_exposure import (
    EXIT_EXPOSED,
    EXIT_NOT_EXPOSED,
    VERDICT_EXPOSED,
    VERDICT_NOT_EXPOSED,
    Colors,
    Result,
    check_target,
    format_report,
)

CA_FILE = os.path.join(os.path.dirname(__file__), "..", "lab", "certs", "server.crt")
VULN_URL = os.environ.get("VULN_URL", "https://localhost:8443")
PATCHED_URL = os.environ.get("PATCHED_URL", "https://localhost:9443")
TIMEOUT = float(os.environ.get("LAB_TIMEOUT", "90"))
POLL_INTERVAL = 2.0

PLAIN = Colors(enabled=False)

failures = 0


def fail(message: str) -> None:
    """Record a failed assertion and print it to stderr."""
    global failures
    failures += 1
    print(f"FAIL: {message}", file=sys.stderr)


def ok(message: str) -> None:
    """Print a passed assertion."""
    print(f"  ok: {message}")


def assert_eq(desc: str, actual: object, expected: object) -> None:
    """Assert ``actual == expected`` with a readable message."""
    if actual == expected:
        ok(desc)
    else:
        fail(f"{desc}: expected {expected!r}, got {actual!r}")


def wait_ready(url: str, deadline: float) -> None:
    """Poll ``url`` until it answers over TLS or the deadline passes."""
    while time.monotonic() < deadline:
        probe = check_target(url, cafile=CA_FILE, timeout=5.0)
        if probe.error is None:
            return
        time.sleep(POLL_INTERVAL)
    print(
        f"FAIL: timed out after {TIMEOUT:g}s waiting for {url}\n"
        "hint: start the lab with 'make up', inspect it with 'make logs'",
        file=sys.stderr,
    )
    sys.exit(1)


def run_case(
    label: str,
    url: str,
    expected_server: str,
    expected_verdict: str,
    expected_exit: int,
) -> None:
    """Run the checker against one lab target and assert its full report."""
    print(f"== {label}: {url} ==")
    result: Result = check_target(url, cafile=CA_FILE, timeout=10.0)
    print(format_report(result, PLAIN))
    print(f"(exit code: {result.exit_code})")
    print()

    assert_eq("negotiates HTTP/2", result.protocol, "HTTP/2")
    assert_eq(f"reports {expected_server}", result.server, expected_server)
    assert_eq("verdict", result.verdict, expected_verdict)
    assert_eq("exit code", result.exit_code, expected_exit)


def main() -> int:
    """Entry point; returns 0 when every assertion passed."""
    if not os.path.isfile(CA_FILE):
        print(
            f"FAIL: missing {CA_FILE} — run 'make certs' first",
            file=sys.stderr,
        )
        return 1

    print("== Waiting for lab endpoints ==")
    deadline = time.monotonic() + TIMEOUT
    wait_ready(VULN_URL, deadline)
    wait_ready(PATCHED_URL, deadline)
    print("both endpoints reachable")
    print()

    run_case(
        "Vulnerable target (expect EXPOSED, nginx/1.31.8)",
        VULN_URL,
        expected_server="nginx/1.31.8",
        expected_verdict=VERDICT_EXPOSED,
        expected_exit=EXIT_EXPOSED,
    )
    run_case(
        "Patched target (expect NOT EXPOSED, nginx/1.31.9)",
        PATCHED_URL,
        expected_server="nginx/1.31.9",
        expected_verdict=VERDICT_NOT_EXPOSED,
        expected_exit=EXIT_NOT_EXPOSED,
    )

    if failures == 0:
        print("LAB VERIFICATION: PASS")
        return 0
    print(f"LAB VERIFICATION: FAIL ({failures} assertion(s) failed)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
