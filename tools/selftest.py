#!/usr/bin/env python3
"""Dependency-free self-test for the validator's pure logic.

Runs the parsing and classification matrix without touching the network, so it
can gate every commit in milliseconds. The end-to-end A/B behaviour is covered
separately by ``verify_lab.py`` against the real lab containers.

Usage:  python tools/selftest.py     (exit code 0 = all assertions passed)
"""

from __future__ import annotations

import sys

from check_exposure import (
    EXIT_CANNOT_ASSESS,
    EXIT_EXPOSED,
    EXIT_NOT_EXPOSED,
    STATUS_VULNERABLE,
    VERDICT_EXPOSED,
    VERDICT_NO_H2,
    VERDICT_NOT_EXPOSED,
    classify,
    parse_nginx_version,
    parse_target,
)

CHECKS = 0


def check(description: str, actual: object, expected: object) -> None:
    """Assert one expectation and count it."""
    global CHECKS
    CHECKS += 1
    if actual != expected:
        print(f"FAIL: {description}: expected {expected!r}, got {actual!r}")
        raise SystemExit(1)


def test_parse_target() -> None:
    """Every accepted target form resolves to (scheme, host, port)."""
    check("URL with path", parse_target("https://example.com:8443/x"),
          ("https", "example.com", 8443))
    check("bare host", parse_target("example.com"), ("https", "example.com", 443))
    check("host:port", parse_target("example.com:9443"),
          ("https", "example.com", 9443))
    check("bare IPv6 untouched", parse_target("::1"), ("https", "::1", 443))
    check("http scheme", parse_target("http://h"), ("http", "h", 80))
    check("explicit port wins", parse_target("https://h:9443", 443),
          ("https", "h", 443))

    for bad in ("ftp://h", "https://", "://nope"):
        try:
            parse_target(bad)
        except ValueError:
            check(f"rejects {bad!r}", True, True)
        else:
            check(f"rejects {bad!r}", "accepted", "ValueError")


def test_parse_version() -> None:
    """Server header parsing normalizes to a 3-tuple or None."""
    check("full version", parse_nginx_version("nginx/1.31.8"), (1, 31, 8))
    check("two-part version", parse_nginx_version("nginx/1.30"), (1, 30, 0))
    check("tokens off", parse_nginx_version("nginx"), None)
    check("other product", parse_nginx_version("Apache/2.4"), None)
    check("empty", parse_nginx_version(None), None)


def test_classify() -> None:
    """The affected-range matrix matches the nginx advisory exactly."""
    # Vulnerable range endpoints.
    check("first affected (1.9.5)", classify((1, 9, 5), True)[2], EXIT_EXPOSED)
    check("last vulnerable stable (1.30.6)", classify((1, 30, 6), True)[2],
          EXIT_EXPOSED)
    check("first vulnerable mainline (1.31.0)", classify((1, 31, 0), True)[2],
          EXIT_EXPOSED)
    check("last vulnerable mainline (1.31.8)", classify((1, 31, 8), True)[2],
          EXIT_EXPOSED)

    # Fixed releases.
    check("fixed stable (1.30.7)", classify((1, 30, 7), True)[2],
          EXIT_NOT_EXPOSED)
    check("fixed mainline (1.31.9)", classify((1, 31, 9), True)[2],
          EXIT_NOT_EXPOSED)
    check("future release", classify((1, 40, 0), True)[2], EXIT_NOT_EXPOSED)

    # Before HTTP/2 existed.
    check("pre-HTTP/2 (1.9.4)", classify((1, 9, 4), True)[2], EXIT_NOT_EXPOSED)

    # HTTP/2 disabled: version vulnerable, but the code path is unreachable.
    status, verdict, code, warnings = classify((1, 31, 8), False)
    check("h2 disabled code", code, EXIT_NOT_EXPOSED)
    check("h2 disabled verdict", verdict, VERDICT_NO_H2)
    check("h2 disabled status", status, STATUS_VULNERABLE)
    check("h2 disabled warns", len(warnings), 1)

    # Happy-path labels stay stable (verify_lab.py asserts on them).
    check("exposed verdict", classify((1, 31, 8), True)[1], VERDICT_EXPOSED)
    check("fixed verdict", classify((1, 31, 9), True)[1], VERDICT_NOT_EXPOSED)


def test_exit_code_domain() -> None:
    """Exit codes are the documented values and never overlap."""
    check("exposed", EXIT_EXPOSED, 2)
    check("not exposed", EXIT_NOT_EXPOSED, 0)
    check("cannot assess", EXIT_CANNOT_ASSESS, 1)
    check("distinct", len({EXIT_EXPOSED, EXIT_NOT_EXPOSED, EXIT_CANNOT_ASSESS}), 3)


def main() -> int:
    """Run every test group; returns a process exit code."""
    for group in (
        test_parse_target,
        test_parse_version,
        test_classify,
        test_exit_code_domain,
    ):
        group()
        print(f"ok: {group.__name__}")
    print(f"SELFTEST: PASS ({CHECKS} assertions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
