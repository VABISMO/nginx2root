# Security Policy

## Reporting a vulnerability in this repository

If you discover a security issue in the **tooling shipped here** (for example
a way to make `tools/check_exposure.py` send something other than an ordinary
HTTP/1.1 request, a path traversal in `tools/gen_certs.py`, or a flaw in the
CI workflow), please report it privately:

1. Use **GitHub Private Vulnerability Reporting** on this repository
   (*Security* → *Report a vulnerability*), or
2. contact the maintainer through the options listed on
   https://github.com/VABISMO if private reporting is unavailable.

Please include:

- a description of the issue and its impact;
- steps to reproduce against a **local** instance of this repository;
- any suggested fix, if you have one.

You should receive an acknowledgement within 7 days. Please allow a reasonable
time for a fix before any public disclosure.

## Out of scope

- Vulnerabilities in **nginx itself**, including CVE-2026-123007. Those are
  already disclosed and fixed by the vendor; report new nginx issues to F5 /
  nginx through https://nginx.org/en/security_advisories.html.
- Issues that require running the repository's lab in a way it does not
  document (for example exposing the vulnerable container to the public
  internet).

## Supported versions

This repository is a research lab, not a shipped product. Fixes are applied
to the latest commit on `main`.

## Safe use

The lab starts an **intentionally vulnerable** nginx 1.31.8 container. It
binds to `127.0.0.1` only. Do not:

- publish its ports to a network you do not control;
- point the validator at systems you are not authorised to test.

The validator itself is non-invasive: it sends ordinary HTTP/1.1 requests and
reads response headers. It never crafts protocol frames.
