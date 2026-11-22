#!/usr/bin/env python3
"""Non-invasive exposure validator for CVE-2026-123007 (nginx2root).

Determines whether an nginx endpoint is exposed to the HTTP/2 flow-control
integer underflow disclosed on 18 November 2026 by combining two facts:

  1. the nginx version advertised in the ``Server`` response header, checked
     against the affected ranges (1.9.5 - 1.31.8; fixed in 1.30.7+ / 1.31.9+);
  2. whether the TLS handshake actually negotiates HTTP/2 via ALPN (``h2``),
     because the vulnerable code path only exists when HTTP/2 is enabled.

The checker sends ordinary HTTP/1.1 requests only. It never crafts protocol
frames and never attempts to trigger the vulnerability.

Exit codes:
  0  target assessed, not exposed (fixed, not affected, or HTTP/2 disabled)
  1  could not assess (unreachable, TLS failure, version not disclosed)
  2  target assessed, EXPOSED to CVE-2026-123007
  64 usage error
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Exit codes (64 mirrors sysexits EX_USAGE so that a usage mistake can never
# be mistaken for "exposed").
# ---------------------------------------------------------------------------
EXIT_NOT_EXPOSED = 0
EXIT_CANNOT_ASSESS = 1
EXIT_EXPOSED = 2
EXIT_USAGE = 64

# ---------------------------------------------------------------------------
# nginx version thresholds for CVE-2026-123007 (nginx security advisory).
# ---------------------------------------------------------------------------
VERSION_MIN_AFFECTED = (1, 9, 5)  # HTTP/2 support introduced in nginx 1.9.5
VERSION_FIXED_STABLE = (1, 30, 7)  # fix backported to the stable branch
VERSION_MAINLINE_START = (1, 31, 0)  # first mainline release above the fix
VERSION_FIXED_MAINLINE = (1, 31, 9)  # fix released on the mainline branch

_SERVER_RE = re.compile(r"^nginx/(\d+)\.(\d+)(?:\.(\d+))?$")

# ---------------------------------------------------------------------------
# Banner (rendered once with pyfiglet, font "ansi_shadow", and embedded so the
# tool has zero third-party dependencies).
# ---------------------------------------------------------------------------
BANNER = """\
███╗   ██╗ ██████╗ ██╗███╗   ██╗██╗  ██╗██████╗ ██████╗  ██████╗  ██████╗
████╗  ██║██╔════╝ ██║████╗  ██║╚██╗██╔╝╚════██╗██╔══██╗██╔═══██╗██╔═══██╗
██╔██╗ ██║██║  ███╗██║██╔██╗ ██║ ╚███╔╝  █████╔╝██████╔╝██║   ██║██║   ██║
██║╚██╗██║██║   ██║██║██║╚██╗██║ ██╔██╗ ██╔═══╝ ██╔══██╗██║   ██║██║   ██║
██║ ╚████║╚██████╔╝██║██║ ╚████║██╔╝ ██╗███████╗██║  ██║╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝

████████╗
╚══██╔══╝
   ██║
   ██║
   ██║
   ╚═╝
"""

TAGLINE_1 = "CVE-2026-123007 · nginx HTTP/2 flow-control integer underflow → RCE"
TAGLINE_2 = "Non-invasive exposure validator · defensive use only"
SEPARATOR = "─" * 74

# ---------------------------------------------------------------------------
# Human-readable report lines (kept stable; verify_lab.py asserts on them).
# ---------------------------------------------------------------------------
STATUS_NOT_AFFECTED = "NOT AFFECTED (nginx < 1.9.5 has no HTTP/2 support)"
STATUS_FIXED = "FIXED VERSION (fixed in 1.30.7+ / 1.31.9+)"
STATUS_VULNERABLE = (
    "VULNERABLE VERSION (affected: 1.9.5-1.31.8; fixed: 1.30.7+/1.31.9+)"
)
STATUS_UNKNOWN = "UNKNOWN (nginx version not disclosed in the Server header)"
STATUS_NOT_NGINX = "NOT NGINX (Server header does not identify nginx)"

VERDICT_EXPOSED = "EXPOSED to CVE-2026-123007"
VERDICT_NOT_EXPOSED = "NOT EXPOSED"
VERDICT_NO_H2 = "NOT EXPOSED (HTTP/2 not negotiated on this endpoint)"
VERDICT_UNKNOWN = "UNKNOWN (nginx version not disclosed)"
VERDICT_NOT_APPLICABLE = "NOT APPLICABLE (target is not nginx)"
VERDICT_CANNOT_ASSESS = "CANNOT ASSESS"


class Colors:
    """ANSI helper that degrades to plain text when color is disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def cyan(self, text: str) -> str:
        return self._wrap("1;36", text)

    def green(self, text: str) -> str:
        return self._wrap("1;32", text)

    def red(self, text: str) -> str:
        return self._wrap("1;31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("1;33", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


@dataclass
class Result:
    """Structured outcome of a single target assessment."""

    target: str
    scheme: str = ""
    host: str = ""
    port: int = 0
    protocol: str = ""
    protocol_detail: str = ""
    tls: str = ""
    server: str = ""
    version: tuple[int, int, int] | None = None
    status: str = ""
    verdict: str = ""
    exit_code: int = EXIT_CANNOT_ASSESS
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------
def parse_target(target: str, port: int | None = None) -> tuple[str, str, int]:
    """Resolve a user-supplied target into (scheme, host, port).

    Accepted forms: ``https://host:8443/path``, ``host``, ``host:8443``.
    An explicit ``port`` argument always wins over any embedded port.
    """
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme '{parsed.scheme}' (use http or https)")
        if not parsed.hostname:
            raise ValueError(f"target '{target}' has no host")
        scheme = parsed.scheme
        host = parsed.hostname
        default = 443 if scheme == "https" else 80
        resolved = parsed.port or default
    else:
        scheme = "https"
        host, resolved = target, 443
        # Convenience: allow "host:port" without a scheme (single colon only,
        # so bare IPv6 literals such as "::1" are left untouched).
        if target.count(":") == 1:
            host_part, port_part = target.rsplit(":", 1)
            if host_part and port_part.isdigit():
                host, resolved = host_part, int(port_part)

    if port is not None:
        resolved = port
    return scheme, host, resolved


# ---------------------------------------------------------------------------
# Low-level probes
# ---------------------------------------------------------------------------
def make_tls_context(
    cafile: str | None,
    insecure: bool,
    alpn: list[str],
) -> ssl.SSLContext:
    """Build a client TLS context with the requested ALPN preferences."""
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context(cafile=cafile)
    context.set_alpn_protocols(alpn)
    return context


def describe_error(exc: BaseException, timeout: float) -> str:
    """Turn a socket/TLS exception into an actionable one-line message."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return (
            "TLS certificate verification failed: "
            f"{exc.verify_message or exc} "
            "(use --cafile lab/certs/server.crt or --insecure for the lab)"
        )
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc}"
    if isinstance(exc, socket.gaierror):
        return f"cannot resolve host: {exc}"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return f"connection timed out after {timeout:g}s"
    if isinstance(exc, ConnectionRefusedError):
        return f"connection refused ({exc})"
    return f"{type(exc).__name__}: {exc}"


def probe_alpn(
    host: str,
    port: int,
    scheme: str,
    timeout: float,
    cafile: str | None,
    insecure: bool,
) -> tuple[str | None, str | None, str | None]:
    """Perform a TLS handshake and report the negotiated ALPN protocol.

    Returns ``(selected_alpn, tls_version, error)``. For cleartext targets the
    handshake is skipped and ``selected_alpn`` is ``None``.
    """
    if scheme == "http":
        return None, None, None

    context = make_tls_context(cafile, insecure, ["h2", "http/1.1"])
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            return tls.selected_alpn_protocol(), tls.version(), None
    except (OSError, ssl.SSLError) as exc:
        return None, None, describe_error(exc, timeout)


def fetch_server_header(
    host: str,
    port: int,
    scheme: str,
    timeout: float,
    cafile: str | None,
    insecure: bool,
) -> tuple[str | None, int | None, str | None]:
    """Send one plain ``GET /`` and return ``(server, status_code, error)``.

    The request is always spoken over HTTP/1.1 (the TLS connection here offers
    only ``http/1.1`` via ALPN) so no HTTP/2 client library is required. The
    ``Server`` header is present on every nginx response, including redirects,
    which are deliberately not followed.
    """
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: nginx2root-check/{__version__}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if scheme == "https":
                context = make_tls_context(cafile, insecure, ["http/1.1"])
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.sendall(request)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
    except (OSError, ssl.SSLError) as exc:
        return None, None, describe_error(exc, timeout)

    if not data:
        return None, None, "connection closed before any response was received"

    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
    lines = head.split("\r\n")
    status_code = None
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    server = None
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            if name.strip().lower() == "server":
                server = value.strip()
                break
    return server, status_code, None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def parse_nginx_version(server_header: str | None) -> tuple[int, int, int] | None:
    """Extract a normalized ``(major, minor, patch)`` tuple from ``nginx/x.y.z``."""
    if not server_header:
        return None
    match = _SERVER_RE.match(server_header.strip())
    if not match:
        return None
    major, minor = int(match.group(1)), int(match.group(2))
    patch = int(match.group(3) or 0)
    return (major, minor, patch)


def classify(
    version: tuple[int, int, int],
    http2_negotiated: bool,
) -> tuple[str, str, int, list[str]]:
    """Map a version + ALPN result onto (status, verdict, exit_code, warnings)."""
    warnings: list[str] = []

    if version < VERSION_MIN_AFFECTED:
        return STATUS_NOT_AFFECTED, VERDICT_NOT_EXPOSED, EXIT_NOT_EXPOSED, warnings

    fixed_on_mainline = version >= VERSION_FIXED_MAINLINE
    fixed_on_stable = VERSION_FIXED_STABLE <= version < VERSION_MAINLINE_START
    if fixed_on_mainline or fixed_on_stable:
        return STATUS_FIXED, VERDICT_NOT_EXPOSED, EXIT_NOT_EXPOSED, warnings

    # Everything left sits inside the affected range 1.9.5 - 1.31.8.
    if http2_negotiated:
        return STATUS_VULNERABLE, VERDICT_EXPOSED, EXIT_EXPOSED, warnings

    warnings.append(
        "HTTP/2 was not negotiated, so the vulnerable code path is not "
        "reachable on this endpoint; the version is still vulnerable, upgrade"
    )
    return STATUS_VULNERABLE, VERDICT_NO_H2, EXIT_NOT_EXPOSED, warnings


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------
def check_target(
    target: str,
    port: int | None = None,
    cafile: str | None = None,
    insecure: bool = False,
    timeout: float = 10.0,
) -> Result:
    """Assess a single target and return a :class:`Result` (never raises)."""
    scheme, host, resolved_port = parse_target(target, port)
    display = f"{scheme}://{host}:{resolved_port}"
    result = Result(target=display, scheme=scheme, host=host, port=resolved_port)

    def fail(message: str) -> Result:
        result.error = message
        result.verdict = VERDICT_CANNOT_ASSESS
        result.exit_code = EXIT_CANNOT_ASSESS
        return result

    # Step 1: reachability, certificate validation, and ALPN negotiation.
    alpn, tls_version, error = probe_alpn(
        host, resolved_port, scheme, timeout, cafile, insecure
    )
    if error:
        return fail(error)

    if scheme == "https":
        if alpn == "h2":
            result.protocol, result.protocol_detail = "HTTP/2", "ALPN: h2"
        elif alpn == "http/1.1":
            result.protocol, result.protocol_detail = "HTTP/1.1", "ALPN: http/1.1"
        else:
            result.protocol, result.protocol_detail = "HTTP/1.1", "no ALPN"
        if insecure:
            result.tls = f"NOT verified, --insecure ({tls_version})"
        else:
            result.tls = f"verified ({tls_version})"
    else:
        result.protocol = "HTTP/1.1"
        result.protocol_detail = "cleartext, no TLS"
        result.tls = "n/a (cleartext HTTP)"

    # Step 2: read the Server header with one ordinary HTTP/1.1 request.
    server, status_code, error = fetch_server_header(
        host, resolved_port, scheme, timeout, cafile, insecure
    )
    if error:
        return fail(error)

    result.server = server or "(no Server header)"
    if status_code is not None and 300 <= status_code < 400:
        result.warnings.append(
            f"response was a redirect ({status_code}); redirects are not "
            "followed, headers were read from the first response"
        )

    # Step 3: combine version and ALPN facts into a verdict.
    if server is None or not server.lower().startswith("nginx"):
        result.status = STATUS_NOT_NGINX
        result.verdict = VERDICT_NOT_APPLICABLE
        result.exit_code = EXIT_NOT_EXPOSED
        result.warnings.append(
            "a reverse proxy may be hiding the real backend; check the origin"
        )
        return result

    result.version = parse_nginx_version(server)
    if result.version is None:
        result.status = STATUS_UNKNOWN
        result.verdict = VERDICT_UNKNOWN
        result.exit_code = EXIT_CANNOT_ASSESS
        result.warnings.append(
            "server_tokens off hides the version; determine it from the "
            "package inventory or by running 'nginx -v' on the host"
        )
        return result

    http2_negotiated = result.protocol == "HTTP/2"
    result.status, result.verdict, result.exit_code, class_warnings = classify(
        result.version, http2_negotiated
    )
    result.warnings.extend(class_warnings)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def format_report(result: Result, colors: Colors) -> str:
    """Render a :class:`Result` as the fixed-layout human-readable report."""
    lines = [f"Target:   {result.target}"]

    if result.error:
        lines.append(f"Error:    {result.error}")
        lines.append(f"Verdict:  {colors.yellow(VERDICT_CANNOT_ASSESS)}")
        return "\n".join(lines)

    lines.append(f"Protocol: {result.protocol} ({result.protocol_detail})")
    lines.append(f"TLS:      {result.tls}")
    lines.append(f"Server:   {result.server}")
    lines.append(f"Status:   {result.status}")

    for warning in result.warnings:
        lines.append(f"Warning:  {colors.yellow(warning)}")

    if result.exit_code == EXIT_EXPOSED:
        verdict = colors.red(result.verdict)
    elif result.exit_code == EXIT_NOT_EXPOSED:
        verdict = colors.green(result.verdict)
    else:
        verdict = colors.yellow(result.verdict)
    lines.append(f"Verdict:  {verdict}")
    return "\n".join(lines)


def print_banner(colors: Colors) -> None:
    """Print the ASCII banner, tagline, and separator."""
    print(colors.cyan(BANNER.rstrip("\n")))
    print(colors.yellow(f"  {TAGLINE_1}"))
    print(colors.dim(f"  {TAGLINE_2}"))
    print(colors.dim(f"  {SEPARATOR}"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class Parser(argparse.ArgumentParser):
    """Argument parser that reports usage errors with EXIT_USAGE (64)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


EXAMPLES = """\
examples:
  check_exposure.py --host localhost --port 8443 --cafile lab/certs/server.crt
  check_exposure.py https://demo.example.com --insecure
  check_exposure.py 10.0.0.5:443 --cafile /path/to/ca.pem

exit codes:
  0    not exposed (fixed, not affected, or HTTP/2 disabled)
  1    cannot assess (unreachable, TLS error, version hidden)
  2    EXPOSED to CVE-2026-123007
  64   usage error
"""


def build_parser() -> Parser:
    """Construct the CLI parser with help text and examples."""
    parser = Parser(
        prog="check_exposure.py",
        description=(
            "Non-invasive exposure validator for CVE-2026-123007 "
            "(nginx HTTP/2 flow-control integer underflow). Sends ordinary "
            "HTTP/1.1 requests only; it never triggers the vulnerability."
        ),
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        metavar="TARGET",
        help="hostname, IP, host:port, or URL (https://host[:port][/path])",
    )
    parser.add_argument(
        "--host",
        metavar="HOST",
        help="target host (alternative to the positional TARGET)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        metavar="PORT",
        help="TCP port (default: 443 for https, 80 for http; overrides URL port)",
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--cafile",
        metavar="FILE",
        help="trust FILE as the CA bundle (e.g. lab/certs/server.crt)",
    )
    tls.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="skip TLS certificate verification",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="connect and TLS timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="suppress the ASCII banner",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors (NO_COLOR is also honoured)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.host and args.target:
        parser.error("pass either TARGET or --host, not both")
    raw_target = args.host or args.target
    if not raw_target:
        parser.error("a target is required (positional TARGET or --host)")

    color_enabled = (
        sys.stdout.isatty()
        and not args.no_color
        and "NO_COLOR" not in os.environ
    )
    colors = Colors(color_enabled)

    if not args.no_banner:
        print_banner(colors)

    try:
        result = check_target(
            raw_target,
            port=args.port,
            cafile=args.cafile,
            insecure=args.insecure,
            timeout=args.timeout,
        )
    except ValueError as exc:
        parser.error(str(exc))

    print(format_report(result, colors))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
