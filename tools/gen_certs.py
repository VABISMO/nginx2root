#!/usr/bin/env python3
"""Generate the self-signed TLS certificate used by the lab.

The certificate is ephemeral: it is written to ``lab/certs/`` (gitignored) and
mounted read-only into both lab containers, then trusted explicitly by the
exposure checker via ``--cafile`` — no ``curl -k`` / ``--insecure`` anywhere
in the verification path.

Usage:
  python tools/gen_certs.py            # create if missing, otherwise reuse
  FORCE=1 python tools/gen_certs.py    # regenerate
  CERT_DAYS=90 python tools/gen_certs.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CERT_DIR = REPO_ROOT / "lab" / "certs"
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

DAYS = int(os.environ.get("CERT_DAYS", "365"))
FORCE = os.environ.get("FORCE", "0") == "1"

# The SAN list must cover every name used to reach the lab locally.
SUBJECT_ALT_NAMES = [
    "DNS:localhost",
    "DNS:nginx2root.local",
    "IP:127.0.0.1",
    "IP:::1",
]


def main() -> int:
    """Create or reuse the lab certificate; returns a process exit code."""
    if shutil.which("openssl") is None:
        print("error: openssl is required but was not found in PATH", file=sys.stderr)
        return 1

    CERT_DIR.mkdir(parents=True, exist_ok=True)

    if CERT_FILE.is_file() and KEY_FILE.is_file() and not FORCE:
        print(f"certs: reusing existing {CERT_FILE} (FORCE=1 to regenerate)")
        return 0

    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        str(DAYS),
        "-nodes",
        "-keyout",
        str(KEY_FILE),
        "-out",
        str(CERT_FILE),
        "-subj",
        "/CN=localhost/O=nginx2root lab",
        "-addext",
        f"subjectAltName={','.join(SUBJECT_ALT_NAMES)}",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
        "-addext",
        "extendedKeyUsage=serverAuth",
    ]
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        print("error: openssl failed to generate the certificate", file=sys.stderr)
        return result.returncode

    KEY_FILE.chmod(0o600)
    print(
        f"certs: wrote {CERT_FILE} (valid {DAYS}d, "
        f"SAN: {', '.join(SUBJECT_ALT_NAMES)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
