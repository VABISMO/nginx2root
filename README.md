# nginx2root

[![CI](https://github.com/VABISMO/nginx2root/actions/workflows/ci.yml/badge.svg)](https://github.com/VABISMO/nginx2root/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CVE-2026-123007](https://img.shields.io/badge/CVE--2026--123007-CVSS%209.2-critical)](https://nvd.nist.gov/vuln/detail/CVE-2026-123007)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

> **Defensive research repository.** It ships a reproducible lab, a
> non-invasive exposure validator, and detection guidance for
> **CVE-2026-123007** (publicly called *nginx2root*). It deliberately
> contains **no exploit code**: nothing here crafts malicious HTTP/2 frames
> or executes commands on a target.

## What happened

On **18 November 2026**, F5 and Rapid7 disclosed **CVE-2026-123007**, an
integer underflow (CWE-191) in the HTTP/2 flow-control accounting of the
nginx `ngx_http_v2_module`. A remote, **unauthenticated** client can drive
the connection window counter past the protocol maximum, after which nginx
interprets an invalid length while copying response data. The resulting
memory corruption can crash the worker process, leak memory, or — under
specific build conditions — execute code with the worker's privileges.

| Field | Value |
| --- | --- |
| CVE | CVE-2026-123007 |
| Alias | nginx2root |
| CWE | CWE-191 — Integer Underflow |
| CVSS 3.1 | 8.1 (F5) |
| CVSSv4 | 9.2 (Rapid7) |
| Attack vector | Network, unauthenticated, requires HTTP/2 enabled |
| Impact | Crash, memory disclosure, potential RCE as the nginx worker |
| Disclosed | 18 November 2026 |
| Discovered by | Stephen Fewer (Rapid7) |

### Affected versions

| Product | Vulnerable | Fixed in |
| --- | --- | --- |
| NGINX Open Source (mainline) | 1.31.0 – 1.31.8 | **1.31.9** |
| NGINX Open Source (stable) | 1.9.5 – 1.30.6 | **1.30.7** |
| NGINX Plus | 37.1.0 – 37.2.0.1 | 37.3.0.1 |
| NGINX Plus | 37.0.0 – 37.0.7.1 | 37.0.8.1 |
| NGINX Plus | R34 – R36 | *no fix — upgrade* |

The condition is simple: the configuration must enable HTTP/2
(`http2 on;` or `listen ... http2`). If HTTP/2 is disabled, the vulnerable
code path is unreachable.

The same release also fixed nine other issues, including four memory-safety
bugs from the same *nginx2root* disclosure set — see
[docs/CVE-2026-123007.md](docs/CVE-2026-123007.md) for the full table.

## Repository layout

```text
.
├── docker-compose.yml        # vulnerable (1.31.8) + patched (1.31.9) targets
├── lab/nginx/                # Dockerfile, nginx.conf (http2 on + TLS), page
├── tools/
│   ├── check_exposure.py     # the validator (CLI, banner, --help)
│   ├── verify_lab.py         # CI gate: asserts A/B behaviour end to end
│   ├── selftest.py           # pure-logic test matrix (no network)
│   └── gen_certs.py          # self-signed lab CA (mounted, never committed)
├── docs/                     # CVE write-up and detection guidance
└── .github/workflows/ci.yml  # lint + real lab verification on every push
```

## Quick start

Requirements: Docker with Compose, Python **3.10+**, OpenSSL.

```bash
make up        # generate the lab certificate, build and start both targets
make verify    # assert: 1.31.8 => EXPOSED, 1.31.9 => NOT EXPOSED
make check     # one-off check against the vulnerable container
make down      # stop and remove the lab
```

`make verify` is what CI runs. It starts both containers, waits for their
health checks, runs the real validator against each, and fails if a single
assertion does not hold.

## The validator

`tools/check_exposure.py` answers one question: *is this endpoint exposed to
CVE-2026-123007?* It combines two independently observable facts:

1. the nginx version in the `Server` response header, checked against the
   affected ranges; and
2. whether the TLS handshake actually negotiates HTTP/2 via ALPN (`h2`),
   since the bug lives only in the HTTP/2 code path.

It sends ordinary `GET /` requests over HTTP/1.1. It never crafts protocol
frames and never triggers the vulnerability.

```console
$ python3 tools/check_exposure.py --host localhost --port 8443 --cafile lab/certs/server.crt

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
  CVE-2026-123007 · nginx HTTP/2 flow-control integer underflow → RCE
  Non-invasive exposure validator · defensive use only
  ──────────────────────────────────────────────────────────────────────────
Target:   https://localhost:8443
Protocol: HTTP/2 (ALPN: h2)
TLS:      verified (TLSv1.3)
Server:   nginx/1.31.8
Status:   VULNERABLE VERSION (affected: 1.9.5-1.31.8; fixed: 1.30.7+/1.31.9+)
Verdict:  EXPOSED to CVE-2026-123007
```

### Usage

```text
usage: check_exposure.py [-h] [--host HOST] [-p PORT] [--cafile FILE | -k]
                         [--timeout SECONDS] [--no-banner] [--no-color]
                         [--version]
                         [TARGET]

positional arguments:
  TARGET             hostname, IP, host:port, or URL (https://host[:port][/path])

options:
  -h, --help         show this help message and exit
  --host HOST        target host (alternative to the positional TARGET)
  -p, --port PORT    TCP port (default: 443 for https, 80 for http; overrides URL port)
  --cafile FILE      trust FILE as the CA bundle (e.g. lab/certs/server.crt)
  -k, --insecure     skip TLS certificate verification
  --timeout SECONDS  connect and TLS timeout in seconds (default: 10)
  --no-banner        suppress the ASCII banner
  --no-color         disable ANSI colors (NO_COLOR is also honoured)
  --version          show program's version number and exit
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Assessed, **not exposed** (fixed, not affected, or HTTP/2 disabled) |
| `1` | **Cannot assess** (unreachable, TLS error, version not disclosed) |
| `2` | Assessed, **EXPOSED** to CVE-2026-123007 |
| `64` | Usage error |

The distinct exit codes make the tool safe to use in scripts and CI:

```bash
python3 tools/check_exposure.py https://example.com --cafile lab/certs/server.crt
case $? in
  0) echo "patched" ;;
  2) echo "EXPOSED — upgrade nginx now" ;;
  *) echo "could not determine" ;;
esac
```

## The lab

Two containers differ **only** by image tag, so any difference in the verdict
is attributable to the fix and nothing else:

| Service | Image | Port | Expected verdict |
| ------- | ----- | ---- | ---------------- |
| `nginx-vuln` | `nginx:1.31.8` (last vulnerable mainline) | `127.0.0.1:8443` | `EXPOSED` (exit 2) |
| `nginx-patched` | `nginx:1.31.9` (first fixed mainline) | `127.0.0.1:9443` | `NOT EXPOSED` (exit 0) |

Both serve TLS with `http2 on;` and share one configuration file
(`lab/nginx/nginx.conf`) and one self-signed certificate
(`lab/certs/`, generated locally and gitignored). Ports bind to loopback
only.

```bash
make up        # generate certs, build and start both containers
make verify    # full A/B assertion (the CI gate)
make check     # one-off check against the vulnerable container
make logs      # tail both containers
make down      # stop and remove everything
```

`make verify` prints the complete report of each target and then asserts,
line by line, that the protocol, `Server` header, verdict, and exit code all
match the expected values:

```text
== Vulnerable target (expect EXPOSED, nginx/1.31.8): https://localhost:8443 ==
...
  ok: negotiates HTTP/2
  ok: reports nginx/1.31.8
  ok: verdict
  ok: exit code
...
LAB VERIFICATION: PASS
```

## Continuous integration

Every push and pull request runs [.github/workflows/ci.yml](.github/workflows/ci.yml):

1. **lint** — `ruff check`, byte-compilation, the pure-logic test matrix
   (`tools/selftest.py`: target parsing, version parsing, the full affected-
   range classification, exit-code domain), and `--help` / `--version` smoke
   tests.
2. **lab** — generates certificates, builds both images, starts them, and runs
   `tools/verify_lab.py`. Container logs are dumped on failure; the lab is torn
   down afterwards.

A green badge therefore means the vulnerable target really is reported as
exposed and the patched target really is not.

## Detection

See [docs/DETECTION.md](docs/DETECTION.md) for concrete signals:

- **Host**: nginx master logging `worker process ... exited on signal`,
  repeated worker restarts, abnormal worker RSS growth.
- **Network**: a single client sustaining many GiB of HTTP/2 traffic dominated
  by 13-byte `WINDOW_UPDATE` frames (the public analysis needs ~119 GiB of
  frames to reach the corrupted state).
- **Prevention**: terminate HTTP/2 at a proxy you control, disable `http2`
  where it is not needed, and keep `server_tokens` in mind when fingerprinting.

## Remediation

Upgrade to a fixed release — no configuration workaround fully removes the
bug while HTTP/2 remains enabled:

| Product | Vulnerable | Fixed |
| ------- | ---------- | ----- |
| NGINX Open Source (mainline) | 1.31.0 – 1.31.8 | **1.31.9** |
| NGINX Open Source (stable) | 1.9.5 – 1.30.6 | **1.30.7** |
| NGINX Plus | 37.1.0 – 37.2.0.1 | **37.3.0.1** |
| NGINX Plus | 37.0.0 – 37.0.7.1 | **37.0.8.1** |
| NGINX Plus | R34 – R36 | *no fix — move to a supported release* |

If you cannot patch immediately, disabling HTTP/2 (`http2 off;`) removes the
reachable code path; fronting nginx with a proxy that terminates HTTP/2 also
prevents crafted frames from reaching the origin.

## November 2026 batch

CVE-2026-123007 was one of ten issues fixed in 1.31.9 / 1.30.7. The four
other memory-safety bugs disclosed together are commonly grouped under the
same *nginx2root* name:

| CVE | Component | Severity (nginx) | Affected |
| --- | --------- | ---------------- | -------- |
| CVE-2026-123007 | `ngx_http_v2_module` flow control | major | 1.9.5 – 1.31.8 |
| CVE-2026-123633 | `ngx_http_v2_module` use-after-free | medium | 1.19.7 – 1.31.8 |
| CVE-2026-123634 | resolver use-after-free | medium | 0.6.18 – 1.31.8 |
| CVE-2026-121810 | HTTP/3 use-after-free | medium | 1.25.0 – 1.31.8 |
| CVE-2026-113425 | mail proxy use-after-free | major | 0.5.33 – 1.31.8 |

Full technical notes: [docs/CVE-2026-123007.md](docs/CVE-2026-123007.md).

## Scope and responsible use

- The validator sends **ordinary HTTP/1.1 requests** and reads response
  headers. It does not send malformed frames, does not degrade service, and
  is safe to run against systems you are authorised to test.
- This repository intentionally ships **no exploit, payload, or weaponised
  PoC**. See [CONTRIBUTING.md](CONTRIBUTING.md) — pull requests containing
  exploit code will be rejected.
- Run the lab locally. It binds to `127.0.0.1` only; do not expose the
  vulnerable container to a network.

## Contributing

Bug reports, detection ideas, and documentation improvements are welcome.
Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) first. Security issues in *this
repository* are handled through [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).

## References

- nginx security advisories — https://nginx.org/en/security_advisories.html
- F5 advisory K000163926 — https://my.f5.com/manage/s/article/K000163926
- Rapid7 technical analysis — https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/
- CVE record — https://www.cve.org/CVERecord?id=CVE-2026-123007
- Cisco advisory (November 2026) — https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nginx-nov-2026-e8jska2s
- CERT-EU advisory 2026-022 — https://cert.europa.eu/publications/security-advisories/2026-022/
