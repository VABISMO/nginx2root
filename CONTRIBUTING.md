# Contributing to nginx2root

Thanks for your interest in improving this repository. It exists to help
defenders understand, detect, and validate **CVE-2026-123007** — contributions
should keep it that way.

## Ground rules

- **No exploit code.** Pull requests that add exploits, weaponised
  proof-of-concept payloads, frame-crafting attack code, or instructions whose
  purpose is to compromise a system will be rejected without exception. The
  validator in `tools/check_exposure.py` must stay non-invasive: ordinary
  HTTP/1.1 requests only.
- **Defensive scope.** Good contributions are lab improvements, validator
  correctness, detection engineering, documentation, CI, and packaging.
- **Be kind.** Participation is governed by the
  [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Requirements: Docker with Compose, Python 3.10+, OpenSSL.

```bash
git clone https://github.com/VABISMO/nginx2root.git
cd nginx2root
make up          # generates lab/certs/, builds and starts both targets
make verify      # must print LAB VERIFICATION: PASS
```

## Making changes

1. Fork and create a feature branch from `main`.
2. Keep the style of the surrounding code: type hints on public functions,
   docstrings that explain *why*, comments only where the code is not
   self-explanatory.
3. Run the local gates before pushing:

   ```bash
   make lint      # ruff check + byte-compile + CLI smoke tests
   make verify    # full A/B lab verification
   ```

4. If you change expected behaviour (verdicts, exit codes, report layout),
   update `README.md` and `tools/verify_lab.py` in the same commit so the
   documentation and the CI gate never disagree.

## Pull requests

- One logical change per PR; describe *what* changed and *why*.
- Reference the issue you are fixing, when there is one.
- Include example output (`--help`, a validator run, `make verify`) when the
  change is user-visible.
- CI must be green: lint plus the real lab verification run on every push.

## Reporting bugs

Open a bug report with:

- your OS, Python version, and Docker version;
- the exact command you ran;
- the full output, including the report block;
- for validator misbehaviour: the target's `Server` header and whether ALPN
  negotiated `h2` (the tool prints both).

Do **not** paste the contents of systems you do not own. This project is for
defensive testing of infrastructure you are authorised to assess.

## Security issues in this repository

If you find a vulnerability in the tooling itself (for example a way to make
the validator send something unexpected), follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

## Questions

Use GitHub Discussions or an issue with the `question` label. Questions about
the CVE itself are best answered by the vendor advisories listed in the
README references.
