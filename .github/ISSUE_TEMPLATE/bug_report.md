---
name: Bug report
about: Something in the lab or the validator behaves unexpectedly
title: ""
labels: bug
assignees: ""
---

## Describe the bug

A clear and concise description of what is wrong.

## To reproduce

Steps to reproduce the behaviour:

1. `make up`
2. `python3 tools/check_exposure.py ...`
3. See error

## Expected behaviour

What you expected to happen instead.

## Environment

- OS:
- Python version (`python3 --version`):
- Docker version (`docker version`):
- Compose version (`docker compose version`):
- Commit hash (`git rev-parse --short HEAD`):

## Output

Paste the full output, including the report block. If the target is reachable,
also paste the response headers (`curl -sI --http2 https://host/`).

> Do not include the contents of systems you do not own.

## Additional context

Anything else that helps: logs, screenshots, what you were trying to achieve.
