# Detection guidance — CVE-2026-123007

Signals you can build on without any exploit traffic. Ordered from cheapest
to most involved.

## 1. Inventory first (no traffic analysis needed)

The bug only exists where HTTP/2 is enabled. Find those endpoints:

```bash
# TLS endpoints that negotiate h2
curl -sI --http2 https://host/ | head -1

# or straight from the config
nginx -T 2>/dev/null | grep -n 'http2\|listen.*http2'
```

Then confirm the version with the validator:

```bash
python3 tools/check_exposure.py https://host --cafile lab/certs/server.crt
```

| Exit code | Meaning | Action |
| --- | --- | --- |
| 0 | not exposed | none |
| 1 | cannot assess | check manually (`nginx -v`, package inventory) |
| 2 | **exposed** | upgrade to 1.31.9 / 1.30.7 |

Note: `server_tokens off` hides the version from the `Server` header and the
validator will return exit code 1. That is a detection gap — keep an
authoritative version inventory outside HTTP.

## 2. Host signals (nginx error log)

Memory corruption in the worker shows up as crashes and restarts:

```text
# master process reporting a dead worker
... [alert] ... worker process ... exited on signal 11
... [error] ... worker process ... exited with fatal code ...
```

Hunt for them with:

```bash
grep -E 'worker process .*(exited on signal|fatal code|core dumped)' /var/log/nginx/error.log
```

Alert on:

- any worker dying on `SIGSEGV` / `SIGBUS` (signals 11 / 7) — not normal for
  nginx under correct operation;
- a burst of worker restarts in a short window;
- steady growth of worker RSS (`ps -o rss= -C nginx`), which can indicate a
  leak or corruption in progress;
- worker counts flapping while `worker_processes auto` should be stable.

## 3. Network signals

The public analysis needs **~119 GiB of HTTP/2 frames** on one connection to
reach the corrupted state, mostly `WINDOW_UPDATE` frames (13 bytes each) plus
traffic to stay within nginx's control-frame rate limits. That volume is
unusual enough to detect on its own:

- **Volume**: a single client IP sustaining many GiB against one origin in
  minutes, especially over HTTP/2 only.
- **Frame mix**: connections dominated by tiny control frames with little
  `DATA` — visible where you log HTTP/2 (Zeek `http2` logs, Suricata with
  HTTP/2 logging, or an eBPF/socktrace hook).
- **Connection behaviour**: one long-lived connection (nginx's default
  connection timeout is one hour) with the client reading slowly while
  pushing frames — the backpressure pattern the bug requires.
- **Rate**: sustained throughput of several hundred Mbit/s from one client
  against a single virtual host.

Sample network-level rule of thumb (tune to your baselines):

```text
alert when: one src_ip → one dst_ip:dport over h2
            AND bytes > 10 GiB within 10 min
            AND frame_count / data_bytes ratio is extreme
```

## 4. Log field reference

nginx can log whether HTTP/2 was used:

```nginx
log_format main '$remote_addr [$time_local] "$request" $status '
                '$body_bytes_sent "$http_user_agent" http=$http2';
```

`http=h2` in access logs tells you which vhosts were spoken over HTTP/2 —
useful for scoping, and for confirming that a vhost you just disabled HTTP/2
on really stopped negotiating it.

## 5. After an incident

1. Capture the worker's core dump if `working_directory` and
   `worker_rlimit_core` allow it — memory-corruption bugs are much easier to
   confirm from a dump than from logs.
2. Check whether the process was exploited beyond a crash: unexpected child
   processes, outbound connections, or file changes as the nginx worker user.
3. Verify the fix with the validator (exit code 0) and confirm the version
   from the package manager, not only from HTTP headers.

## 6. Preventive controls

- Patch to 1.31.9 / 1.30.7 — the only complete fix.
- Where HTTP/2 is unnecessary: `http2 off;`.
- Terminate HTTP/2 at a proxy you control; forward HTTP/1.1 to the origin.
- Rate-limit and geo-restrict internet-facing vhosts; one hour of sustained
  throughput from a single client should never be normal for your service.
- Keep `server_tokens` in mind: hiding the version also hides it from your
  own scanners, so inventory versions out-of-band.
