# myatg HTTP serve mode — design

**Date:** 2026-06-29
**Branch:** `feat/serve-mode` (extends PR #2)
**Status:** Approved design (pending implementation plan)

## Summary

Add an HTTP front end to myatg's persistent-validator capability. A host POSTs
**file bytes** to a local HTTP endpoint and gets back the same JSON verdict myatg
already emits. The server is the in-box, kernel-hardened `System.Net.HttpListener`
(http.sys), bound to loopback on a high port, and is deployable as a **least-privilege
Windows service** running under a virtual service account (`NT SERVICE\myatg`).

This is purely **additive**: the one-shot CLI path and the existing stdin `--serve`
mode (PR #2) are unchanged. All modes call the same `ValidateFile(...)` core, so
verdicts stay byte-identical across one-shot / stdin / HTTP.

## Goals

- Validate uploaded bytes over HTTP with one JSON verdict per request.
- Use the battle-hardened built-in HTTP stack (http.sys), not a hand-rolled parser.
- Run as a persistent, **warm** worker (CLR JIT + trust/CRL caches stay hot).
- Run **least-privilege**: no LocalSystem, no per-run elevation, loopback-only by default.
- Reuse the existing verdict core verbatim — no change to validation logic.

## Non-goals

- **No TLS in-process.** Loopback-only by default; if a remote needs it, front with a
  reverse proxy that terminates TLS. (Keeps the cert surface out of the validator.)
- **No batch/multi-file per request.** One file per request. Batching is a future option.
- **No auth scheme beyond a static shared token.** No user accounts, no OAuth.
- **No change to verdict logic or JSON shape.**

## Run modes (all additive)

| Mode | Flag | Purpose | Privilege |
|------|------|---------|-----------|
| One-shot | *(positional path)* | Unchanged | none |
| Stdin serve | `--serve` | Unchanged (PR #2): one path per stdin line → one JSON line | none |
| HTTP console | `--serve-http` | Foreground HTTP server for dev / host-spawned use | binding a fixed loopback port as non-admin needs a scoped urlacl (or run elevated, or just use the service) |
| HTTP service | `--service` + `--install-service` / `--uninstall-service` | Persistent Windows service, auto-start, auto-restart | least-priv via `NT SERVICE\myatg`; installer sets a scoped urlacl once |

The SCM launches the service process with `--service`; operators never run that flag by hand.

## HTTP API contract

### Endpoints

- `POST /validate` — body is the **raw file bytes**. Returns the JSON verdict.
- `GET /healthz` — liveness probe. Returns `{"ok":true}`; no auth required.

Any other method/route → `405` / `404` with a small JSON error body.

### Request

- **Body:** raw file bytes (`Content-Type` ignored; treated as opaque bytes).
- **Per-request option overrides** via query string:
  - `?rev=online|offline|none` — revocation mode (default = server's startup `--rev`).
  - `?scripts=<mode>` — script analysis mode (default = server's startup `--scripts`).
  These map directly to the existing `ValidateFile(path, rev, scriptMode)` parameters,
  which are passed by value per call — safe under concurrency (no shared mutable state).
- **Auth:** `Authorization: Bearer <token>` header, required iff the server was started
  with `--token` (see Security).

### Server-global options (startup only, not per-request)

These are inherently process-wide or touch shared/static state, so they are configured
at startup and **not** overridable per request:

- `--gv <csv>` — graveyard CSV, loaded **once** at startup (read-only after load → thread-safe).
- `--max-size <mb>` — max accepted file size. Backed by a static field; keeping it
  server-global avoids a per-request race on that static. Enforced on both `Content-Length`
  and actual bytes read; oversize → `413`.
- `--refresh` / `--warm-cache <dir>` — trust/cache warmups, run once at startup if given.

> Design note on "expose all CLI options": the per-request knobs that are safe and
> meaningful to vary per file (`rev`, `scripts`) are exposed as query params. Options that
> are load-once or back static state (`gv`, `max-size`, `refresh`, `warm-cache`) are
> server-global by design — varying them per request is either meaningless (graveyard) or
> a concurrency hazard (max-size static). This is a deliberate boundary, not an omission.

### Response

- `200 OK`, `Content-Type: application/json`, body = the existing verdict object
  (same schema as one-shot / stdin output; see `ValidateFile` / `ErrJson` in `myatg.cs`).
- Validation *failures of the file* (unsigned, revoked, etc.) are still `200` with the
  verdict describing them — they are successful validations, not HTTP errors.
- HTTP-level errors use small JSON bodies:
  - `400` malformed request (e.g. empty body)
  - `401` missing/invalid token
  - `404` unknown route, `405` bad method
  - `413` body exceeds `--max-size`
  - `500` unexpected server error (should be rare; per-request handler catches and maps
    exceptions to `ErrJson` at `200` the same way stdin serve does, reserving `500` for
    framework-level failures)

### Request handling flow

1. http.sys accepts and parses the HTTP request (malformed/oversized/slowloris handled in kernel).
2. Handler checks method/route, then token (constant-time compare).
3. Body streamed to a unique temp file in a service-account-owned temp dir, capped at
   `--max-size`; abort with `413` if exceeded.
4. `ValidateFile(tempPath, rev, scriptMode)` → JSON string (its own try/catch → `ErrJson`,
   so a bad file never crashes the worker — same guarantee as stdin serve).
5. Write `200` + JSON. Delete the temp file in a `finally`.

## Concurrency

- `HttpListener` accept loop dispatches each request to the thread pool; multiple
  validations run concurrently.
- Thread-safety: `ValidateFile` takes `rev`/`scriptMode` by value; the graveyard is
  read-only post-load; `maxBytes` stays server-global (not mutated per request). No shared
  mutable state on the hot path.
- A bounded concurrency gate (semaphore, default small e.g. 4) caps simultaneous validations
  to avoid CPU/memory exhaustion under load; excess requests queue briefly. Limit configurable
  via `--max-concurrency`.
- `OutOfMemoryException` is **not** swallowed per-request (process state is suspect after OOM);
  it propagates so the service's restart-on-failure brings up a clean worker — matching the
  existing stdin-serve choice to rethrow OOM.

## Security model

- **Loopback by default.** Default bind `127.0.0.1`, default port `8137` (high, unprivileged).
  `--bind <addr>` / `--port <n>` to change.
- **Non-loopback requires a token.** If `--bind` is set to anything other than a loopback
  address and no `--token` is provided, the server **refuses to start** (fail closed),
  unless `--allow-insecure` is explicitly passed. Loopback with no token is allowed
  (local trust boundary).
- **Token check** is a constant-time comparison to avoid timing oracles.
- **No privilege for validation.** Service runs as `NT SERVICE\myatg`; uploaded bytes go to
  a temp dir that account owns, so no broad filesystem read is needed. Trust stores read are
  world-readable; CRL/OCSP is outbound network.
- **Scoped urlacl.** The reservation grants only the service SID the right to bind only the
  configured loopback prefix.

## Windows service

### Account

Runs under the **virtual service account `NT SERVICE\myatg`**:
- Auto-provisioned at service creation; no password, no account management.
- Isolated per-service SID; minimal default rights.

(`NT AUTHORITY\LocalService` is an acceptable fallback but less isolated; virtual account is default.)

### Install (`--install-service`, run elevated once)

Does three things via the Service Control Manager + http.sys config:
1. Create the service: `binPath = "<exe> --service --port <n> [--bind ...] [--gv ...] ..."`,
   `obj = "NT SERVICE\myatg"`, `start = auto`.
2. Add the scoped urlacl: `netsh http add urlacl url=http://<bind>:<port>/ user="NT SERVICE\myatg"`
   (or the equivalent `HttpSetServiceConfiguration` P/Invoke).
3. Set failure actions: restart on crash (e.g. restart/restart/restart with a short delay).

`--uninstall-service` reverses all three (stop + delete service, remove urlacl).

### Service entry (`--service`)

- `ServiceBase.Run` hands control to the SCM.
- `OnStart`: start `HttpListener` on a background thread; return promptly.
- `OnStop`: signal shutdown, `listener.Stop()/Close()`, join the worker, exit cleanly.

## Console mode (`--serve-http`)

Foreground equivalent for dev / host-spawned use. Same HTTP behavior. On `HttpListenerException`
(Access Denied / reservation missing), print a **clear, actionable** message with the exact
`netsh http add urlacl ...` command and a pointer to `--install-service`, instead of a raw
stack trace.

## Build & CI changes

- `build.cmd`: add `/r:System.ServiceProcess.dll` (for `ServiceBase`). `HttpListener` lives in
  `System.dll` (already referenced). Confirm the legacy `v4.0.30319` csc accepts the new code
  (the other branch already hit `?.` rejection — avoid newer syntax).
- `.github/workflows/ci.yml`: add an HTTP smoke test (Windows runner):
  - start `--serve-http` on a test port in the background,
  - `GET /healthz` → `{"ok":true}`,
  - `POST /validate` with a sample file's bytes → assert a JSON verdict line,
  - `POST` without token to a token-required instance → `401`,
  - optional: oversize body → `413`.

## Testing

Behavioral cases the implementation must cover (TDD where practical):

- `POST /validate` with signed/unsigned/revoked sample bytes → verdict matches the one-shot
  CLI output for the same file (byte-identical core).
- Empty body → `400`.
- Oversize body (> `--max-size`) → `413`, no temp file left behind.
- Bad method / unknown route → `405` / `404`.
- Token: required-and-correct → `200`; required-and-missing/wrong → `401`; not-required → `200`.
- Non-loopback `--bind` without `--token` and without `--allow-insecure` → refuses to start.
- Concurrency: N simultaneous requests all return correct, independent verdicts.
- Temp files are cleaned up on success, on validation error, and on oversize abort.
- Service: install → running → `healthz` ok → uninstall removes service + urlacl.

## Open implementation details (to resolve in the plan)

- Exact default port (`8137` proposed; pick a documented, unlikely-to-collide value).
- Whether to expose `--max-concurrency` in v1 or hardcode a sane default.
- urlacl via shelling `netsh` vs `HttpSetServiceConfiguration` P/Invoke (both fine; netsh is
  simpler and already a documented dependency surface).
