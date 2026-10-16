# Pinned cpuminer-opt hardening

`cpuminer-opt-v26.1-security.patch` applies to JayDDee/cpuminer-opt commit
`b34565bfaca5da9ed894a326e3ba0dfe459550a4` (v26.1). The SoloMiner updater must
check this exact commit, run `git apply --check`, and apply this patch before
building. A failed or partially applied patch must abort the update. Never apply
it opportunistically to an arbitrary upstream revision.

The patch changes `util.c` and `sysinfos.c`:

- RPC HTTPS and Stratum TLS require certificate-chain verification and hostname
  matching. `--cert` supplies an optional CA bundle for both transports. Without
  it, fresh/reset libcurl handles keep their built-in default CA configuration.
  All libcurl options set in RPC/Stratum setup are checked; failures prevent the
  request or connection. Stratum schemes are matched case-insensitively and
  only the scheme selects TLS.
- Stratum receive buffering is capped at **1 MiB of accumulated wire bytes**,
  plus one terminating NUL. Embedded NUL bytes, buffer/line allocation failure,
  peer disconnection, and a frame incomplete after **60 seconds** disconnect
  the session. Partial frames are never submitted to the JSON parser. A failed
  `realloc` preserves the original allocation. Subsequent complete frames are
  retained without `strtok` collapsing empty frames.
- Send/receive byte counts passed to modern libcurl use `size_t` objects. This
  removes upstream's cast from `int *` to `size_t *` in `curl_easy_send`, which
  writes beyond the four-byte object on 64-bit systems.
- Linux CPU temperature detection enumerates hwmon devices instead of assuming
  fixed boot-dependent hwmon numbers. Only `coretemp`, `k10temp`, `k8temp`,
  `zenpower`, `cpu_thermal`, and `x86_pkg_temp` are eligible. The hottest valid
  integer reading from every `temp*_input` is used, in the range 0–150°C.
  Zero remains the upstream unavailable-sensor result. SoloMiner's doctor and
  health checks must report that a thermal cutoff cannot protect a machine
  without readable supported CPU sensors.

TLS is enforced only for HTTPS / `stratum+ssl://` / `stratum+tcps://`. Plain
`stratum+tcp://` remains plaintext; this patch does not invent TLS support for a
pool that offers only TCP. SoloMiner must require a deliberate insecure transport
opt-in for such endpoints. This focused patch is not a complete security audit
of cpuminer-opt's algorithm implementations, JSON handlers, or other transports.

## Offline regression validation

The test suite compiles the actual postimage C functions extracted from this
patch with synthetic transport, allocator, and hwmon fixtures. It never launches
a miner or connects to a pool.

```bash
SANITIZE=1 python3 -m unittest discover -s tests -v
```

To also validate patch applicability, use a clean checkout of the pinned commit
and set `CPUMINER_SOURCE` to its directory:

```bash
CPUMINER_SOURCE=/path/to/pinned-clean-checkout SANITIZE=1 \
  python3 tests/test_upstream_patch.py -v
```

CI must separately apply the patch and compile the full pinned upstream source as
an unprivileged builder. The isolated tests do not replace the full build or a
Fedora hardware acceptance test. Before adopting a newer upstream version,
review/refresh this patch and its pin together, then rerun all validation.
