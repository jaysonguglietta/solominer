# Pinned cpuminer-opt hardening

`cpuminer-opt-v26.1-security.patch` applies to JayDDee/cpuminer-opt commit
`b34565bfaca5da9ed894a326e3ba0dfe459550a4` (v26.1). The SoloMiner updater must
check this exact commit, run `git apply --check`, and apply this patch before
building. A failed or partially applied patch must abort the update. Never apply
it opportunistically to an arbitrary upstream revision.

The patch changes `util.c`, `cpu-miner.c`, `miner.h`, and `sysinfos.c`:

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
- Stratum extranonce and job fields are bounded and checked as complete hex
  before publication. A candidate job is allocated and decoded separately;
  malformed messages and allocation failures preserve the previous complete
  job. Merkle allocations are freed by allocated capacity, not the most recent
  branch count. The block-height scanner checks every index before reading.
  Rejected notifications cannot mark a new job or be mistaken for share
  responses. Work generation uses the extranonce length stored with its job,
  even when a pool sends a new extranonce size before another job.
  Current limits are a 128-byte printable ASCII job ID, 64-byte extranonce1,
  64 KiB assembled coinbase, and 1,024 Merkle branches. A pool exceeding these
  limits is rejected rather than allocating unbounded memory.
- After a complete, valid job has been turned into usable work, the miner
  writes a single `J` byte to the inherited decimal `SOLOMINER_EVENT_FD` if set.
  The pipe is supplied by SoloMiner's supervisor. Invalid jobs and work
  allocation failures never produce an event, and no pool content enters the
  event channel. The miner works normally when the variable is absent. The
  descriptor is made nonblocking, so an undrained pipe cannot
  stall mining; a full or closed pipe can drop an event without invalidating
  the job. A closed pipe does not terminate the miner through `SIGPIPE`.
- Linux CPU temperature detection enumerates hwmon devices instead of assuming
  fixed boot-dependent hwmon numbers. Only `coretemp`, `k10temp`, `k8temp`,
  `zenpower`, `cpu_thermal`, and `x86_pkg_temp` are eligible. The hottest valid
  integer reading from every `temp*_input` is used, in the range 0–150°C.
  Zero remains the upstream unavailable-sensor result. SoloMiner's doctor and
  health checks must report that a thermal cutoff cannot protect a machine
  without readable supported CPU sensors.

The SoloMiner supervisor, outside this native patch, persists the first
delivered `J` event immediately to `/run/solominer/state.json` and throttles
subsequent state writes. The timestamp shows validated work reached the miner;
it does not show an accepted share or payout. A dropped event can delay this
telemetry without invalidating the job.

TLS is enforced only for HTTPS / `stratum+ssl://` / `stratum+tcps://`. Plain
`stratum+tcp://` remains plaintext; this patch does not invent TLS support for a
pool that offers only TCP. SoloMiner must require a deliberate insecure transport
opt-in for such endpoints. This focused patch is not a complete security audit
of cpuminer-opt's algorithm implementations, JSON handlers, or other transports.

## Offline regression validation

The test suite compiles the actual postimage C functions extracted from this
patch with synthetic transport, allocator, Stratum JSON, and hwmon fixtures. It
tests short coinbases, malformed fields, branch resizing, allocation failure,
and valid-job event emission. It never launches a miner or connects to a pool.
The Python runtime suite also checks that the first delivered event reaches
the state file while a harmless fixture process is still running.

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
