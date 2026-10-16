# SoloMiner

A Fedora-first background service for conservative, hobby Bitcoin CPU solo mining, with reviewed source pins, isolated builds, resource limits, diagnostics, and rollback.

CPU mining has extremely low odds of finding a Bitcoin block. This setup is for experimentation on hardware you control; it is not a profitability claim. Only a public Bitcoin receiving address is needed. Never enter a private key or seed phrase.

## What this version provides

- A dedicated, unprivileged `solominer` runtime account and a separate build account.
- A fixed `cpuminer-opt` v26.1 source commit plus a mandatory local patch for certificate verification and bounded Stratum input.
- Builds without root in a systemd sandbox. Installed code and release metadata are owned by root.
- CPU, memory, task, and temperature limits; validated configuration; readable logs; disabled pool redirects by default.
- Local status, configuration/permission diagnostics, health checks, serialized updates, staging, and rollback.
- Atomic file replacement, startup verification, and recovery of the previous release after failed activation.
- A systemd health timer that reports meaningful failures locally through journald.

There is no web dashboard, listening management API, external notification service, unconfigured pool change, or automatic Fedora upgrade. Pool failover occurs only when explicitly configured.

## Requirements

Fedora Linux with systemd, `sudo` access, internet access for builds, outbound pool connectivity, a checksum-valid mainnet Bitcoin receiving address, and enough disk/memory to compile `cpuminer-opt`.

The installer can install Fedora build prerequisites with `--install-deps`. It does not upgrade the operating system by default. Continue normal Fedora security maintenance separately.

## Upgrade an existing installation

Run from your existing SoloMiner Git checkout:

```bash
cd /path/to/solominer
git switch main
git pull --ff-only
sudo bash scripts/install-solominer.sh --migrate
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer status
```

Save local edits before pulling; `--ff-only` stops on divergent history. Review incoming changes before running an installer with `sudo`.

`--migrate` requires and preserves `/etc/sysconfig/btc-solo-cpu`, validates it, installs the management code and systemd units, builds the approved patched miner, and restarts the service. It replaces the old miner-owned executable layout with root-owned releases. When safe to import, the old binary is retained for recovery. An imported legacy binary has unknown provenance and does not gain the new upstream security fixes.

If dependencies are missing:

```bash
sudo bash scripts/install-solominer.sh --migrate --install-deps
```

If configuration validation fails, correct the named field with `sudoedit /etc/sysconfig/btc-solo-cpu` and rerun migration. Valid `POOL`, `WALLET`, `WORKER`, and `THREADS` assignments are preserved; new settings use the defaults below. Configuration is parsed as data and never sourced as shell code.

## First installation

```bash
git clone https://github.com/jaysonguglietta/solominer.git
cd solominer
sudo bash scripts/install-solominer.sh --install-deps
```

On first run the installer creates `/etc/sysconfig/btc-solo-cpu` from the example and stops because its wallet is a placeholder. Enter your receiving address and worker name:

```bash
sudoedit /etc/sysconfig/btc-solo-cpu
sudo bash scripts/install-solominer.sh
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer status
```

The final install enables the miner and health timer. Read the pool transport note before leaving it running.

## Configuration

Edit the root-owned `/etc/sysconfig/btc-solo-cpu`. Use one `NAME=value` assignment per line. Blank lines and whole-line comments are allowed; values with spaces can be quoted. Multiline values, duplicate/unknown keys, shell expansion, arbitrary miner flags, and embedded pool credentials are unsupported.

| Setting | Default | Meaning |
| --- | --- | --- |
| `POOL` | `stratum+tcp://pool.nerdminer.io:3333` | Explicit host and port; supports `stratum+tcp`, `stratum+ssl`, and `stratum+tcps`. |
| `WALLET` | Placeholder; must be changed | Checksum-valid mainnet Base58Check, Bech32, or Bech32m receive address. |
| `WORKER` | `fedora1` | 1–64 letters, digits, underscores, or hyphens; use a different name per machine. |
| `THREADS` | `2` | Integer from 1 through the host's logical CPU count. |
| `MAX_TEMP` | `75` | Temperature pause threshold in Celsius; 45–100. Requires a working CPU sensor. |
| `CPU_QUOTA` | `100%` | Aggregate CPU budget: `100%` means one logical CPU's time, `200%` means two. |
| `MEMORY_MAX` | `256M` | systemd memory ceiling; 64M–64G using `M` or `G`. |
| `TASKS_MAX` | `64` | systemd task ceiling; 16–4096. |
| `NO_REDIRECT` | `true` | Reject pool-requested destination changes; opt out only for a pool that requires them. |
| `RETRY_PAUSE` | `30` | Seconds between reconnect attempts; 5–600. |
| `FALLBACK_POOLS` | Empty | Optional comma-separated list of up to three unique pool URLs, different from `POOL`. |
| `HEALTH_TIMEOUT` | `900` | Connection-health grace period in seconds; 120–86400. |
| `ALLOW_INSECURE_POOL` | `true` | Permit plaintext for existing pool compatibility; set `false` with verified TLS. |

`Nice=15` lowers scheduling priority; `CPU_QUOTA` sets the CPU budget. Start conservatively and measure sustained temperature/memory before raising limits. On a one-thread machine, set `THREADS=1`.

After changing configuration, validate and apply resource limits:

```bash
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer apply-config
```

Mining arguments always use SHA256d, `--no-color`, fixed conventional pool password `x`, and no management API. `apply-config` validates and applies both miner arguments and CPU/memory/task ceilings without rebuilding.

### Pool transport and trust

The NerdMiner default remains plaintext for compatibility. An observer on that network path can read or modify mining traffic. This release warns about plaintext and supports `ALLOW_INSECURE_POOL=false`; it cannot make a plaintext-only provider secure.

If your pool documents a TLS endpoint, configure that exact host/port and set `ALLOW_INSECURE_POOL=false`. The patched miner verifies the certificate chain against the operating system trust store and the expected hostname. Do not guess TLS ports, disable verification, or silently switch pool operators. TLS authenticates the chosen endpoint; it does not prove that the pool operator is honest.

`NO_REDIRECT=true` reduces unexpected destination changes. Assess the provider's destination policy before disabling it. For optional failover, set `FALLBACK_POOLS` to a comma-separated list of provider-verified endpoints. After three upstream retries, any unrequested miner exit advances through the primary/fallback list with at least a 30-second pause. An explicit service stop never rotates pools. Every endpoint uses the same wallet/worker and transport policy; with `ALLOW_INSECURE_POOL=false`, plaintext fallback URLs are rejected. Without configured fallbacks, the miner keeps retrying the primary pool. The software never changes your payout address.

## Local commands

```bash
sudo /usr/local/bin/solominer status
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer health
sudo /usr/local/bin/solominer apply-config
sudo /usr/local/bin/solominer update --check
sudo /usr/local/bin/solominer update
sudo /usr/local/bin/solominer rollback
```

Use `solominer --help` and `solominer COMMAND --help` for the installed interface.

| Command | Behavior |
| --- | --- |
| `status` | Service state, release provenance, pool/worker, resource use, temperatures, and recent events. |
| `doctor` | Configuration, permissions, release integrity, effective systemd settings, and sensor diagnostics. |
| `health` | Local service/journal evaluation; active process and pool connectivity are distinct signals. |
| `update --check` | Approved pin and installed release; no build or activation and no moving upstream branch. |
| `update` | Install current management code/units, build the approved patched source, record provenance, and activate with startup verification. |
| `update --no-restart` | Stage only; do not change active release or restart the miner. |
| `update --activate-staged` | Activate the staged release after checking it matches the current approved source, patch, and management bundle. |
| `apply-config` | Validate settings and apply resource limits/restart without rebuilding the miner. |
| `rollback` | Restore the previous retained release and check startup. Legacy rollback may reintroduce old weaknesses. |

The runtime `run` command is for systemd. Use service commands instead of launching additional miners manually. Concurrent maintenance is rejected.

## Future updates directly from Git

The repository carries management code, approved upstream revision, and mandatory patch. Pulling Git alone does not alter the running service.

```bash
cd /path/to/solominer
git switch main
git pull --ff-only
sudo bash scripts/install-solominer.sh
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer status
```

`sudo bash scripts/update-solominer.sh` uses the same update flow. Use `--no-restart` to stage, `--activate-staged` to activate that staged build, and `--check` to inspect. `--install-deps` explicitly installs prerequisites; `--update-packages` explicitly requests a Fedora package upgrade. Neither happens by default. Previous shell environment overrides such as `SOURCE_REPO`, `UPDATE_PACKAGES`, and `RESTART_SERVICE` are unsupported; use explicit command options.

New upstream revisions must be reviewed, pinned, patched, and tested in this repository before adoption. An upstream release does not automatically become an approved update.

## Monitoring and service management

```bash
sudo systemctl status btc-solo-cpu.service
sudo journalctl -u btc-solo-cpu.service -n 100 --no-pager
sudo journalctl -u btc-solo-cpu.service -f
sudo systemctl list-timers solominer-health.timer
sudo journalctl -u solominer-health.service --since today --no-pager
```

The timer checks every five minutes after a two-minute startup delay, with a small randomized delay. Health alerts remain local in journald and emit only on new conditions or recovery. It detects prolonged connection errors, crashes, overheating, sensor loss, and unusually low CPU progress after a grace period. CPU progress is an advisory signal, with known pauses and restarts excluded. The timer does not email, send webhooks, or automatically restart workers. Configure external monitoring separately for off-host delivery. A low-hashrate CPU worker may submit shares rarely; absent shares alone are not an outage signal. Check the pool dashboard for accepted work and payout attribution.

```bash
sudo systemctl stop btc-solo-cpu.service
sudo systemctl start btc-solo-cpu.service
sudo systemctl restart btc-solo-cpu.service
sudo systemctl disable --now btc-solo-cpu.service solominer-health.timer
```

## Installed files and security boundaries

- `/usr/local/bin/solominer`: root-owned management entry point.
- `/usr/local/libexec/solominer/releases/`: immutable, root-owned management releases activated together.
- `/etc/sysconfig/btc-solo-cpu`: root-owned configuration.
- `/etc/systemd/system/btc-solo-cpu.service`: miner sandbox and resource-limit drop-in.
- `/etc/systemd/system/solominer-health.service` and `.timer`: local health checks.
- `/opt/cpuminer-opt`: root-owned active binary and provenance.
- `/var/lib/solominer-admin`: root-owned backup manifests, previous files, and staged builds.
- `/var/lib/solominer-build`: temporary private build workspaces.
- `/var/lib/solominer-health`: local health state; `/run/solominer-admin`: maintenance lock.

Build code has no root credentials and cannot write the installed executable tree. Promotion only accepts the expected regular executable. The private build workspace is cleaned after success or failure. The runtime account cannot replace executable or management code. Read [SECURITY.md](SECURITY.md) for residual risks and reporting guidance.

Keep SELinux enabled. The installer does not loosen SELinux policy or open firewall ports. Investigate denials and local overrides on your particular Fedora release.

## Troubleshooting

**Configuration rejected:** run `sudo /usr/local/bin/solominer doctor`, fix the named assignment, and rerun installation. Use a real receive address; invalid checksums/placeholders intentionally fail. Never put shell commands or private wallet material in the file.

**Build fails:** the active release remains available. Inspect the error, disk space, network, and Fedora prerequisites; retry after fixing the cause. Do not run upstream build scripts with `sudo` as a workaround.

**Activation fails:** the updater attempts to restore the previous release. Inspect `solominer status` and the service journal. If both releases fail, repair configuration/pool access before restarting.

**Pool connection fails:** verify the provider's current host/port/transport, DNS, outbound firewall, system time, and CA store. Do not disable certificate verification. Local startup success does not prove network connectivity.

**Sensor missing:** inspect `sensors` and `/sys/class/hwmon`. `MAX_TEMP` works only if the miner can read a relevant CPU sensor. Diagnose hardware/kernel support before relying on it. CPU quotas are independent containment, not a thermal guarantee.

**Too hot or unresponsive:** stop the service, reduce `THREADS`/`CPU_QUOTA`, address cooling, and run `sudo /usr/local/bin/solominer apply-config`. Choose a hardware-appropriate temperature threshold.

**Unexpected behavior:** inspect `sudo systemctl cat btc-solo-cpu.service` and `sudo systemd-analyze security btc-solo-cpu.service`. Effective local settings matter more than repository defaults.

## Development and verification

Local tests need no miner or pool connection:

```bash
python3 -m unittest discover -s tests -v
bash -n scripts/install-solominer.sh scripts/update-solominer.sh
```

CI runs Python tests and shell linting on Ubuntu, plus a full pinned/patched upstream build as an unprivileged account and systemd unit verification in Fedora. A disposable Ubuntu VM also executes the actual systemd build sandbox, activation, configuration, staging, rollback, and health units using a harmless compiled fixture. The fixture never mines or contacts a pool; the test refuses any preexisting SoloMiner installation and cleans up its own files/accounts. It does not access your running host.

Before a new deployment, use a disposable Fedora VM to verify install/update/rollback, account write denial, sensor behavior, resource budgets, SELinux AVCs, and controlled TLS failure scenarios. These tests do not establish the safety of all native third-party code or every Fedora/hardware combination.
