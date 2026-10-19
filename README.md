# SoloMiner

A Fedora-first background service for conservative, hobby Bitcoin CPU solo mining, with reviewed source pins, isolated builds, resource limits, diagnostics, and rollback.

CPU mining has extremely low odds of finding a Bitcoin block. This setup is for experimentation on hardware you control; it is not a profitability claim. Only a public Bitcoin receiving address is needed. Never enter a private key or seed phrase.

## What this version provides

- A dedicated, unprivileged `solominer` runtime account and a separate build account.
- A fixed `cpuminer-opt` v26.1 source commit plus a mandatory local patch for certificate verification and bounded Stratum input.
- Builds without root in a systemd sandbox. Installed code and release metadata are owned by root.
- CPU, memory, swap, task, and temperature limits; validated configuration; readable logs; disabled pool redirects by default.
- Local status, configuration/permission diagnostics, health checks, serialized updates, staging, and rollback.
- Atomic file replacement, startup verification, and recovery of the previous release or last working configuration after failed activation.
- A systemd health timer that reports meaningful failures locally through journald.
- A bounded valid-job freshness deadline that restarts a stalled worker and rotates to an explicitly configured fallback.

There is no web dashboard, listening management API, external notification service, unconfigured pool change, or automatic Fedora upgrade. Pool failover occurs only when explicitly configured.

## Requirements

Traditional, mutable Fedora Linux with systemd, `sudo` access, internet access for builds, outbound pool connectivity, a checksum-valid mainnet Bitcoin receiving address, and enough disk/memory to compile `cpuminer-opt`.

Fedora Atomic variants (including Silverblue and Kinoite) have a different filesystem and package model; this installer refuses them. Do not bypass that check or replace symlink safeguards. Use a traditional Fedora installation until an Atomic-specific installer is implemented.

The CI build uses a Fedora 44 container. Validate the real service on the Fedora release and hardware you intend to use; the container does not exercise host systemd or SELinux.

The installer can install Fedora build prerequisites with `--install-deps`. It does not upgrade the operating system by default. Continue normal Fedora security maintenance separately.

## Upgrade an existing installation

Run these steps on your Fedora machine, from your existing SoloMiner checkout. The build needs network access to fetch the pinned upstream commit; staging does not stop the running service.

1. Record the active version and save your configuration:

   ```bash
   sudo /usr/local/bin/solominer status
   sudo install -m 0600 -o root -g root /etc/sysconfig/btc-solo-cpu /root/btc-solo-cpu.before-update
   ```

   If an older installation lacks the `solominer` command, use `sudo systemctl status btc-solo-cpu.service` for the first check.

2. Update and review the checkout. Save local edits first; `--ff-only` intentionally stops on divergent history:

   ```bash
   cd /path/to/solominer
   git switch main
   git pull --ff-only
   git log -1 --format='%h %s'
   ```

3. Inspect `/etc/sysconfig/btc-solo-cpu` with `sudoedit`. If the pool URL begins with `stratum+tcp://`, set `ALLOW_INSECURE_POOL=true` **only if you explicitly accept plaintext mining traffic**. The preferred choice is a pool-documented `stratum+ssl://` or `stratum+tcps://` endpoint with `ALLOW_INSECURE_POOL=false`. An older config that relied on the previous implicit plaintext allowance must now state its choice; an existing explicit `true` remains valid. Apply the same policy to every fallback URL.

4. For a previously managed installation, stage, activate, and verify:

   ```bash
   sudo bash scripts/update-solominer.sh --check
   sudo bash scripts/update-solominer.sh --no-restart
   sudo bash scripts/update-solominer.sh --activate-staged
   sudo /usr/local/bin/solominer doctor
   sudo /usr/local/bin/solominer status
   sudo systemctl status btc-solo-cpu.service solominer-health.timer
   ```

   For the older unmanaged layout, replace the two update commands with `sudo bash scripts/install-solominer.sh --migrate --install-deps`. Migration requires and preserves the existing configuration, installs the managed code and units, and retains an importable old binary for recovery. An imported binary has unknown provenance and lacks the new native fixes.

5. Watch the local logs and pool dashboard for a valid job and credited work:

   ```bash
   sudo journalctl -u btc-solo-cpu.service -n 100 --no-pager
   sudo journalctl -u solominer-health.service -n 50 --no-pager
   ```

If prerequisites are missing on a managed installation, rerun the staging command with `--install-deps`. If validation fails, fix the named setting with `sudoedit` and retry. A failed activation attempts to restore the prior release. If the new release is active but operationally unsuitable, run `sudo /usr/local/bin/solominer rollback`, then verify status again. Rollback preserves the current configuration; if an older release cannot parse a newly added setting, restore `/root/btc-solo-cpu.before-update` with `sudo install -m 0640 -o root -g solominer /root/btc-solo-cpu.before-update /etc/sysconfig/btc-solo-cpu` and run `sudo /usr/local/bin/solominer apply-config`.

## First installation

```bash
git clone https://github.com/jaysonguglietta/solominer.git
cd solominer
sudo bash scripts/install-solominer.sh --install-deps
```

On first run the installer creates `/etc/sysconfig/btc-solo-cpu` from the example and stops because its wallet is a placeholder. Enter your receiving address and worker name, then choose a provider-documented TLS pool endpoint. If your provider has only plaintext Stratum, explicitly set `ALLOW_INSECURE_POOL=true` after understanding the network risk:

```bash
sudoedit /etc/sysconfig/btc-solo-cpu
sudo bash scripts/install-solominer.sh
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer status
```

The final install enables the miner and health timer. It refuses the example's plaintext URL until you make that transport choice.

## Configuration

Edit the root-owned `/etc/sysconfig/btc-solo-cpu`. Use one `NAME=value` assignment per line. Blank lines and whole-line comments are allowed; values with spaces can be quoted. Multiline values, duplicate/unknown keys, shell expansion, arbitrary miner flags, and embedded pool credentials are unsupported.

| Setting | Default | Meaning |
| --- | --- | --- |
| `POOL` | Example `stratum+tcp://pool.nerdminer.io:3333`; requires explicit opt-in | Explicit host and port; supports `stratum+tcp`, `stratum+ssl`, and `stratum+tcps`. |
| `WALLET` | Placeholder; must be changed | Checksum-valid mainnet Base58Check, Bech32, or Bech32m receive address. |
| `WORKER` | `fedora1` | 1–64 letters, digits, underscores, or hyphens; use a different name per machine. |
| `THREADS` | `2` | Integer from 1 through the host's logical CPU count. |
| `MAX_TEMP` | `75` | Temperature pause threshold in Celsius; 45–100. Requires a working CPU sensor. |
| `CPU_QUOTA` | `100%` | Aggregate CPU budget: `100%` means one logical CPU's time, `200%` means two. |
| `MEMORY_MAX` | `256M` | systemd memory ceiling; 64M–64G using `M` or `G`. Swap is disabled for the miner service. |
| `TASKS_MAX` | `64` | systemd task ceiling; 16–4096 and at least `THREADS + 8` for miner and supervisor tasks. |
| `NO_REDIRECT` | `true` | Reject pool-requested destination changes; opt out only for a pool that requires them. |
| `RETRY_PAUSE` | `30` | Seconds between reconnect attempts; 5–600. |
| `FALLBACK_POOLS` | Empty | Optional comma-separated list of up to three unique pool URLs, different from `POOL`. |
| `HEALTH_TIMEOUT` | `900` | Seconds allowed without a validated new job before restarting or trying a configured fallback; 120–86400. |
| `ALLOW_INSECURE_POOL` | `false` | Explicitly set `true` only when accepting plaintext for every configured plaintext pool. |

`Nice=15` lowers scheduling priority; `CPU_QUOTA` sets the CPU budget. Start conservatively and measure sustained temperature/memory before raising limits. On a one-thread machine, set `THREADS=1`.

After changing configuration, validate and apply resource limits:

```bash
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer apply-config
```

For a safer edit, write a complete candidate file outside the live path and apply it transactionally:

```bash
sudo cp -a /etc/sysconfig/btc-solo-cpu /etc/sysconfig/btc-solo-cpu.candidate
sudoedit /etc/sysconfig/btc-solo-cpu.candidate
sudo /usr/local/bin/solominer apply-config --from /etc/sysconfig/btc-solo-cpu.candidate
```

The candidate is validated before the running configuration changes. If service activation fails, SoloMiner restores the last working configuration. Remove the candidate when satisfied; the active file remains `/etc/sysconfig/btc-solo-cpu`.

If you edited the live file and `apply-config` rejects it, the command restores the last working copy and saves your rejected edit under `/var/lib/solominer-admin/rejected-config-*` for correction. It restarts a unit in the `failed` state after restoring the file; a unit intentionally stopped by the operator remains stopped.

Mining arguments always use SHA256d, `--no-color`, fixed conventional pool password `x`, and no management API. `apply-config` validates and applies both miner arguments and CPU/memory/task ceilings without rebuilding.

### Pool transport and trust

The example NerdMiner endpoint is plaintext for compatibility, but new installations fail closed until you explicitly opt in. An observer on that network path can read or modify mining traffic. The software cannot make a plaintext-only provider secure.

If your pool documents a TLS endpoint, configure that exact host/port and set `ALLOW_INSECURE_POOL=false`. The patched miner verifies the certificate chain against the operating system trust store and the expected hostname. Do not guess TLS ports, disable verification, or silently switch pool operators. TLS authenticates the chosen endpoint; it does not prove that the pool operator is honest.

`NO_REDIRECT=true` blocks pool-requested destination changes. For optional failover, set `FALLBACK_POOLS` to a comma-separated list of provider-verified endpoints. Repeated connection failure, an unrequested miner exit, or the absence of a validated fresh job advances through the primary/fallback list after the retry pause. An explicit service stop never rotates pools. Every endpoint uses the same wallet/worker and transport policy; with `ALLOW_INSECURE_POOL=false`, plaintext fallback URLs are rejected. Without configured fallbacks, the miner keeps retrying the primary pool. The software never changes your payout address. A low-hashrate worker can go a long time without an accepted share; job freshness is a separate signal.

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
| `status` | Service state, release provenance, configured and active pool, timestamp and age of the last validated job, resource use, temperatures, and recent events. |
| `doctor` | Configuration, permissions, release integrity, effective systemd settings, and sensor diagnostics. |
| `health` | Local service, validated-job state, and CPU/thermal evaluation; active process and useful work are distinct signals. |
| `update --check` | Approved pin and installed release; no build or activation and no moving upstream branch. |
| `update` | Install current management code/units, build the approved patched source, record provenance, and activate with startup verification. |
| `update --no-restart` | Stage only; do not change active release or restart the miner. |
| `update --activate-staged` | Activate the staged release after checking it matches the current approved source, patch, and management bundle. |
| `apply-config [--from /absolute/path]` | Validate and activate a candidate configuration with recovery on failure; apply resource limits without rebuilding. |
| `rollback` | Restore the previous retained release and check startup. Legacy rollback may reintroduce old weaknesses. |

The runtime `run` command is for the dedicated systemd service account and rejects root execution. Use service commands instead of launching additional miners manually. Concurrent maintenance is rejected.

## Future updates directly from Git

The repository carries management code, approved upstream revision, and mandatory patch. Pulling Git alone does not alter the running service. Follow the staged [upgrade procedure](#upgrade-an-existing-installation) for later releases as well. `sudo bash scripts/update-solominer.sh` activates immediately; `--no-restart` stages, `--activate-staged` activates the matching staged build, and `--check` inspects. `--install-deps` explicitly installs prerequisites; `--update-packages` explicitly requests a Fedora package upgrade. Neither happens by default. Previous shell environment overrides such as `SOURCE_REPO`, `UPDATE_PACKAGES`, and `RESTART_SERVICE` are unsupported; use explicit command options.

New upstream revisions must be reviewed, pinned, patched, and tested in this repository before adoption. An upstream release does not automatically become an approved update.

## Monitoring and service management

```bash
sudo systemctl status btc-solo-cpu.service
sudo journalctl -u btc-solo-cpu.service -n 100 --no-pager
sudo journalctl -u btc-solo-cpu.service -f
sudo systemctl list-timers solominer-health.timer
sudo journalctl -u solominer-health.service --since today --no-pager
```

The timer checks every five minutes after a two-minute startup delay, with a small randomized delay. Health alerts remain local in journald and emit only on new conditions or recovery. It detects stale validated jobs, crashes, overheating, sensor loss, and unusually low CPU progress after a grace period. CPU progress is an advisory signal, with known pauses and restarts excluded. The health checker reads a dedicated miner state file and systemd accounting; it does not need access to the whole system journal. The timer does not email or send webhooks. The supervisor itself restarts or rotates a worker that receives no valid job within `HEALTH_TIMEOUT`. A low-hashrate CPU worker may submit shares rarely; absent shares alone are not an outage signal. Check the pool dashboard for accepted work and payout attribution.

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
- `/var/lib/solominer-health`: local health alert state; `/run/solominer/state.json`: bounded worker/job state readable by the health service; `/run/solominer-admin`: maintenance lock.

Build code has no root credentials and cannot write the installed executable tree. Promotion only accepts the expected regular executable. The private build workspace is cleaned after success or failure. The runtime account cannot replace executable or management code. Read [SECURITY.md](SECURITY.md) for residual risks and reporting guidance.

Keep SELinux enabled. The installer does not loosen SELinux policy or open firewall ports. Investigate denials and local overrides on your particular Fedora release.

## Troubleshooting

**Configuration rejected:** run `sudo /usr/local/bin/solominer doctor`, fix the named assignment, and rerun installation. Use a real receive address; invalid checksums/placeholders intentionally fail. Never put shell commands or private wallet material in the file.

**Build fails:** the active release remains available. Inspect the error, disk space, network, and Fedora prerequisites; retry after fixing the cause. Do not run upstream build scripts with `sudo` as a workaround.

**Activation fails:** the updater attempts to restore the previous release. `apply-config --from` also restores the last working configuration after a failed candidate. Inspect `solominer status` and the service journal. If both releases fail, repair configuration/pool access before restarting.

**Pool connection or job freshness fails:** verify the provider's current host/port/transport, DNS, outbound firewall, system time, and CA store. Inspect the active pool and last validated job in `solominer status`. Do not disable certificate verification. Local startup success does not prove network connectivity or valid work.

**Sensor missing:** inspect `sensors` and `/sys/class/hwmon`. `MAX_TEMP` works only if the miner can read a relevant CPU sensor. Diagnose hardware/kernel support before relying on it. CPU quotas are independent containment, not a thermal guarantee.

**Too hot or unresponsive:** stop the service, reduce `THREADS`/`CPU_QUOTA`, address cooling, and run `sudo /usr/local/bin/solominer apply-config`. Choose a hardware-appropriate temperature threshold.

**Unexpected behavior:** inspect `sudo systemctl cat btc-solo-cpu.service` and `sudo systemd-analyze security btc-solo-cpu.service`. Effective local settings matter more than repository defaults.

## Development and verification

Local tests need no miner or pool connection:

```bash
python3 -m unittest discover -s tests -v
bash -n scripts/install-solominer.sh scripts/update-solominer.sh tests/fedora_acceptance.sh
```

CI runs Python tests and shell linting on Ubuntu, plus a full pinned/patched upstream build as an unprivileged account and systemd unit verification in a Fedora container. A disposable Ubuntu VM also executes the actual systemd build sandbox, activation, configuration, staging, rollback, and health units using a harmless compiled fixture. The fixture never mines or contacts a pool; the test refuses any preexisting SoloMiner installation and cleans up its own files/accounts.

For Fedora-specific acceptance, use a **fresh, disposable traditional Fedora VM**, with systemd running and SELinux enforcing. Install the normal build prerequisites and `gcc`, keep the VM isolated from personal files and credentials, then from a checkout run:

```bash
sudo env CI=true SOLOMINER_DISPOSABLE_VM=1 bash tests/fedora_acceptance.sh
sudo ausearch -m AVC,USER_AVC -ts recent -i
```

The wrapper refuses an existing SoloMiner installation, a non-Fedora host, Fedora Atomic, or non-enforcing SELinux. Review any AVCs against SoloMiner and correct policy or file labels rather than disabling SELinux. The GitHub workflow has an optional `fedora_vm` manual-dispatch job for an **ephemeral** self-hosted Fedora VM runner labeled `fedora` and `disposable`; ordinary PRs never receive that job. Register a one-job runner from a fresh VM snapshot using GitHub's [ephemeral runner instructions](https://docs.github.com/en/actions/reference/runners/self-hosted-runners#ephemeral-runners-for-autoscaling), then discard the VM after the job. A job without a matching runner stays queued, so leave `fedora_vm` unchecked until one is available. These checks do not establish the safety of all native third-party code or every Fedora/hardware combination.
