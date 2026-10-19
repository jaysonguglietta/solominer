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

The installer can install Fedora build prerequisites with `--install-deps`. It does not upgrade the operating system by default. Use the [manual updater](#manual-fedora-and-solominer-updates) or your normal Fedora maintenance process for security updates.

## Upgrade or migrate an existing Fedora installation

The Git checkout and running installation are separate. `/opt/cpuminer-opt` contains the upstream miner source and installed binary; its Git remote may be `JayDDee/cpuminer-opt`. **Do not switch branches or pull there to update SoloMiner.** Use a checkout whose remote is `jaysonguglietta/solominer`. An older installation may have no SoloMiner checkout or `/usr/local/bin/solominer` command at all.

1. Check the existing service and find or create a SoloMiner checkout. If the `find` command prints `/root/solominer/scripts/update-solominer.sh`, for example, the checkout is `/root/solominer` (the directory containing `scripts`). If it prints nothing, clone a fresh copy. Cloning does not change the running service.

   ```bash
   systemctl show btc-solo-cpu.service -p LoadState -p ActiveState
   test -f /etc/sysconfig/btc-solo-cpu && echo "Config exists" || echo "Config missing"
   test -x /usr/local/bin/solominer && echo "Managed command exists" || echo "No managed command"
   sudo find /root /home /srv /opt -type f -path '*/scripts/update-solominer.sh' -print 2>/dev/null
   ```

   If no checkout was found:

   ```bash
   git clone https://github.com/jaysonguglietta/solominer.git "$HOME/solominer"
   cd "$HOME/solominer"
   ```

   If either the service or configuration is missing, do not run `--migrate`; inspect the existing setup. Follow [First installation](#first-installation) only when this is actually a new install.

2. From the SoloMiner checkout selected in step 1, verify its remote, review local edits, and update `main`. Stop if the remote is the upstream `cpuminer-opt` repository or if `git status` shows changes you have not reviewed. `--ff-only` deliberately stops on divergent history.

   ```bash
   git remote get-url origin
   git status --short
   git switch main
   git pull --ff-only origin main
   git log -1 --format='%h %s'
   ```

3. Save the existing configuration under a unique root-only filename, then validate it with the new parser **before** migration or activation. Keep the printed backup path for recovery. The validator prints an error without changing the live service.

   ```bash
   backup_path="/root/btc-solo-cpu.before-update.$(date -u +%Y%m%dT%H%M%SZ)"
   sudo install -m 0600 -o root -g root /etc/sysconfig/btc-solo-cpu "$backup_path"
   printf 'Config backup: %s\n' "$backup_path"
   sudo python3 -c 'from solominer.config import load_config; load_config("/etc/sysconfig/btc-solo-cpu"); print("Configuration valid")'
   ```

   If validation rejects a `stratum+tcp://` pool, use `sudoedit /etc/sysconfig/btc-solo-cpu` to select a **pool-documented** `stratum+ssl://` or `stratum+tcps://` host and port with `ALLOW_INSECURE_POOL=false`, or set `ALLOW_INSECURE_POOL=true` exactly once if you deliberately accept plaintext traffic. Do not guess a TLS port. The same rule applies to fallback pools. Fix any other named validation error and rerun the validator until it prints `Configuration valid`.

4. Choose the command that matches the current installation:

   - **Managed install** (`/usr/local/bin/solominer` exists): stage and then activate. `--check` compares this checkout with installed provenance; it does not fetch Git. Staging builds without stopping the service; activation briefly restarts it.

     ```bash
     sudo bash scripts/update-solominer.sh --check
     sudo bash scripts/update-solominer.sh --no-restart
     sudo bash scripts/update-solominer.sh --activate-staged
     ```

   - **Older unmanaged install** (service and config exist, but the command is absent): migrate with the validated configuration. The installer builds before stopping the service, backs up the old executable and unit for rollback, and installs the managed service and health timer. An imported legacy binary has unknown provenance and may retain old defects.

     ```bash
     sudo bash scripts/install-solominer.sh --migrate --install-deps
     ```

5. Verify the release and pool connection. A running service and supervisor telemetry do not by themselves prove a pool job was received. `status` should eventually show a `Last validated job` timestamp; `doctor` may say `Waiting for the first validated Stratum job` during the initial grace period. The first delivered valid-job event is recorded immediately. If no valid job arrives within `HEALTH_TIMEOUT` (900 seconds by default), the supervisor restarts the worker or tries a configured fallback. Check the active pool, failure count, service journal, and pool dashboard. A valid job is not an accepted share or payout; CPU solo mining may go a long time without either. Redact your wallet address before sharing logs.

   ```bash
   sudo /usr/local/bin/solominer doctor
   sudo /usr/local/bin/solominer status
   sudo systemctl status btc-solo-cpu.service solominer-health.timer --no-pager
   sudo journalctl -u btc-solo-cpu.service -n 100 --no-pager
   sudo journalctl -u solominer-health.service -n 50 --no-pager
   ```

If prerequisites are missing on a managed installation, rerun the staging command with `--install-deps`. A failed activation attempts to restore the prior release. If the new release is active but unsuitable, run `sudo /usr/local/bin/solominer rollback` and verify the service. Rollback preserves the live configuration; restore the saved backup if the older release cannot use newer settings. A rollback to an unmanaged legacy install can remove the `solominer` command, so use `systemctl` and the old unit to verify it instead of assuming `apply-config` is available.

## First installation

```bash
git clone https://github.com/jaysonguglietta/solominer.git "$HOME/solominer"
cd "$HOME/solominer"
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

The repository carries management code, approved upstream revision, and mandatory patch. Pulling Git alone does not alter the running service. Follow the staged [upgrade procedure](#upgrade-or-migrate-an-existing-fedora-installation) for later releases, or install the [manual updater](#manual-fedora-and-solominer-updates) for occasional operator-controlled updates. `sudo bash scripts/update-solominer.sh` activates immediately; `--no-restart` stages, `--activate-staged` activates the matching staged build, and `--check` compares the checkout with the installed release. `--install-deps` explicitly installs prerequisites; `--update-packages` explicitly requests a Fedora package upgrade. Neither happens by default. Previous shell environment overrides such as `SOURCE_REPO`, `UPDATE_PACKAGES`, and `RESTART_SERVICE` are unsupported; use explicit command options.

New upstream revisions must be reviewed, pinned, patched, and tested in this repository before adoption. An upstream release does not automatically become an approved update.

## Manual Fedora and SoloMiner updates

For a traditional Fedora host with a managed SoloMiner installation, `scripts/manual-update.sh` provides a command you can keep at `/etc/solominer/update.sh` and run when you choose. It has no timer or automatic reboot. It updates Fedora RPMs, SoloMiner code, or both only when you select the corresponding mode. Code-related modes require a clean, root-owned `/root/solominer` checkout on `main`, connected to the expected SoloMiner GitHub remote. It is separate from `/opt/cpuminer-opt`.

Install the script once from a checkout whose contents you have reviewed. Run this block in a root shell (`sudo -i` if needed), since a normal user cannot access `/root/solominer`. It stops if the branch, remote, or worktree is unexpected, and asks you to type the complete reviewed SHA before installing anything. The checkout must already exist; see [Upgrade or migrate an existing Fedora installation](#upgrade-or-migrate-an-existing-fedora-installation) if it does not. Read the displayed diff, especially changes to `scripts/manual-update.sh`, before entering the SHA:

```bash
(
  set -e
  cd /root/solominer
  test ! -L /root/solominer
  test -d /root/solominer/.git && test ! -L /root/solominer/.git
  bad_path=$(find /root/solominer -xdev \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print -quit)
  test -z "$bad_path"
  test "$(git remote get-url origin)" = 'https://github.com/jaysonguglietta/solominer.git'
  test "$(git branch --show-current)" = main
  dirty=$(git status --porcelain=v1 --untracked-files=all)
  test -z "$dirty"
  git -c core.hooksPath=/dev/null fetch --no-tags origin main
  reviewed_sha=$(git rev-parse 'FETCH_HEAD^{commit}')
  git merge-base --is-ancestor HEAD "$reviewed_sha"
  git --no-pager log --oneline "HEAD..$reviewed_sha"
  git --no-pager diff --stat --no-ext-diff --no-textconv HEAD "$reviewed_sha"
  git --no-pager diff --no-ext-diff --no-textconv HEAD "$reviewed_sha"
  read -r -p 'Type the full reviewed commit SHA to install the updater: ' approved_sha
  test "$approved_sha" = "$reviewed_sha"
  git -c core.hooksPath=/dev/null merge --ff-only "$reviewed_sha"
  install -d -m 0755 -o root -g root /etc/solominer
  install -m 0700 -o root -g root scripts/manual-update.sh /etc/solominer/update.sh
)
```

For each maintenance session, start with a non-installing update check. It fetches the repository's `main` branch from its fixed HTTPS URL and reports the complete Git commit ID, incoming commits and change summary, and available Fedora package updates; it does not activate code or install RPMs. It can update the local Git object store and DNF metadata. A bare invocation has the same behavior:

```bash
sudo /etc/solominer/update.sh --check
```

Use the **full 40-character commit ID** printed by `--check` in the next commands, replacing `COMMIT_SHA` below. Run the Git review commands in a root shell. Before a SoloMiner code update, inspect the complete incoming diff and any changes to root-run scripts, the pinned source, patch, service units, and dependency list. The commit ID is an explicit choice of what to install: if `main` moves after the check, the updater stops and asks you to check and review again.

```bash
git -C /root/solominer --no-pager log --oneline HEAD..COMMIT_SHA
git -C /root/solominer --no-pager diff --stat --no-ext-diff --no-textconv HEAD COMMIT_SHA
git -C /root/solominer --no-pager diff --no-ext-diff --no-textconv HEAD COMMIT_SHA
sudo /etc/solominer/update.sh --miner COMMIT_SHA
```

Choose `--packages` to run `dnf upgrade --refresh` without changing the SoloMiner Git checkout. It requires a terminal and asks you to type `UPGRADE` before invoking DNF. This upgrades eligible RPMs across the **whole Fedora system**, not only SoloMiner prerequisites. Choose `--all COMMIT_SHA` to run that DNF transaction first and then update SoloMiner from the reviewed commit. A failed package transaction stops the combined update before the SoloMiner code step. If the remote `main` moves during the package transaction, the RPMs remain updated and the code step stops until you review the new commit. Neither mode performs a Fedora release upgrade or reboots the machine.

```bash
sudo /etc/solominer/update.sh --packages
sudo /etc/solominer/update.sh --all COMMIT_SHA
```

The code modes fast-forward the checked-out `main` branch, stage the managed build, activate it, then run `doctor` and `status`. Activation can briefly interrupt mining. The updater script in `/etc` is a separate root-owned copy: a SoloMiner code update does not silently replace it. After reviewing a newer `scripts/manual-update.sh`, repeat the `sudo install -m 0700 ...` command above to refresh the copy.

Check the service and validated-job timestamp after maintenance. A package update can require an operator-controlled reboot or restart of affected services; SoloMiner rollback does **not** undo Fedora RPM upgrades. If a code activation fails, inspect the output and journal; the managed updater attempts to recover the prior release. If a new SoloMiner release runs but is unsuitable, use `sudo /usr/local/bin/solominer rollback` and verify it again. A rollback does not rewind `/root/solominer`, so review that checkout before a later retry.

```bash
sudo /usr/local/bin/solominer doctor
sudo /usr/local/bin/solominer status
sudo systemctl status btc-solo-cpu.service --no-pager
sudo journalctl -u btc-solo-cpu.service -n 100 --no-pager
```

## Monitoring and service management

```bash
sudo systemctl status btc-solo-cpu.service
sudo journalctl -u btc-solo-cpu.service -n 100 --no-pager
sudo journalctl -u btc-solo-cpu.service -f
sudo systemctl list-timers solominer-health.timer
sudo journalctl -u solominer-health.service --since today --no-pager
```

The timer checks every five minutes after a two-minute startup delay, with a small randomized delay. Health alerts remain local in journald and emit only on new conditions or recovery. It detects stale validated jobs, crashes, overheating, sensor loss, and unusually low CPU progress after a grace period. CPU progress is an advisory signal, with known pauses and restarts excluded. The health checker reads a dedicated miner state file and systemd accounting; it does not need access to the whole system journal. The timer does not email or send webhooks. The supervisor records the first delivered valid-job event immediately, then throttles later state writes. It restarts or rotates a worker that receives no valid job within `HEALTH_TIMEOUT`. A low-hashrate CPU worker may submit shares rarely; absent shares alone are not an outage signal. Check the pool dashboard for accepted work and payout attribution.

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
- `/etc/solominer/update.sh`: optional, root-owned manual update command copied from a reviewed checkout.
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

**Manual updater refuses to run:** verify that `/root/solominer` is the clean, root-owned SoloMiner `main` checkout and that its `origin` is the expected repository. If `main` advanced after `--check`, inspect the new diff and use its new full commit ID. Do not bypass ownership, remote, or clean-worktree checks. If DNF fails, resolve the Fedora package error before retrying; SoloMiner rollback cannot restore RPMs.

**Pool connection or job freshness fails:** verify the provider's current host/port/transport, DNS, outbound firewall, system time, and CA store. Inspect the active pool and last validated job in `solominer status`. Do not disable certificate verification. Local startup success does not prove network connectivity or valid work.

**Sensor missing:** inspect `sensors` and `/sys/class/hwmon`. `MAX_TEMP` works only if the miner can read a relevant CPU sensor. Diagnose hardware/kernel support before relying on it. CPU quotas are independent containment, not a thermal guarantee.

**Too hot or unresponsive:** stop the service, reduce `THREADS`/`CPU_QUOTA`, address cooling, and run `sudo /usr/local/bin/solominer apply-config`. Choose a hardware-appropriate temperature threshold.

**Unexpected behavior:** inspect `sudo systemctl cat btc-solo-cpu.service` and `sudo systemd-analyze security btc-solo-cpu.service`. Effective local settings matter more than repository defaults.

## Development and verification

Local tests need no miner or pool connection:

```bash
python3 -m unittest discover -s tests -v
bash -n scripts/install-solominer.sh scripts/update-solominer.sh scripts/manual-update.sh tests/fedora_acceptance.sh
```

CI runs Python tests and shell linting on Ubuntu, plus a full pinned/patched upstream build as an unprivileged account and systemd unit verification in a Fedora container. A disposable Ubuntu VM also executes the actual systemd build sandbox, activation, configuration, staging, rollback, and health units using a harmless compiled fixture. The fixture never mines or contacts a pool; the test refuses any preexisting SoloMiner installation and cleans up its own files/accounts.

For Fedora-specific acceptance, use a **fresh, disposable traditional Fedora VM**, with systemd running and SELinux enforcing. Install the normal build prerequisites and `gcc`, keep the VM isolated from personal files and credentials, then from a checkout run:

```bash
sudo env CI=true SOLOMINER_DISPOSABLE_VM=1 bash tests/fedora_acceptance.sh
sudo ausearch -m AVC,USER_AVC -ts recent -i
```

The wrapper refuses an existing SoloMiner installation, a non-Fedora host, Fedora Atomic, or non-enforcing SELinux. Review any AVCs against SoloMiner and correct policy or file labels rather than disabling SELinux. The GitHub workflow has an optional `fedora_vm` manual-dispatch job for an **ephemeral** self-hosted Fedora VM runner labeled `fedora` and `disposable`; ordinary PRs never receive that job. Register a one-job runner from a fresh VM snapshot using GitHub's [ephemeral runner instructions](https://docs.github.com/en/actions/reference/runners/self-hosted-runners#ephemeral-runners-for-autoscaling), then discard the VM after the job. A job without a matching runner stays queued, so leave `fedora_vm` unchecked until one is available. These checks do not establish the safety of all native third-party code or every Fedora/hardware combination.
