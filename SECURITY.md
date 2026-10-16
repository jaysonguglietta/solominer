# Security

SoloMiner is a Fedora service wrapper around native third-party mining code. Security-sensitive boundaries are root installation, downloaded build inputs, unprivileged builds, runtime permissions, and untrusted Stratum traffic.

## Security model

The administrator controls the Git checkout and root-owned configuration. `sudo` installation trusts the management code in that checkout. Review incoming changes first; a root installer cannot protect against an intentionally malicious administrator-selected installer.

Miner source is an immutable approved commit, not a moving branch. A mandatory versioned patch enables certificate/hostname verification and bounds Stratum buffering. Pinning reduces unexpected updates; it is not an upstream signature or proof that all source is harmless. Build scripts execute as a separate unprivileged account inside a restrictive systemd unit. Root installs only the expected regular executable. The distinct runtime account cannot modify installed code.

The runtime sandbox has no added capabilities, read-only code, protected system/home/kernel interfaces, limited address families, and resource ceilings. It reduces impact after compromise; native parser bugs, kernel vulnerabilities, and permissive local overrides still matter. Never run the miner or upstream builds as root.

The three service identities must have non-login shells, dedicated primary groups, and no account-level supplementary groups. This prevents accidental inheritance of administrative or privileged socket access. The health unit explicitly receives read access through the miner and systemd journal groups; it has no network access.

There is no public management API, authentication session, database, tenant model, webhook receiver, or file upload server. Keep upstream remote APIs disabled. Only outbound pool connectivity is required; no inbound firewall port is needed.

## Network and privacy

The default NerdMiner endpoint uses plaintext for existing compatibility. An on-path attacker can observe or tamper with mining traffic. `ALLOW_INSECURE_POOL=false` rejects plaintext. Use a provider-documented TLS endpoint or separately authenticated tunnel; do not guess ports or bypass certificate checks.

The patched TLS path checks chain and hostname. This authenticates the chosen endpoint, not the honesty of the pool or its payouts. `NO_REDIRECT=true` blocks pool-requested destination changes by default. Disabling it is an explicit compatibility tradeoff.

Receiving addresses and worker names appear in process arguments and logs. They are public identifiers but correlate activity. This software needs no private key, seed phrase, exchange token, or wallet password. Never store them here. Local health checks do not transmit logs to notification services.

## Updates and recovery

Updates use a lock, private build workspace, bounded commands, root-owned release storage, binary digests, and provenance metadata. Failed builds leave the active release intact. Files are replaced atomically while the service is stopped; failed startup checks attempt to restore the prior release. The complete multi-file activation is not a power-loss transaction. After an interruption or power loss, an administrator should inspect state and logs.

Startup verification checks local service execution. It cannot prove honest pool behavior, successful payouts, or future availability. Journal-based health signals and sensor data have operational limits. Health checks do not automatically restart based on a guessed connection problem.

Imported legacy binaries have unknown provenance and may retain prior defects. Rollback provides recovery, not proof that an older version is secure. Prefer repairing the pinned release over remaining on a legacy binary.

Continue normal Fedora security updates. Package upgrades are explicitly requested and do not happen by default. Keep SELinux enabled and inspect effective systemd overrides, `solominer doctor`, and `systemd-analyze security` output.

## Validation expectations

CI exercises configuration, command construction, maintenance invariants, shell linting, unit syntax, upstream patch application/buffer limits, and an unprivileged Fedora build without mining. Local unit tests do not operate a real service. A separate CI-only integration script uses a harmless compiled fixture on a disposable Ubuntu systemd VM to verify actual sandboxing, activation, staging, rollback, and health units. It refuses preexisting installations and requires explicit CI/root/Linux conditions; it performs no mining or pool connection.

Validate on a disposable Fedora host before relying on unattended operation:

1. Fresh install, migration, update, staging, rollback, interrupted/failed builds, failed activation, and concurrent update rejection.
2. Runtime write denial for code, provenance, configuration, and all parent directories; builder write denial outside its workspace.
3. Trusted matching TLS success and untrusted/expired/wrong-host certificate rejection at a controlled endpoint.
4. Oversized/fragmented Stratum input, allocation failures, bounded memory, and clean disconnects.
5. Pool/DNS outage, sleep/resume, crash loops, sensor loss, temperature warnings, and local alerts.
6. Effective resource limits, SELinux AVCs, no unexpected listening sockets, current Fedora advisories, and linked-library inventory.

No complete audit of `cpuminer-opt`, Fedora, the kernel, or linked libraries is claimed. The user's running Fedora host was not remotely inspected during this repository update.

## Reporting

Use GitHub private vulnerability reporting if enabled. Otherwise contact the repository owner privately before publishing exploit details. Do not put private keys, credentials, sensitive full logs, or working attacks against third-party pools in public issues.

Include the SoloMiner commit, installed provenance, Fedora/systemd version, effective unit, minimal reproducible test, impact, and sanitized logs. Distinguish confirmed exploitation from suspected risk. Test only systems you own or are authorized to assess.
