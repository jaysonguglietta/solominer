"""Privileged promotion, unprivileged builds, provenance, and recovery."""
from __future__ import annotations
import contextlib
import datetime as dt
import fcntl
import hashlib
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from .config import ConfigError, DEFAULT_CONFIG, load_config, parse_config

SOURCE_ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_REPO = "https://github.com/JayDDee/cpuminer-opt.git"
UPSTREAM_REVISION = "b34565bfaca5da9ed894a326e3ba0dfe459550a4"
UPSTREAM_VERSION = "v26.1"
PATCH_NAME = "cpuminer-opt-v26.1-security.patch"
INSTALL_DIR = Path("/opt/cpuminer-opt")
ADMIN_DIR = Path("/var/lib/solominer-admin")
BUILDER_ROOT = Path("/var/lib/solominer-build")
LIB_ROOT = Path("/usr/local/libexec/solominer/releases")
UNIT_DIR = Path("/etc/systemd/system")
SERVICE = "btc-solo-cpu.service"
HEALTH_TIMER = "solominer-health.timer"
CLI_PATH = Path("/usr/local/bin/solominer")
RESOURCE_PATH = UNIT_DIR / (SERVICE + ".d") / "50-solominer-resources.conf"
TARGETS = {"binary": INSTALL_DIR / "cpuminer", "metadata": INSTALL_DIR / "install.json",
           "cli": CLI_PATH, "service": UNIT_DIR / SERVICE,
           "health_service": UNIT_DIR / "solominer-health.service",
           "health_timer": UNIT_DIR / HEALTH_TIMER, "resources": RESOURCE_PATH}
DEPS = ["git", "gcc", "gcc-c++", "make", "automake", "autoconf", "libtool",
        "libcurl-devel", "jansson-devel", "pkgconf-pkg-config", "binutils",
        "gmp-devel", "zlib-devel", "openssl-devel",
        "lm_sensors", "python3", "patch", "util-linux", "systemd"]
MIN_BUILD_FREE_BYTES = 1024 ** 3

class AdminError(RuntimeError):
    """Recoverable administrative error."""

def command(argv, *, capture=False, timeout=120, env=None, input=None, check=True):
    result = subprocess.run(list(map(str, argv)), check=False, timeout=timeout,
                            text=True, capture_output=capture, env=env, input=input)
    if check and result.returncode:
        raise AdminError(f"Command failed ({result.returncode}): {argv[0]} "
                         + ((result.stderr or "").strip() if capture else ""))
    return result

def require_host():
    if os.geteuid() != 0:
        raise AdminError("Run this administrative command with sudo.")
    if not Path("/etc/fedora-release").is_file():
        raise AdminError("Installation and updates require Fedora with a running systemd manager.")
    if Path("/run/ostree-booted").exists():
        raise AdminError("Fedora Atomic/rpm-ostree hosts are not supported by this installer; "
                         "use a traditional Fedora installation. No system changes were made.")

def require_commands():
    for name in ("git", "systemctl", "systemd-run", "systemd-analyze", "make", "gcc",
                 "autoreconf", "pkg-config", "readelf"):
        if shutil.which(name) is None:
            raise AdminError(f"Missing {name}; use --install-deps to install prerequisites.")
    if not Path("/run/systemd/system").is_dir():
        raise AdminError("A running systemd system manager is required for isolated builds.")

def secure_dir(path: Path, mode=0o755):
    path = Path(path)
    if not path.is_absolute():
        raise AdminError("Administrative paths must be absolute.")
    for part in reversed((path, *path.parents)):
        if part == Path("/"):
            continue
        if not part.exists() and not part.is_symlink():
            part.mkdir(mode=mode if part == path else 0o755)
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AdminError(f"Unsafe directory ownership, permissions, or symlink: {part}")
    # Never widen a previously private administrative directory.
    os.chmod(path, stat.S_IMODE(path.stat().st_mode) & mode)

def secure_install_dir():
    secure_dir(INSTALL_DIR.parent)
    if INSTALL_DIR.exists() or INSTALL_DIR.is_symlink():
        if not stat.S_ISDIR(INSTALL_DIR.lstat().st_mode):
            raise AdminError(f"Refusing substituted installation directory: {INSTALL_DIR}")
        os.chown(INSTALL_DIR, 0, 0)
        os.chmod(INSTALL_DIR, 0o755)
    else:
        secure_dir(INSTALL_DIR)

def atomic_write(path: Path, data: bytes, mode=0o644, gid=0):
    secure_dir(path.parent)
    if path.is_symlink():
        raise AdminError(f"Refusing symlink destination: {path}")
    fd, name = tempfile.mkstemp(prefix=".solominer-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)

def read_regular(path: Path, limit=128 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise AdminError(f"Expected a bounded regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise AdminError(f"File grew beyond its safety limit: {path}")
        return data
    finally:
        os.close(fd)

def config_from_data(data: bytes):
    try:
        return parse_config(data.decode('utf-8'), DEFAULT_CONFIG)
    except UnicodeError as error:
        raise ConfigError("Configuration must be UTF-8 text.") from error

@contextlib.contextmanager
def update_lock():
    secure_dir(Path("/run/solominer-admin"), 0o700)
    fd = os.open("/run/solominer-admin/update.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise AdminError("Unsafe update lock file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AdminError("Another SoloMiner administrative operation is in progress.") from error
        yield
    finally:
        os.close(fd)

def ensure_users():
    for user in ("solominer", "solominer-build", "solominer-health"):
        try:
            account = pwd.getpwnam(user)
        except KeyError:
            command(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                     "/nonexistent", "--shell", "/usr/sbin/nologin", user])
            account = pwd.getpwnam(user)
        if account.pw_uid == 0 or account.pw_gid == 0:
            raise AdminError(f"Refusing privileged service identity {user}.")
        try:
            group = grp.getgrnam(user)
        except KeyError as error:
            raise AdminError(f"Expected dedicated group {user} does not exist.") from error
        if group.gr_gid != account.pw_gid:
            raise AdminError(f"{user} must use its dedicated primary group {user}.")
        if account.pw_shell not in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"):
            raise AdminError(f"{user} must be a dedicated non-login service account.")
        if set(os.getgrouplist(user, account.pw_gid)) != {account.pw_gid}:
            raise AdminError(f"{user} has unexpected supplementary groups; use a dedicated service identity.")

def patch_digest():
    return hashlib.sha256(read_regular(SOURCE_ROOT / "patches" / PATCH_NAME)).hexdigest()

def bundle_files():
    files = list((SOURCE_ROOT / "solominer").glob("*.py")) + list((SOURCE_ROOT / "systemd").glob("*"))
    files += [SOURCE_ROOT / "patches" / PATCH_NAME, SOURCE_ROOT / "scripts" / "build-miner.sh"]
    return sorted(path for path in files if path.is_file())

def bundle_digest():
    digest = hashlib.sha256()
    for path in bundle_files():
        digest.update(str(path.relative_to(SOURCE_ROOT)).encode() + b"\0")
        digest.update(read_regular(path))
    return digest.hexdigest()[:24]

def check_update():
    try:
        installed = json.loads(read_regular(INSTALL_DIR / "install.json"))
    except (OSError, ValueError):
        installed = {}
    expected = {"revision": UPSTREAM_REVISION, "patch_sha256": patch_digest(), "control_digest": bundle_digest()}
    return {"installed": installed, "approved": expected,
            "update_available": any(installed.get(key) != value for key, value in expected.items()),
            "note": "Compares this checkout with installed provenance; never automatically adopts upstream code."}

def builder_command(argv, workspace: Path, *, network=False):
    """Run builder-controlled code in a bounded service; only an explicit fetch gets network."""
    options = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
            "--uid=solominer-build", "--gid=solominer-build", f"--working-directory={workspace / 'source'}",
            "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
            "--property=PrivateDevices=yes", "--property=InaccessiblePaths=/var/tmp",
            "--property=CapabilityBoundingSet=", "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes",
            "--property=RestrictSUIDSGID=yes", "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=30min", "--property=MemoryMax=2G",
            "--property=MemorySwapMax=512M", "--property=TasksMax=256", "--property=CPUQuota=200%",
            "--property=TemporaryFileSystem=/tmp:rw,size=512M,mode=1777",
            f"--property=ReadWritePaths={workspace}", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
            f"HOME={workspace / 'home'}", "TMPDIR=/tmp", "LANG=C",
            "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
            "CFLAGS=-O2 -march=native -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE",
            "LDFLAGS=-Wl,-z,relro,-z,now -pie", *map(str, argv)]
    if not network:
        options.insert(options.index("--property=PrivateDevices=yes"), "--property=PrivateNetwork=yes")
    return options

def run_builder(argv, workspace, timeout, *, network=False, capture=False, input=None):
    unit = ("solominer-fetch-" if network else "solominer-build-") + uuid.uuid4().hex
    args = builder_command(argv, workspace, network=network)
    args.insert(1, f"--unit={unit}")
    try:
        return command(args, timeout=timeout, capture=capture, input=input)
    finally:
        # Interrupted systemd-run must not leave acquisition or a build alive after cleanup.
        command(["systemctl", "stop", unit], check=False, capture=True)

def needed_libraries(binary: Path, workspace: Path):
    """Inspect ELF metadata inside the sandbox without invoking the dynamic loader."""
    output = run_builder(["readelf", "-W", "-d", str(binary)], workspace, 60, capture=True).stdout
    libraries = sorted(set(re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", output)))
    if not any(re.fullmatch(r"libjansson\.so(?:\.\d+)*", library) for library in libraries):
        raise AdminError("Built miner is not dynamically linked to Fedora's system Jansson library.")
    return libraries

@contextlib.contextmanager
def built_candidate():
    secure_dir(BUILDER_ROOT)
    if shutil.disk_usage(BUILDER_ROOT).free < MIN_BUILD_FREE_BYTES:
        raise AdminError("At least 1 GiB of free space is required in the SoloMiner build filesystem.")
    account = pwd.getpwnam("solominer-build")
    with tempfile.TemporaryDirectory(prefix="build-", dir=BUILDER_ROOT) as directory:
        workspace = Path(directory)
        os.chown(workspace, account.pw_uid, account.pw_gid)
        home = workspace / "home"
        home.mkdir(mode=0o700)
        os.chown(home, account.pw_uid, account.pw_gid)
        source = workspace / "source"
        source.mkdir(mode=0o700)
        os.chown(source, account.pw_uid, account.pw_gid)
        def git(*args, input=None, capture=False, network=False):
            return run_builder(["git", "-c", "core.hooksPath=/dev/null",
                                "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *args],
                               workspace, timeout=600, input=input, capture=capture, network=network)
        print(f"Fetching approved {UPSTREAM_VERSION} source as solominer-build...", flush=True)
        git("init", "--quiet", str(source))
        git("-C", str(source), "fetch", "--quiet", "--depth=1", UPSTREAM_REPO, UPSTREAM_REVISION,
            network=True)
        git("-C", str(source), "checkout", "--quiet", "--detach", "FETCH_HEAD")
        revision = git("-C", str(source), "rev-parse", "HEAD", capture=True).stdout.strip()
        if revision != UPSTREAM_REVISION:
            raise AdminError("Fetched source does not match approved revision.")
        patch = read_regular(SOURCE_ROOT / "patches" / PATCH_NAME).decode()
        git("-C", str(source), "apply", "--check", "-", input=patch)
        git("-C", str(source), "apply", "-", input=patch)
        driver = workspace / "build-miner.sh"
        driver.write_bytes(read_regular(SOURCE_ROOT / "scripts" / "build-miner.sh"))
        driver.chmod(0o444)
        print("Building without root or network access in a restricted service...", flush=True)
        run_builder(["/bin/bash", str(driver)], workspace, timeout=1900)
        binary = source / "cpuminer"
        data = read_regular(binary)
        if not data.startswith(b"\x7fELF"):
            raise AdminError("Build did not produce a regular ELF executable.")
        libraries = needed_libraries(binary, workspace)
        run_builder([binary, "--version"], workspace, timeout=60)
        fedora = platform.freedesktop_os_release()
        metadata = {"upstream_version": UPSTREAM_VERSION, "revision": revision,
                    "sha256": hashlib.sha256(data).hexdigest(), "patch_sha256": patch_digest(),
                    "control_digest": bundle_digest(), "installed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "fedora_release": fedora.get("PRETTY_NAME", "Fedora"), "fedora_version": fedora.get("VERSION_ID"),
                    "architecture": platform.machine(),
                    "compiler": run_builder(["gcc", "-dumpfullversion", "-dumpversion"],
                                            workspace, 60, capture=True).stdout.strip(),
                    "linked_libraries": libraries}
        yield data, metadata

def install_bundle():
    release = LIB_ROOT / bundle_digest()
    secure_dir(release)
    for path in bundle_files():
        atomic_write(release / path.relative_to(SOURCE_ROOT), read_regular(path))
    wrapper = ("#!/usr/bin/python3\nimport sys\nsys.path.insert(0, " + repr(str(release)) + ")\n"
               "from solominer.cli import main\nraise SystemExit(main())\n")
    atomic_write(CLI_PATH, wrapper.encode(), 0o755)

def snapshot(states=None):
    secure_dir(ADMIN_DIR, 0o700)
    backup_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    backup = ADMIN_DIR / "backups" / backup_id
    secure_dir(backup, 0o700)
    manifest = {}
    for key, path in TARGETS.items():
        if path.is_symlink():
            raise AdminError(f"Refusing symlink in activation target: {path}")
        if path.exists():
            data = read_regular(path)
            atomic_write(backup / key, data, 0o600)
            manifest[key] = hashlib.sha256(data).hexdigest()
        else:
            manifest[key] = None
    atomic_write(backup / "manifest.json", json.dumps(manifest, sort_keys=True).encode(), 0o600)
    atomic_write(backup / "states.json", json.dumps(states or {}).encode(), 0o600)
    return backup_id

def load_backup(backup_id):
    if not re.fullmatch(r"\d{8}T\d{6}Z-[a-f0-9]{8}", backup_id):
        raise AdminError("Invalid backup identifier.")
    backup = ADMIN_DIR / "backups" / backup_id
    manifest = json.loads(read_regular(backup / "manifest.json"))
    if set(manifest) != set(TARGETS):
        raise AdminError("Unexpected backup manifest entries.")
    contents = {}
    states = json.loads(read_regular(backup / "states.json"))
    if (not isinstance(states, dict) or set(states) - {SERVICE, HEALTH_TIMER}
            or any(not isinstance(value, dict) or set(value) != {"active", "enabled"} or any(type(flag) is not bool for flag in value.values())
                   for value in states.values())):
        raise AdminError("Invalid backup service states.")
    for key, digest in manifest.items():
        if digest is not None:
            data = read_regular(backup / key)
            if hashlib.sha256(data).hexdigest() != digest:
                raise AdminError(f"Backup integrity check failed: {key}")
            contents[key] = data
    for key, path in TARGETS.items():
        secure_dir(path.parent)
        if path.is_symlink():
            raise AdminError(f"Refusing symlink restore target: {path}")
    return contents, states

def restore(backup_id):
    contents, states = load_backup(backup_id)
    for key, path in TARGETS.items():
        if key in contents:
            atomic_write(path, contents[key], 0o755 if key in ("binary", "cli") else 0o644)
        else:
            path.unlink(missing_ok=True)
    return states

def is_active(unit):
    return command(["systemctl", "is-active", "--quiet", unit], capture=True, check=False).returncode == 0

def unit_states():
    return {unit: {"active": is_active(unit), "enabled": command(
        ["systemctl", "is-enabled", "--quiet", unit], capture=True, check=False).returncode == 0}
        for unit in (SERVICE, HEALTH_TIMER)}

def stop_units():
    for unit in (HEALTH_TIMER, "solominer-health.service", SERVICE):
        command(["systemctl", "stop", unit], check=False, capture=True)
    if is_active(SERVICE):
        raise AdminError("Could not stop the miner safely; installation is unchanged.")

def restore_backup(backup_id):
    load_backup(backup_id)  # Reject corruption/unsafe destinations before downtime.
    stop_units()
    # Remove links while the current units still exist, including first-install rollback.
    for unit in (SERVICE, HEALTH_TIMER):
        command(["systemctl", "disable", unit], check=False, capture=True)
    states = restore(backup_id)
    command(["systemctl", "daemon-reload"])
    for unit, flags in states.items():
        if flags["enabled"]:
            command(["systemctl", "enable", unit])
        if flags["active"]:
            command(["systemctl", "start", unit])
    if states.get(SERVICE, {}).get("active"):
        verify_started()

def verify_started():
    stable_pid = None
    for _ in range(5):
        if not is_active(SERVICE):
            raise AdminError("Miner stopped during activation; restoring prior installation.")
        pid = command(["systemctl", "show", SERVICE, "--property=MainPID", "--value"], capture=True).stdout.strip()
        if not pid.isdigit() or pid == "0" or (stable_pid is not None and pid != stable_pid):
            raise AdminError("Miner is restarting during activation; restoring prior installation.")
        stable_pid = pid
        time.sleep(1)

def write_units(config):
    for name in (SERVICE, "solominer-health.service", HEALTH_TIMER):
        atomic_write(UNIT_DIR / name, read_regular(SOURCE_ROOT / "systemd" / name))
    resources = "[Service]\n" + f"CPUQuota={config.cpu_quota}\nMemoryMax={config.memory_max}\nTasksMax={config.tasks_max}\n"
    atomic_write(RESOURCE_PATH, resources.encode())
    command(["systemd-analyze", "verify", str(UNIT_DIR / SERVICE), str(UNIT_DIR / "solominer-health.service"),
             str(UNIT_DIR / HEALTH_TIMER)])

def restore_record(path, prior):
    if prior is None:
        path.unlink(missing_ok=True)
    else:
        atomic_write(path, prior, 0o600)

def recovery_errors(steps):
    """Attempt every recovery step, including release restore after disk errors."""
    failures = []
    for label, action in steps:
        try:
            action()
        except BaseException as error:
            failures.append(f"{label}: {error}")
    return failures

def activate(data, metadata, config):
    secure_install_dir()
    expected_config = read_regular(DEFAULT_CONFIG, 65536)
    if config_from_data(expected_config) != config or read_regular(DEFAULT_CONFIG, 65536) != expected_config:
        raise AdminError("Configuration changed during the build; validate it and retry before downtime.")
    good_path = ADMIN_DIR / "last-good-config"
    backup_path = ADMIN_DIR / "last-backup"
    prior_good = read_regular(good_path, 65536) if good_path.exists() else None
    prior_backup = read_regular(backup_path, 256) if backup_path.exists() else None
    backup_id = snapshot(unit_states())
    try:
        stop_units()
        atomic_write(INSTALL_DIR / "cpuminer", data, 0o755)
        atomic_write(INSTALL_DIR / "install.json", json.dumps(metadata, indent=2).encode())
        install_bundle()
        write_units(config)
        command(["systemctl", "daemon-reload"])
        command(["systemctl", "enable", SERVICE])
        command(["systemctl", "restart", SERVICE])
        verify_started()
        command(["systemctl", "enable", "--now", HEALTH_TIMER])
        if read_regular(DEFAULT_CONFIG, 65536) != expected_config:
            raise AdminError("Configuration changed during activation; restoring prior release.")
        atomic_write(good_path, expected_config, 0o600)
        atomic_write(backup_path, backup_id.encode(), 0o600)
    except BaseException as error:
        failures = recovery_errors([
            ("release restore", lambda: restore_backup(backup_id)),
            ("configuration record restore", lambda: restore_record(good_path, prior_good)),
            ("backup pointer restore", lambda: restore_record(backup_path, prior_backup)),
        ])
        if failures:
            raise AdminError("Activation failed and recovery is incomplete: " + "; ".join(failures)) from error
        raise
    print(f"Installed patched {UPSTREAM_VERSION} ({UPSTREAM_REVISION[:12]}).")
    print("Startup was stable. Run sudo /usr/local/bin/solominer doctor for pool and sensor checks.")

def prepare_config(migrate=False):
    if not DEFAULT_CONFIG.exists():
        if migrate:
            raise AdminError("--migrate requires an existing /etc/sysconfig/btc-solo-cpu.")
        ensure_users()
        atomic_write(DEFAULT_CONFIG, read_regular(SOURCE_ROOT / "systemd" / "btc-solo-cpu.env.example"),
                     0o640, pwd.getpwnam("solominer").pw_gid)
        raise AdminError("Created /etc/sysconfig/btc-solo-cpu. Set WALLET with sudoedit, then rerun install.")
    if DEFAULT_CONFIG.is_symlink():
        raise AdminError("Refusing a symlink configuration file.")
    config = load_config(DEFAULT_CONFIG)
    ensure_users()
    original = read_regular(DEFAULT_CONFIG)
    backup = DEFAULT_CONFIG.with_name(DEFAULT_CONFIG.name + ".pre-hardening")
    if not backup.exists():
        atomic_write(backup, original, 0o600)
    atomic_write(DEFAULT_CONFIG, original, 0o640, pwd.getpwnam("solominer").pw_gid)
    return config

def install_or_update(args):
    require_host()
    with update_lock():
        if args.install_deps:
            command(["dnf", "-y", "install", *DEPS], timeout=1800)
        if args.update_packages:
            command(["dnf", "-y", "upgrade", "--refresh"], timeout=3600)
        require_commands()
        config = prepare_config(getattr(args, "migrate", False))
        secure_dir(ADMIN_DIR, 0o700)
        if getattr(args, "activate_staged", False):
            data = read_regular(ADMIN_DIR / "staged" / "cpuminer")
            metadata = json.loads(read_regular(ADMIN_DIR / "staged" / "install.json"))
            if (metadata.get("sha256") != hashlib.sha256(data).hexdigest()
                    or metadata.get("revision") != UPSTREAM_REVISION
                    or metadata.get("patch_sha256") != patch_digest()
                    or metadata.get("control_digest") != bundle_digest()):
                raise AdminError("Staged build does not match this checkout; rebuild before activation.")
            activate(data, metadata, config)
            return
        with built_candidate() as (data, metadata):
            if args.no_restart:
                atomic_write(ADMIN_DIR / "staged" / "cpuminer", data, 0o600)
                atomic_write(ADMIN_DIR / "staged" / "install.json", json.dumps(metadata).encode(), 0o600)
                print("Staged verified build without changing the active binary or unit.")
                print("Activate: sudo bash scripts/update-solominer.sh --activate-staged")
            else:
                activate(data, metadata, config)

def rollback():
    require_host()
    with update_lock():
        secure_install_dir()
        backup_id = read_regular(ADMIN_DIR / "last-backup").decode().strip()
        current = snapshot(unit_states())
        try:
            restore_backup(backup_id)
        except BaseException:
            restore_backup(current)
            raise
        atomic_write(ADMIN_DIR / "last-backup", current.encode(), 0o600)
        print(f"Restored backup {backup_id}; wallet configuration was preserved.")

def apply_config(source=None):
    """Apply a candidate atomically and restore the last working config on failure."""
    require_host()
    with update_lock():
        secure_dir(ADMIN_DIR, 0o700)
        if not DEFAULT_CONFIG.exists() or DEFAULT_CONFIG.is_symlink():
            raise AdminError("A regular /etc/sysconfig/btc-solo-cpu must exist before applying settings.")
        previous_good_path = ADMIN_DIR / "last-good-config"
        previous_good = (read_regular(previous_good_path, 65536)
                         if previous_good_path.exists() else None)
        source_path = Path(source) if source is not None else DEFAULT_CONFIG
        if not source_path.is_absolute():
            raise AdminError("Candidate configuration path must be absolute.")
        candidate = read_regular(source_path, 65536)
        try:
            config = config_from_data(candidate)
        except ConfigError:
            if source is None and previous_good is not None:
                config_from_data(previous_good)
                rejected = ADMIN_DIR / ("rejected-config-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                                        + "-" + uuid.uuid4().hex[:8])
                atomic_write(rejected, candidate, 0o600)
                ensure_users()
                atomic_write(DEFAULT_CONFIG, previous_good, 0o640, pwd.getpwnam("solominer").pw_gid)
                if command(["systemctl", "is-failed", "--quiet", SERVICE],
                           check=False, capture=True).returncode == 0:
                    try:
                        command(["systemctl", "restart", SERVICE])
                        verify_started()
                    except BaseException as error:
                        raise AdminError(f"Restored last working configuration, but the failed service did not recover; rejected edit saved at {rejected}. Inspect its journal.") from error
                raise AdminError(f"Invalid live configuration restored from last known good; rejected edit saved at {rejected}.")
            raise
        if source is None and previous_good is None:
            raise AdminError("No last-known-good configuration is recorded. Run update first or use apply-config --from /absolute/candidate.")
        ensure_users()
        current = read_regular(DEFAULT_CONFIG, 65536)
        if previous_good is None:
            if source_path == DEFAULT_CONFIG:
                raise AdminError("No last-known-good configuration is recorded; provide a separate candidate file.")
            config_from_data(current)
        else:
            config_from_data(previous_good)
        rollback_config = previous_good if previous_good is not None else current
        backup_path = ADMIN_DIR / "last-backup"
        prior_backup = read_regular(backup_path, 256) if backup_path.exists() else None
        states = unit_states()
        backup_id = snapshot(states)
        if read_regular(DEFAULT_CONFIG, 65536) != current:
            raise AdminError("Live configuration changed during validation; retry without concurrent edits.")
        try:
            stop_units()
            if read_regular(DEFAULT_CONFIG, 65536) != current:
                raise AdminError("Live configuration changed during activation; restoring previous release.")
            atomic_write(DEFAULT_CONFIG, candidate, 0o640, pwd.getpwnam("solominer").pw_gid)
            write_units(config)
            command(["systemctl", "daemon-reload"])
            command(["systemctl", "restart", SERVICE])
            verify_started()
            if states[HEALTH_TIMER]["active"]:
                command(["systemctl", "start", HEALTH_TIMER])
            if read_regular(DEFAULT_CONFIG, 65536) != candidate:
                raise AdminError("Live configuration changed during startup; preserving that edit and restoring the previous release.")
            atomic_write(previous_good_path, candidate, 0o600)
            atomic_write(backup_path, backup_id.encode(), 0o600)
        except BaseException as error:
            failures = []
            try:
                live = read_regular(DEFAULT_CONFIG, 65536)
            except BaseException as read_error:
                failures.append(f"configuration inspection: {read_error}")
                live = None
            steps = []
            if live == candidate and live != rollback_config:
                steps.append(("configuration restore", lambda: atomic_write(
                    DEFAULT_CONFIG, rollback_config, 0o640, pwd.getpwnam("solominer").pw_gid)))
            steps.extend([
                ("release restore", lambda: restore_backup(backup_id)),
                ("configuration record restore", lambda: restore_record(previous_good_path, previous_good)),
                ("backup pointer restore", lambda: restore_record(backup_path, prior_backup)),
            ])
            failures.extend(recovery_errors(steps))
            if failures:
                raise AdminError("Configuration activation failed and recovery is incomplete: "
                                 + "; ".join(failures)) from error
            raise
        print("Validated configuration and resource limits applied; startup was stable.")
