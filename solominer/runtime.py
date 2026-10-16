"""Unprivileged miner execution, host diagnostics and stateful local health alerts."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any

from .config import ConfigError, DEFAULT_BINARY, DEFAULT_CONFIG, load_config

SERVICE = 'btc-solo-cpu.service'
DEFAULT_STATE = Path('/var/lib/solominer-health/state.json')
CPU_SENSORS = {'coretemp', 'k10temp', 'k8temp', 'zenpower', 'cpu_thermal', 'x86_pkg_temp'}


def _command(args: list[str], timeout: float = 5, limit: int = 262144) -> tuple[int, str]:
    """Bound command duration and output; never invoke a shell."""
    process = None
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            output = bytearray()
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 124, 'Command timed out.'
                for key, _ in selector.select(min(remaining, 0.2)):
                    block = os.read(key.fileobj.fileno(), min(65536, limit - len(output) + 1))
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(block)
                    if len(output) > limit:
                        return 125, 'Command output exceeded the safety limit.'
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return process.returncode, output.decode('utf-8', errors='replace').strip()
    except subprocess.TimeoutExpired:
        return 124, 'Command timed out.'
    except OSError as exc:
        return 127, f'Command unavailable: {exc}'
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdout is not None:
                process.stdout.close()


def immutable_binary(binary: Path | str = DEFAULT_BINARY) -> tuple[bool, str]:
    """Require an installed regular root-owned executable and immutable ancestors."""
    binary = Path(binary)
    if not binary.is_absolute():
        return False, 'Miner executable must use an absolute path.'
    try:
        for ancestor in [binary, *binary.parents]:
            info = ancestor.lstat()
            if stat.S_ISLNK(info.st_mode):
                return False, f'{ancestor} must not be a symbolic link.'
            if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False, f'{ancestor} must be root-owned and not writable by group or others.'
            if ancestor == binary and (not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR):
                return False, f'{binary} must be a regular executable file.'
            if ancestor != binary and not stat.S_ISDIR(info.st_mode):
                return False, f'{ancestor} must be a directory.'
    except OSError as exc:
        return False, f'Cannot inspect miner executable: {exc}'
    return True, 'Miner and installation path are root-owned and not writable by the service.'


def immutable_config(path: Path | str = DEFAULT_CONFIG) -> tuple[bool, str]:
    path = Path(path)
    try:
        info = path.lstat()
        if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return False, 'Configuration must be an absolute regular root-owned file, without group or other write permissions.'
        for parent in path.parents:
            ancestor = parent.lstat()
            if not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid != 0 or ancestor.st_mode & 0o022:
                return False, f'Configuration directory {parent} must be root-owned and not writable by group or others.'
    except OSError as exc:
        return False, f'Cannot inspect configuration permissions: {exc}'
    return True, 'Configuration is root-owned and read-only to the service.'


def installation(binary: Path | str = DEFAULT_BINARY) -> dict[str, Any]:
    binary = Path(binary)
    metadata = binary.parent / 'install.json'
    try:
        info = metadata.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
            return {'verified': False, 'error': 'Installation metadata must be a small root-owned regular file without group/other write permission.'}
        data = json.loads(metadata.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not re.fullmatch(r'[a-f0-9]{64}', str(data.get('sha256', ''))):
            return {'verified': False, 'error': 'Installation metadata has no valid SHA-256 digest.'}
        digest = hashlib.sha256()
        with binary.open('rb') as source:
            for block in iter(lambda: source.read(1048576), b''):
                digest.update(block)
        data['verified'] = digest.hexdigest() == data['sha256']
        if not data['verified']:
            data['error'] = 'Installed binary does not match its recorded SHA-256 digest.'
        return data
    except (OSError, UnicodeError, ValueError) as exc:
        return {'verified': False, 'error': f'Cannot verify installation metadata: {exc}'}


def run_miner(config_path: Path | str = DEFAULT_CONFIG, binary: Path | str = DEFAULT_BINARY) -> None:
    config = load_config(config_path)
    for check, target in ((immutable_config, config_path), (immutable_binary, binary)):
        ok, message = check(target)
        if not ok:
            raise ConfigError(message)
    metadata = installation(binary)
    if not metadata['verified']:
        raise ConfigError(str(metadata['error']))
    # Argument arrays avoid environment expansion and option injection.
    if config.fallback_pools:
        _supervise(config, binary)
    else:
        os.execv(str(binary), config.miner_args(binary))


def _supervise(config: Any, binary: Path | str) -> None:
    """Rotate only administrator-configured pools after bounded retry exhaustion.

    cpuminer returns zero on Stratum retry exhaustion, so every unrequested exit
    is treated as a failure. A requested service stop always stops the child.
    """
    stopped = threading.Event()
    child = None

    def stop(_signum: int, _frame: Any) -> None:
        stopped.set()
        if child is not None and child.poll() is None:
            child.terminate()

    originals = {number: signal.signal(number, stop) for number in (signal.SIGTERM, signal.SIGINT)}
    pools = (config.pool, *config.fallback_pools)
    index = 0
    try:
        while not stopped.is_set():
            current = replace(config, pool=pools[index])
            child = subprocess.Popen(current.miner_args(binary) + ['--retries=3'])
            if stopped.is_set():
                child.terminate()
            while child.poll() is None:
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    if stopped.is_set():
                        try:
                            child.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                        break
            if stopped.is_set():
                break
            next_index = (index + 1) % len(pools)
            print(json.dumps({'event': 'pool_failover', 'message': 'Stratum connection failed: miner exited; rotating configured pool after cooldown.',
                              'previous_pool': pools[index], 'next_pool': pools[next_index],
                              'exit_code': child.returncode, 'cooldown_seconds': max(30, config.retry_pause)}), flush=True)
            if stopped.wait(max(30, config.retry_pause)):
                break
            index = next_index
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for number, handler in originals.items():
            signal.signal(number, handler)


def temperatures(sysfs: Path | str = '/sys') -> list[dict[str, Any]]:
    """Read CPU/package sensors only; unrelated GPU values do not trigger alerts."""
    root = Path(sysfs)
    readings: list[dict[str, Any]] = []
    for hwmon in sorted((root / 'class/hwmon').glob('hwmon*'))[:64]:
        try:
            name = (hwmon / 'name').read_text()[:64].strip()
        except OSError:
            continue
        if name not in CPU_SENSORS:
            continue
        for sensor in sorted(hwmon.glob('temp*_input'))[:64]:
            try:
                celsius = int(sensor.read_text()[:16].strip()) / 1000
                label_file = sensor.with_name(sensor.name.replace('_input', '_label'))
                label = label_file.read_text()[:80].strip() if label_file.exists() else sensor.stem
                if 0 < celsius <= 150:
                    readings.append({'sensor': name, 'label': label, 'celsius': celsius, 'source': 'hwmon'})
            except (OSError, ValueError):
                continue
    for thermal in sorted((root / 'class/thermal').glob('thermal_zone*'))[:64]:
        try:
            name = (thermal / 'type').read_text()[:64].strip()
            if name not in CPU_SENSORS:
                continue
            celsius = int((thermal / 'temp').read_text()[:16].strip()) / 1000
            if 0 < celsius <= 150:
                readings.append({'sensor': name, 'label': thermal.name, 'celsius': celsius, 'source': 'thermal_zone'})
        except (OSError, ValueError):
            continue
    return readings


def service_state() -> dict[str, str]:
    properties = ['ActiveState', 'SubState', 'Result', 'NRestarts', 'MainPID', 'CPUUsageNSec',
                  'MemoryCurrent', 'TasksCurrent', 'CPUQuotaPerSecUSec', 'MemoryMax', 'TasksMax']
    code, output = _command(['systemctl', 'show', SERVICE, '--no-pager', '--property=' + ','.join(properties)])
    if code:
        return {'error': output[:1000]}
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def report(config_path: Path | str = DEFAULT_CONFIG, binary: Path | str = DEFAULT_BINARY) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    result: dict[str, Any] = {'service': service_state(), 'checks': checks, 'temperatures': temperatures()}
    try:
        config = load_config(config_path)
        result['configuration'] = asdict(config)
        result['configuration']['wallet'] = config.wallet[:6] + '…' + config.wallet[-6:]
        checks.append({'name': 'configuration', 'ok': True, 'severity': 'error', 'message': 'Configuration values are valid.'})
        plaintext = any(pool.startswith('stratum+tcp:') for pool in (config.pool, *config.fallback_pools))
        checks.append({'name': 'pool_transport', 'ok': not plaintext, 'severity': 'warning',
                       'message': 'Plaintext Stratum exposes pool traffic to network interception; use verified TLS if your pool supports it.'
                       if plaintext else 'Stratum uses certificate-verified TLS in the managed patched build.'})
        checks.append({'name': 'pool_redirects', 'ok': config.no_redirect, 'severity': 'warning',
                       'message': 'Pool redirect requests are blocked.' if config.no_redirect else 'Pool redirect requests are enabled; a server can change the destination.'})
        effective = result['service']
        if 'error' not in effective:
            memory_match = re.fullmatch(r'([0-9]+)([MG])', config.memory_max)
            assert memory_match is not None
            memory_bytes = int(memory_match[1]) * 1024 ** (2 if memory_match[2] == 'M' else 3)
            quota_match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(us|ms|s)', effective.get('CPUQuotaPerSecUSec', ''))
            quota_percent = None
            if quota_match:
                quota_percent = float(quota_match[1]) * {'us': 0.0001, 'ms': 0.1, 's': 100}[quota_match[2]]
            limits_match = (effective.get('MemoryMax') == str(memory_bytes)
                            and effective.get('TasksMax') == str(config.tasks_max)
                            and quota_percent is not None
                            and abs(quota_percent - float(config.cpu_quota[:-1])) < 0.01)
            checks.append({'name': 'resource_limits', 'ok': limits_match, 'severity': 'warning',
                           'message': 'Active systemd resource limits match configuration.' if limits_match else
                           'Active systemd limits differ from configuration; run sudo solominer apply-config to regenerate the managed drop-in and restart.'})

    except ConfigError as exc:
        checks.append({'name': 'configuration', 'ok': False, 'severity': 'error', 'message': str(exc)})
    for name, checker, target in [('configuration_permissions', immutable_config, config_path), ('binary_permissions', immutable_binary, binary)]:
        ok, message = checker(target)
        checks.append({'name': name, 'ok': ok, 'severity': 'error', 'message': message})
    if checks[-1]['ok']:
        result['installation'] = installation(binary)
        valid = bool(result['installation']['verified'])
        checks.append({'name': 'binary_integrity', 'ok': valid, 'severity': 'error',
                       'message': 'Binary matches the recorded installation digest.' if valid else result['installation']['error']})
        if valid:
            result['version'] = result['installation'].get('upstream_version', 'unknown')
    service = result['service']
    running = service.get('ActiveState') == 'active' and service.get('SubState') == 'running'
    checks.append({'name': 'service', 'ok': running, 'severity': 'error',
                   'message': 'Miner service is running.' if running else service.get('error', 'Miner service is not running; inspect journalctl -u btc-solo-cpu.service.')})
    checks.append({'name': 'cpu_temperature', 'ok': any(reading['source'] == 'hwmon' for reading in result['temperatures']), 'severity': 'warning',
                   'message': 'CPU temperature sensors are readable.' if any(reading['source'] == 'hwmon' for reading in result['temperatures']) else 'No readable CPU hwmon temperature sensors. Thermal cutoff cannot be relied on; inspect lm_sensors and kernel sensor drivers.'})
    result['ok'] = not any(not check['ok'] and check['severity'] == 'error' for check in checks)
    return result


def _read_state(state_path: Path) -> dict[str, Any]:
    try:
        info = state_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            return {}
        value = json.loads(state_path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def _save_state(state_path: Path, state: dict[str, Any]) -> None:
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.state-', dir=state_path.parent)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(state, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, state_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _journal(since: float) -> tuple[list[tuple[float, str]], str | None]:
    code, output = _command(['journalctl', '--unit=' + SERVICE, '--since=@' + str(int(since)),
                             '--lines=300', '--output=json', '--no-pager', '--quiet'])
    if code:
        return [], output[:1000]
    entries = []
    for line in output.splitlines():
        try:
            record = json.loads(line)
            message = record.get('MESSAGE')
            timestamp = float(record['__REALTIME_TIMESTAMP']) / 1000000
            if isinstance(message, str):
                entries.append((timestamp, message[:4096]))
        except (ValueError, TypeError, KeyError):
            continue
    return sorted(entries), None


_FAILURE = re.compile(r'(stratum.*(?:failed|timeout|timed out|disconnect|interrupted)|connection.*(?:refused|failed|reset)|SSL connect error|certificate.*(?:verification|verify|validation).*failed)', re.I)
_SUCCESS = re.compile(r'(stratum.*(?:connected|difficulty|new job)|new (?:work|block|job)|accepted(?:\s*[:(]|\s+share))', re.I)
_REJECT = re.compile(r'(?:rejected|invalid share|unauthorized|authentication failed)', re.I)


def health_check(state_path: Path | str = DEFAULT_STATE, config_path: Path | str = DEFAULT_CONFIG,
                 binary: Path | str = DEFAULT_BINARY) -> dict[str, Any]:
    """Track process, connection failures, heat and crash loops; silence repeats.

    No accepted-share deadline is used: solo miners can hash successfully for a
    long time without ever submitting a winning share. Alerts stay local to the
    journal; no wallet, logs or machine data leave the host.
    """
    now = time.time()
    state_path = Path(state_path)
    previous = _read_state(state_path)
    diagnostics = report(config_path, binary)
    issues: dict[str, str] = {}
    for check in diagnostics['checks']:
        if not check['ok'] and check['name'] not in ('pool_transport', 'pool_redirects', 'version_command'):
            issues[check['name']] = check['message']
    try:
        config = load_config(config_path)
        timeout = config.health_timeout
    except ConfigError:
        config = None
        timeout = 900
    readings = diagnostics['temperatures']
    if config and readings and max(sensor['celsius'] for sensor in readings) >= config.max_temp:
        issues['overheating'] = f'CPU temperature reached the configured {config.max_temp}°C limit; mining should pause until it cools.'
    service = diagnostics['service']
    try:
        restarts = int(service.get('NRestarts', '0'))
        old_restarts = int(previous.get('restarts', restarts))
    except (TypeError, ValueError):
        restarts = old_restarts = 0
    if restarts - old_restarts >= 3 or (service.get('SubState') == 'auto-restart' and restarts >= 3):
        issues['crash_loop'] = 'Miner restarted repeatedly; inspect the service journal before continuing.'
    last_check = previous.get('checked_at', now - timeout)
    if not isinstance(last_check, (int, float)) or not now - 86400 <= last_check <= now:
        last_check = now - timeout
    # Overlap by a second to avoid skipping boundary journal entries.
    entries, journal_error = _journal(max(now - 86400, last_check - 1))
    disconnected = previous.get('disconnected_since')
    if not isinstance(disconnected, (int, float)) or not now - 604800 <= disconnected <= now:
        disconnected = None
    rejects = 0
    for timestamp, message in entries:
        if _SUCCESS.search(message) and not _FAILURE.search(message):
            disconnected = None
        elif _FAILURE.search(message):
            disconnected = disconnected if disconnected is not None else timestamp
        if _REJECT.search(message):
            rejects += 1
    if journal_error:
        issues['journal_access'] = 'Health monitor cannot read miner logs: ' + journal_error
    if disconnected is not None and now - disconnected >= timeout and service.get('ActiveState') == 'active':
        issues['pool_connection'] = f'Pool connection errors have persisted for at least {timeout} seconds with no subsequent connection/work message.'
    if rejects >= 5:
        issues['pool_rejections'] = 'Pool repeatedly rejected work or authentication; verify wallet, worker and pool compatibility in the miner journal.'
    old_issues = previous.get('issues', {})
    if not isinstance(old_issues, dict):
        old_issues = {}
    events = ([{'event': 'alert', 'issue': name, 'message': message} for name, message in sorted(issues.items()) if name not in old_issues]
              + [{'event': 'recovered', 'issue': name, 'message': 'Condition cleared.'} for name in sorted(old_issues) if name not in issues])
    state = {'checked_at': now, 'restarts': restarts, 'disconnected_since': disconnected, 'issues': issues}
    _save_state(state_path, state)
    return {'ok': not issues, 'changed': bool(events), 'events': events, 'issues': issues,
            'checked_at': now, 'service': service.get('ActiveState', 'unknown')}
