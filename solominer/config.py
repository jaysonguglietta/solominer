"""Strict, non-executing parser for SoloMiner's systemd environment file."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

DEFAULT_CONFIG = Path('/etc/sysconfig/btc-solo-cpu')
DEFAULT_BINARY = Path('/opt/cpuminer-opt/cpuminer')


class ConfigError(ValueError):
    """A configuration error safe to show to the administrator."""


def _bitcoin_address(address: str) -> bool:
    """Verify a mainnet Base58Check or BIP173/BIP350 witness address."""
    if not isinstance(address, str) or not 14 <= len(address) <= 90:
        return False
    if address.startswith(('1', '3')):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        value = 0
        try:
            for char in address:
                value = value * 58 + alphabet.index(char)
        except ValueError:
            return False
        payload = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        payload = b'\x00' * (len(address) - len(address.lstrip('1'))) + payload
        return (len(payload) == 25 and payload[0] in (0, 5)
                and hashlib.sha256(hashlib.sha256(payload[:-4]).digest()).digest()[:4] == payload[-4:])
    if address.lower() != address and address.upper() != address:
        return False
    address = address.lower()
    if not address.startswith('bc1'):
        return False
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    try:
        data = [alphabet.index(char) for char in address[3:]]
    except ValueError:
        return False
    if len(data) < 7:
        return False
    checksum = 1
    for value in [3, 3, 0, 2, 3] + data:  # HRP expansion for "bc".
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for index, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> index) & 1:
                checksum ^= generator
    version = data[0]
    if version > 16 or checksum != (1 if version == 0 else 0x2bc830a3):
        return False
    accumulator = bits = 0
    program = bytearray()
    for value in data[1:-6]:
        accumulator = (accumulator << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            program.append((accumulator >> bits) & 255)
    if bits >= 5 or ((accumulator << (8 - bits)) & 255):
        return False
    return 2 <= len(program) <= 40 and (version != 0 or len(program) in (20, 32))


def _integer(value: str, name: str, minimum: int, maximum: int) -> int:
    if not re.fullmatch(r'[0-9]+', value):
        raise ConfigError(f'{name} must be an integer from {minimum} to {maximum}.')
    number = int(value)
    if not minimum <= number <= maximum:
        raise ConfigError(f'{name} must be an integer from {minimum} to {maximum}.')
    return number


def _boolean(value: str, name: str) -> bool:
    if value.lower() in ('1', 'true', 'yes'):
        return True
    if value.lower() in ('0', 'false', 'no'):
        return False
    raise ConfigError(f'{name} must be true or false.')


def validate_pool(pool: str, allow_insecure: bool = True) -> str:
    """Constrain destination syntax; DNS/IP reachability is deliberately not guessed."""
    try:
        parsed = urlsplit(pool)
        port = parsed.port
        hostname = parsed.hostname
    except ValueError as exc:
        raise ConfigError('POOL must be a valid Stratum URL with an explicit port.') from exc
    if parsed.scheme not in ('stratum+tcp', 'stratum+ssl', 'stratum+tcps'):
        raise ConfigError('POOL must use stratum+tcp, stratum+ssl, or stratum+tcps.')
    if parsed.scheme == 'stratum+tcp' and not allow_insecure:
        raise ConfigError('Plaintext POOL requires ALLOW_INSECURE_POOL=true; use verified TLS when your pool supports it.')
    if (not hostname or parsed.username is not None or parsed.password is not None
            or port is None or not 1 <= port <= 65535 or parsed.path not in ('', '/')
            or parsed.query or parsed.fragment or any(ord(char) < 33 for char in pool)):
        raise ConfigError('POOL requires a hostname and port, with no credentials, query, fragment, or extra path.')
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_host = hostname.encode('idna').decode('ascii')
        except UnicodeError as exc:
            raise ConfigError('POOL hostname is invalid.') from exc
        if len(ascii_host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                             for label in ascii_host.rstrip('.').split('.')):
            raise ConfigError('POOL hostname is invalid.')
    return pool


@dataclass(frozen=True)
class Config:
    pool: str
    wallet: str
    worker: str
    threads: int
    max_temp: int = 75
    cpu_quota: str = '100%'
    memory_max: str = '256M'
    tasks_max: int = 64
    no_redirect: bool = True
    retry_pause: int = 30
    health_timeout: int = 900
    allow_insecure_pool: bool = True
    fallback_pools: tuple[str, ...] = ()

    def miner_args(self, binary: str | Path = DEFAULT_BINARY) -> list[str]:
        args = [str(binary), '-a', 'sha256d', '-o', self.pool, '-u', f'{self.wallet}.{self.worker}',
                '-p', 'x', '-t', str(self.threads), f'--max-temp={self.max_temp}',
                '--no-color', f'--retry-pause={self.retry_pause}']
        if self.no_redirect:
            args.append('--no-redirect')
        return args


def load_config(path: Path | str = DEFAULT_CONFIG) -> Config:
    """Read a small assignment-only EnvironmentFile without sourcing or expansion.

    Values may be single/double quoted. Multiline assignments, substitutions,
    duplicate names and unknown names are rejected, so mistakes fail closed.
    """
    path = Path(path)
    try:
        with path.open('r', encoding='utf-8') as source:
            contents = source.read(65537)
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f'Cannot read configuration {path}: {exc}') from exc
    if len(contents) > 65536:
        raise ConfigError('Configuration is larger than 64 KiB.')
    allowed = {'POOL', 'WALLET', 'WORKER', 'THREADS', 'MAX_TEMP', 'CPU_QUOTA', 'MEMORY_MAX',
               'TASKS_MAX', 'NO_REDIRECT', 'RETRY_PAUSE', 'HEALTH_TIMEOUT', 'ALLOW_INSECURE_POOL', 'FALLBACK_POOLS'}
    values: dict[str, str] = {}
    for lineno, line in enumerate(contents.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line)
        if not match:
            raise ConfigError(f'Configuration line {lineno}: expected NAME=value.')
        name, value = match.groups()
        if name not in allowed:
            raise ConfigError(f'Configuration line {lineno}: unknown setting {name}.')
        if name in values:
            raise ConfigError(f'Configuration line {lineno}: duplicate setting {name}.')
        if name == 'FALLBACK_POOLS' and not value:
            values[name] = ''
            continue
        try:
            parsed = shlex.split(value, comments=False, posix=True)
        except ValueError as exc:
            raise ConfigError(f'Configuration line {lineno}: invalid quoting.') from exc
        if len(parsed) != 1 or any(ord(char) < 32 for char in parsed[0]):
            raise ConfigError(f'Configuration line {lineno}: expected one nonempty value.')
        values[name] = parsed[0]
    for required in ('POOL', 'WALLET', 'WORKER', 'THREADS'):
        if required not in values:
            raise ConfigError(f'Missing {required} in {path}.')
    allow_insecure = _boolean(values.get('ALLOW_INSECURE_POOL', 'true'), 'ALLOW_INSECURE_POOL')
    validate_pool(values['POOL'], allow_insecure)
    fallback_pools = tuple(values.get('FALLBACK_POOLS', '').split(',')) if values.get('FALLBACK_POOLS') else ()
    if len(fallback_pools) > 3 or len(set((values['POOL'], *fallback_pools))) != 1 + len(fallback_pools):
        raise ConfigError('FALLBACK_POOLS must contain at most three unique URLs different from POOL.')
    for fallback in fallback_pools:
        validate_pool(fallback, allow_insecure)
    if not _bitcoin_address(values['WALLET']):
        raise ConfigError('WALLET must be a checksum-valid mainnet Bitcoin receive address.')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', values['WORKER']):
        raise ConfigError('WORKER must contain 1–64 letters, digits, underscores, or hyphens.')
    logical_cpus = os.cpu_count() or 1
    threads = _integer(values['THREADS'], 'THREADS', 1, logical_cpus)
    max_temp = _integer(values.get('MAX_TEMP', '75'), 'MAX_TEMP', 45, 100)
    cpu_quota = values.get('CPU_QUOTA', '100%')
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]{1,2})?%', cpu_quota):
        raise ConfigError('CPU_QUOTA must be a percentage such as 100% (one logical CPU).')
    try:
        quota = Decimal(cpu_quota[:-1])
    except InvalidOperation as exc:
        raise ConfigError('CPU_QUOTA is invalid.') from exc
    if not Decimal(1) <= quota <= logical_cpus * 100:
        raise ConfigError(f'CPU_QUOTA must be between 1% and {logical_cpus * 100}%.')
    memory_max = values.get('MEMORY_MAX', '256M')
    memory_match = re.fullmatch(r'([0-9]+)([MG])', memory_max)
    if not memory_match:
        raise ConfigError('MEMORY_MAX must use M or G, for example 256M or 1G.')
    memory_bytes = int(memory_match[1]) * (1024 ** (2 if memory_match[2] == 'M' else 3))
    if not 64 * 1024**2 <= memory_bytes <= 64 * 1024**3:
        raise ConfigError('MEMORY_MAX must be between 64M and 64G.')
    return Config(values['POOL'], values['WALLET'], values['WORKER'], threads, max_temp, cpu_quota,
                  memory_max, _integer(values.get('TASKS_MAX', '64'), 'TASKS_MAX', 16, 4096),
                  _boolean(values.get('NO_REDIRECT', 'true'), 'NO_REDIRECT'),
                  _integer(values.get('RETRY_PAUSE', '30'), 'RETRY_PAUSE', 5, 600),
                  _integer(values.get('HEALTH_TIMEOUT', '900'), 'HEALTH_TIMEOUT', 120, 86400),
                  allow_insecure, fallback_pools)
