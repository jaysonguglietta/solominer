"""Offline security and behavior checks; never connect to a mining pool."""
from contextlib import ExitStack
from dataclasses import replace
import io
import json
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from solominer.config import ConfigError, _bitcoin_address, load_config
from solominer import runtime

WALLET = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'settings'

    def load(self, extra='', **changes):
        values = dict(POOL='stratum+tcp://pool.example.org:3333', WALLET=WALLET, WORKER='fedora1',
                      THREADS='2', ALLOW_INSECURE_POOL='true')
        values.update(changes)
        self.path.write_text(''.join(f'{key}={value}\n' for key, value in values.items()) + extra)
        with patch('solominer.config.os.cpu_count', return_value=4):
            return load_config(self.path)

    def test_legacy_values_preserved_with_conservative_defaults(self):
        config = self.load()
        self.assertEqual((config.wallet, config.worker, config.threads), (WALLET, 'fedora1', 2))
        self.assertEqual((config.cpu_quota, config.max_temp, config.no_redirect), ('100%', 75, True))
        self.assertEqual(config.fallback_pools, ())

    def test_bitcoin_checksums_and_network(self):
        # Official witness vectors: bitcoin/bips BIP173 and BIP350.
        valid = [WALLET, '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
                 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
                 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3',
                 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
                 'BC1SW50QGDZ25J', 'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs']
        invalid = [WALLET[:-1] + 'X', 'bc1qreplace_with_your_wallet_address',
                   'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
                   'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
                   'bC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                   'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
                   'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
                   'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
                   'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P']
        for address in valid:
            with self.subTest(address=address):
                self.assertTrue(_bitcoin_address(address))
        for address in invalid:
            with self.subTest(address=address):
                self.assertFalse(_bitcoin_address(address))

    def test_no_shell_evaluation_or_option_injection(self):
        marker = Path(self.directory.name) / 'executed'
        with self.assertRaises(ConfigError):
            self.load(WORKER=f'"$(touch {marker})"')
        self.assertFalse(marker.exists())
        for worker in ('--url=attacker', 'worker.one', 'worker;id', '`id`'):
            with self.subTest(worker=worker), self.assertRaises(ConfigError):
                self.load(WORKER=worker)
        for extra in ('THREADS=1\n', 'UNKNOWN=1\n', 'export THREADS=1\n'):
            with self.subTest(extra=extra), self.assertRaises(ConfigError):
                self.load(extra)

    def test_quoted_values_and_ipv6(self):
        config = self.load(POOL='"stratum+ssl://[::1]:3333"', THREADS='1')
        self.assertEqual(config.pool, 'stratum+ssl://[::1]:3333')
        self.assertIn('--max-temp=75', config.miner_args('/opt/cpuminer-opt/cpuminer'))
        self.assertIn('--no-color', config.miner_args())
        self.assertIn('--no-redirect', config.miner_args())
        self.assertIn('--retry-pause=30', config.miner_args())
        self.assertEqual(config.miner_args()[config.miner_args().index('-u') + 1], WALLET + '.fedora1')

    def test_pool_validation_and_no_silent_transport_downgrade(self):
        for pool in ('https://example.org:443', 'stratum+tcp://user:pass@pool.org:3333',
                     'stratum+tcp://pool.org', 'stratum+tcp://pool.org:3333/path',
                     'stratum+tcp://pool.org:3333?x=1', 'stratum+tcp://pool.org:99999',
                     'stratum+tcp://bad_host:3333', 'stratum+tcp://pool.org:3333#fragment'):
            with self.subTest(pool=pool), self.assertRaises(ConfigError):
                self.load(POOL=pool)
        with self.assertRaises(ConfigError):
            self.load(ALLOW_INSECURE_POOL='false')
        with self.assertRaises(ConfigError):
            self.load('FALLBACK_POOLS=stratum+tcp://other.org:3333\n', POOL='stratum+ssl://pool.org:3333', ALLOW_INSECURE_POOL='false')
        self.assertFalse(self.load(POOL='stratum+ssl://pool.org:3333', ALLOW_INSECURE_POOL='false').allow_insecure_pool)

    def test_plaintext_requires_explicit_opt_in(self):
        self.path.write_text(f'POOL=stratum+tcp://pool.example.org:3333\nWALLET={WALLET}\nWORKER=fedora1\nTHREADS=2\n')
        with self.assertRaisesRegex(ConfigError, 'ALLOW_INSECURE_POOL=true'):
            load_config(self.path)

    def test_resource_limits_validate_before_systemd_write(self):
        for extra in ('MAX_TEMP=101\n', 'MAX_TEMP=44\n', 'CPU_QUOTA=401%\n', 'CPU_QUOTA=0%\n',
                      'CPU_QUOTA=infinity\n', 'MEMORY_MAX=infinity\n', 'MEMORY_MAX=32M\n',
                      'TASKS_MAX=1\n', 'NO_REDIRECT=maybe\n', 'RETRY_PAUSE=0\n', 'HEALTH_TIMEOUT=1\n'):
            with self.subTest(extra=extra), self.assertRaises(ConfigError):
                self.load(extra)
        with self.assertRaises(ConfigError):
            self.load(THREADS='5')
        config = self.load('CPU_QUOTA=150.50%\nMEMORY_MAX=1G\n')
        self.assertEqual(config.cpu_quota, '150.50%')

    def test_fallbacks_are_bounded_and_explicit(self):
        config = self.load('FALLBACK_POOLS=stratum+tcp://a.org:3333,stratum+ssl://b.org:3333\n')
        self.assertEqual(len(config.fallback_pools), 2)
        self.assertEqual(self.load('FALLBACK_POOLS=\n').fallback_pools, ())
        for urls in ('stratum+tcp://pool.example.org:3333', 'stratum+tcp://a.org:3333,stratum+tcp://a.org:3333',
                     ','.join(f'stratum+tcp://pool{number}.org:3333' for number in range(4))):
            with self.subTest(urls=urls), self.assertRaises(ConfigError):
                self.load('FALLBACK_POOLS=' + urls + '\n')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.config_path = self.path / 'config'
        self.config_path.write_text(f'POOL=stratum+tcp://pool.example.org:3333\nWALLET={WALLET}\n'
                                    'WORKER=fedora1\nTHREADS=1\nALLOW_INSECURE_POOL=true\n')
        self.config = load_config(self.config_path)

    def test_installation_permissions_include_ancestor_directories(self):
        binary = Path('/opt/cpuminer-opt/cpuminer')
        values = {path: SimpleNamespace(st_mode=(stat.S_IFREG if path == binary else stat.S_IFDIR) | 0o755,
                                       st_uid=0) for path in [binary, *binary.parents]}
        with patch.object(Path, 'lstat', autospec=True, side_effect=lambda path: values[path]):
            self.assertTrue(runtime.immutable_binary(binary)[0])
            values[binary.parent].st_mode |= stat.S_IWGRP
            self.assertFalse(runtime.immutable_binary(binary)[0])
            values[binary.parent].st_mode = stat.S_IFLNK | 0o755
            self.assertFalse(runtime.immutable_binary(binary)[0])

    def test_diagnostics_never_execute_native_miner(self):
        state = {'ActiveState': 'active', 'SubState': 'running', 'MemoryMax': str(256 * 1024**2),
                 'TasksMax': '64', 'CPUQuotaPerSecUSec': '1s', 'MemorySwapMax': '0'}
        with patch.object(runtime, 'service_state', return_value=state), \
             patch.object(runtime, 'temperatures', return_value=[]), \
             patch.object(runtime, 'immutable_config', return_value=(True, 'ok')), \
             patch.object(runtime, 'immutable_binary', return_value=(True, 'ok')), \
             patch.object(runtime, 'installation', return_value={'verified': True, 'upstream_version': 'v26.1'}), \
             patch.object(runtime, '_command') as command:
            result = runtime.report(self.config_path)
        command.assert_not_called()
        self.assertEqual(result['version'], 'v26.1')
        self.assertTrue(next(check for check in result['checks'] if check['name'] == 'resource_limits')['ok'])

    def test_bounded_commands(self):
        code, output = runtime._command([sys.executable, '-c', 'print("test")'])
        self.assertEqual((code, output), (0, 'test'))
        code, output = runtime._command([sys.executable, '-c', 'print("x" * 100000)'], limit=100)
        self.assertEqual(code, 125)
        code, output = runtime._command([sys.executable, '-c', 'import time; time.sleep(2)'], timeout=0.15)
        self.assertEqual(code, 124)
        code, output = runtime._command(['/no-such-solominer-tool'])
        self.assertEqual(code, 127)

    def test_tls_primary_does_not_hide_plaintext_fallback_warning(self):
        self.config_path.write_text(f'POOL=stratum+ssl://secure.example.org:443\nWALLET={WALLET}\n'
                                    'WORKER=fedora1\nTHREADS=1\nALLOW_INSECURE_POOL=true\n'
                                    'FALLBACK_POOLS=STRATUM+TCP://backup.example.org:3333\n')
        with patch.object(runtime, 'service_state', return_value={'error': 'fixture'}), \
             patch.object(runtime, 'temperatures', return_value=[]), \
             patch.object(runtime, 'immutable_config', return_value=(True, 'ok')), \
             patch.object(runtime, 'immutable_binary', return_value=(False, 'fixture')):
            result = runtime.report(self.config_path)
        transport = next(check for check in result['checks'] if check['name'] == 'pool_transport')
        self.assertFalse(transport['ok'])
        self.assertIn('fallback', transport['message'])

    def test_untrusted_binary_never_executes(self):
        with patch.object(runtime, 'immutable_config', return_value=(True, 'ok')), \
             patch.object(runtime, 'immutable_binary', return_value=(False, 'unsafe binary')), \
             patch.object(runtime, '_supervise') as execute:
            with self.assertRaisesRegex(ConfigError, 'unsafe binary'):
                runtime.run_miner(self.config_path, self.path / 'miner')
            execute.assert_not_called()

    def test_metadata_mismatch_never_executes(self):
        with patch.object(runtime, 'immutable_config', return_value=(True, 'ok')), \
             patch.object(runtime, 'immutable_binary', return_value=(True, 'ok')), \
             patch.object(runtime, 'installation', return_value={'verified': False, 'error': 'digest mismatch'}), \
             patch.object(runtime, '_supervise') as execute:
            with self.assertRaisesRegex(ConfigError, 'digest mismatch'):
                runtime.run_miner(self.config_path, '/opt/cpuminer-opt/cpuminer')
            execute.assert_not_called()

    def test_default_execution_uses_supervisor_even_with_one_pool(self):
        with patch.object(runtime, 'immutable_config', return_value=(True, 'ok')), \
             patch.object(runtime, 'immutable_binary', return_value=(True, 'ok')), \
             patch.object(runtime, 'installation', return_value={'verified': True}), \
             patch.object(runtime, '_supervise') as execute:
            runtime.run_miner(self.config_path, '/opt/cpuminer-opt/cpuminer')
            execute.assert_called_once_with(self.config, '/opt/cpuminer-opt/cpuminer')

    def test_root_cannot_run_miner(self):
        with patch.object(runtime.os, 'geteuid', return_value=0), \
             patch.object(runtime, '_supervise') as execute:
            with self.assertRaisesRegex(ConfigError, 'root'):
                runtime.run_miner(self.config_path)
            execute.assert_not_called()

    def test_supervisor_restarts_when_no_valid_job_arrives(self):
        miner = self.path / 'quiet-miner'
        miner.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n')
        miner.chmod(0o755)
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'No validated Stratum job'):
            runtime._supervise(replace(self.config, health_timeout=1), miner,
                               self.path / 'mining.json')
        self.assertLess(time.monotonic() - started, 4)
        state = json.loads((self.path / 'mining.json').read_text())
        self.assertIsNone(state['last_job_at'])
        self.assertEqual(state['failures'], 1)
        self.assertEqual((self.path / 'mining.json').stat().st_mode & 0o777, 0o640)

    def test_valid_job_events_keep_miner_alive_until_normal_exit(self):
        miner = self.path / 'job-miner'
        miner.write_text('#!/usr/bin/env python3\nimport os, time\n'
                         'fd = int(os.environ["SOLOMINER_EVENT_FD"])\n'
                         'for _ in range(8):\n'
                         '    os.write(fd, b"J")\n'
                         '    time.sleep(0.2)\n')
        miner.chmod(0o755)
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'exited with status 0'):
            runtime._supervise(replace(self.config, health_timeout=1), miner,
                               self.path / 'mining.json')
        self.assertGreater(time.monotonic() - started, 1)
        state = json.loads((self.path / 'mining.json').read_text())
        self.assertIsInstance(state['last_job_at'], float)
        self.assertEqual(state['failures'], 1)

    def test_temperature_enumeration_ignores_gpu(self):
        for number, name, temp in ((0, 'amdgpu', '99000'), (8, 'coretemp', '66000'), (12, 'k10temp', '72000')):
            hwmon = self.path / 'class/hwmon' / f'hwmon{number}'
            hwmon.mkdir(parents=True)
            (hwmon / 'name').write_text(name)
            (hwmon / 'temp1_input').write_text(temp)
        readings = runtime.temperatures(self.path)
        self.assertEqual(sorted(item['celsius'] for item in readings), [66.0, 72.0])

    def healthy_diagnostics(self):
        return {'checks': [], 'temperatures': [{'sensor': 'coretemp', 'celsius': 60, 'source': 'hwmon'}],
                'service': {'ActiveState': 'active', 'SubState': 'running', 'NRestarts': '0'}}

    def test_no_share_deadline_or_repeated_status_noise(self):
        state_path = self.path / 'health/state.json'
        with patch.object(runtime, 'report', return_value=self.healthy_diagnostics()):
            first = runtime.health_check(state_path, self.config_path)
            second = runtime.health_check(state_path, self.config_path)
        self.assertTrue(first['ok'])
        self.assertFalse(first['changed'])
        self.assertFalse(second['changed'])
        self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)

    def test_valid_job_alert_persists_and_recovers_once(self):
        state_path = self.path / 'state.json'
        diagnostics = self.healthy_diagnostics()
        diagnostics['checks'] = [{'name': 'job_freshness', 'ok': False, 'severity': 'error',
                                  'message': 'No validated Stratum job.'}]
        with patch.object(runtime, 'report', return_value=diagnostics), \
             patch.object(runtime.time, 'time', return_value=10000):
            first = runtime.health_check(state_path, self.config_path)
        self.assertIn('job_freshness', first['issues'])
        self.assertTrue(first['changed'])
        with patch.object(runtime, 'report', return_value=diagnostics), \
             patch.object(runtime.time, 'time', return_value=10300):
            second = runtime.health_check(state_path, self.config_path)
        self.assertFalse(second['changed'])
        diagnostics['checks'] = []
        with patch.object(runtime, 'report', return_value=diagnostics), \
             patch.object(runtime.time, 'time', return_value=10600):
            third = runtime.health_check(state_path, self.config_path)
        self.assertEqual(third['events'][0]['event'], 'recovered')
        self.assertTrue(third['ok'])

    def test_heat_and_crash_loop_alerts(self):
        state_path = self.path / 'state.json'
        state_path.write_text(json.dumps({'checked_at': 10000, 'restarts': 0, 'issues': {}}))
        diagnostics = self.healthy_diagnostics()
        diagnostics['service']['NRestarts'] = '4'
        diagnostics['temperatures'][0]['celsius'] = 80
        with patch.object(runtime, 'report', return_value=diagnostics), \
             patch.object(runtime.time, 'time', return_value=10300):
            result = runtime.health_check(state_path, self.config_path)
        self.assertIn('overheating', result['issues'])
        self.assertIn('crash_loop', result['issues'])

    def sample_cpu_health(self, now, cpu_ns='1000000000', pid='321', temperature=60, active=True,
                          stale_job=False):
        diagnostics = self.healthy_diagnostics()
        diagnostics['service'].update(CPUUsageNSec=cpu_ns, MainPID=pid,
                                      ActiveState='active' if active else 'inactive',
                                      SubState='running' if active else 'dead')
        diagnostics['temperatures'][0]['celsius'] = temperature
        if stale_job:
            diagnostics['checks'].append({'name': 'job_freshness', 'ok': False, 'severity': 'error',
                                           'message': 'No validated Stratum job.'})
        with patch.object(runtime, 'report', return_value=diagnostics), \
             patch.object(runtime.time, 'time', return_value=now):
            return runtime.health_check(self.path / 'cpu-state.json', self.config_path)

    def test_cpu_progress_warmup_and_hashing_without_shares(self):
        first = self.sample_cpu_health(10000)
        self.assertNotIn('worker_idle', first['issues'])
        for number in range(1, 5):
            result = self.sample_cpu_health(10000 + 300 * number, cpu_ns=str(1000000000 + 3000000000 * number))
            self.assertNotIn('worker_idle', result['issues'])
        state = json.loads((self.path / 'cpu-state.json').read_text())
        self.assertEqual(state['last_progress_at'], 11200)

    def test_idle_worker_alerts_once_and_cpu_progress_recovers(self):
        self.sample_cpu_health(10000)
        self.sample_cpu_health(10300)
        self.sample_cpu_health(10600)
        stalled = self.sample_cpu_health(10900)
        self.assertIn('worker_idle', stalled['issues'])
        self.assertEqual(stalled['events'], [{'event': 'alert', 'issue': 'worker_idle', 'message': stalled['issues']['worker_idle']}])
        unchanged = self.sample_cpu_health(11200)
        self.assertFalse(unchanged['changed'])
        recovered = self.sample_cpu_health(11500, cpu_ns='1100000001')
        self.assertNotIn('worker_idle', recovered['issues'])
        self.assertIn({'event': 'recovered', 'issue': 'worker_idle', 'message': 'Condition cleared.'}, recovered['events'])

    def test_thermal_pause_resets_idle_grace(self):
        self.sample_cpu_health(10000)
        self.sample_cpu_health(10300)
        hot = self.sample_cpu_health(10600, temperature=80)
        self.assertIn('overheating', hot['issues'])
        hot = self.sample_cpu_health(10900, temperature=80)
        self.assertNotIn('worker_idle', hot['issues'])
        cooling = self.sample_cpu_health(11200)
        self.assertNotIn('worker_idle', cooling['issues'])
        state = json.loads((self.path / 'cpu-state.json').read_text())
        self.assertEqual(state['last_progress_at'], 10900)

    def test_stale_jobs_suppress_idle_worker_alert(self):
        self.sample_cpu_health(10000)
        self.sample_cpu_health(10300, stale_job=True)
        self.sample_cpu_health(10600, stale_job=True)
        result = self.sample_cpu_health(11200, stale_job=True)
        self.assertIn('job_freshness', result['issues'])
        self.assertNotIn('worker_idle', result['issues'])
        reconnected = self.sample_cpu_health(11500)
        self.assertNotIn('worker_idle', reconnected['issues'])

    def test_unavailable_accounting_never_reports_idle(self):
        for counter in (None, '[not set]', '18446744073709551615', '-1'):
            with self.subTest(counter=counter):
                self.sample_cpu_health(10000)
                self.sample_cpu_health(10300)
                self.sample_cpu_health(10600)
                result = self.sample_cpu_health(10900, cpu_ns=counter)
                self.assertNotIn('worker_idle', result['issues'])
                (self.path / 'cpu-state.json').unlink()

    def test_restart_and_counter_reset_restart_idle_grace(self):
        for cpu_ns, pid in (('1000000000', '322'), ('0', '321')):
            with self.subTest(cpu_ns=cpu_ns, pid=pid):
                self.sample_cpu_health(10000)
                self.sample_cpu_health(10300)
                self.sample_cpu_health(10600)
                result = self.sample_cpu_health(10900, cpu_ns=cpu_ns, pid=pid)
                self.assertNotIn('worker_idle', result['issues'])
                state = json.loads((self.path / 'cpu-state.json').read_text())
                self.assertEqual(state['last_progress_at'], 10900)
                (self.path / 'cpu-state.json').unlink()

    def test_inactive_service_and_monitor_gap_reset_idle_grace(self):
        self.sample_cpu_health(10000)
        self.sample_cpu_health(10300)
        self.sample_cpu_health(10600)
        result = self.sample_cpu_health(10900, active=False)
        self.assertNotIn('worker_idle', result['issues'])
        resumed = self.sample_cpu_health(14000)
        self.assertNotIn('worker_idle', resumed['issues'])

    def test_pool_failover_handles_upstream_zero_exit(self):
        config = replace(self.config, fallback_pools=('stratum+tcp://backup.example.org:3333',))
        child1 = Mock(returncode=0, pid=101)
        child1.poll.return_value = 0
        child2 = Mock(returncode=0, pid=102)
        child2.poll.return_value = 0
        stopped = Mock()
        stopped.is_set.side_effect = [False] * 20
        stopped.wait.side_effect = [False, True]
        with patch.object(runtime.threading, 'Event', return_value=stopped), \
             patch.object(runtime.signal, 'signal', return_value=signal.SIG_DFL), \
             patch.object(runtime.subprocess, 'Popen', side_effect=[child1, child2]) as start, \
             patch('sys.stdout', new=io.StringIO()):
            runtime._supervise(config, '/opt/cpuminer-opt/cpuminer', self.path / 'mining.json')
        self.assertEqual(start.call_count, 2)
        first_args = start.call_args_list[0].args[0]
        second_args = start.call_args_list[1].args[0]
        self.assertIn('--retries=3', first_args)
        self.assertIn(config.pool, first_args)
        self.assertIn(config.fallback_pools[0], second_args)
        stopped.wait.assert_any_call(30)


    def test_requested_stop_never_rotates_pool(self):
        config = replace(self.config, fallback_pools=('stratum+tcp://backup.example.org:3333',))
        handlers = {}
        child = Mock(returncode=0, pid=101)
        child.poll.return_value = 0

        def register(number, handler):
            handlers[number] = handler
            return signal.SIG_DFL

        def start_child(*_args, **_kwargs):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return child

        with patch.object(runtime.signal, 'signal', side_effect=register), \
             patch.object(runtime.subprocess, 'Popen', side_effect=start_child) as start, \
             patch('sys.stdout', new=io.StringIO()) as output:
            runtime._supervise(config, '/opt/cpuminer-opt/cpuminer', self.path / 'mining.json')
        self.assertEqual(start.call_count, 1)
        child.terminate.assert_not_called()  # It had already exited when stop arrived.
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
