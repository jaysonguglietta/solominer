"""Fixture-only tests for privilege boundaries and recoverable maintenance.

These tests never call dnf/systemd, change host accounts, execute a miner, or
write installed paths. Root-only ownership operations use explicit mocks.
"""
from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from solominer import admin


class IdentitySecurityTests(unittest.TestCase):
    def test_dedicated_existing_accounts_are_accepted(self):
        account = SimpleNamespace(pw_uid=991, pw_gid=991, pw_shell='/sbin/nologin')
        with patch.object(admin.pwd, 'getpwnam', return_value=account), \
             patch.object(admin.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=991)), \
             patch.object(admin.os, 'getgrouplist', return_value=[991]):
            admin.ensure_users()

    def test_login_identity_is_rejected(self):
        account = SimpleNamespace(pw_uid=991, pw_gid=991, pw_shell='/bin/bash')
        with patch.object(admin.pwd, 'getpwnam', return_value=account), \
             patch.object(admin.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=991)):
            with self.assertRaisesRegex(admin.AdminError, 'non-login'):
                admin.ensure_users()

    def test_extra_groups_cannot_inherit_socket_or_admin_privileges(self):
        account = SimpleNamespace(pw_uid=991, pw_gid=991, pw_shell='/usr/sbin/nologin')
        with patch.object(admin.pwd, 'getpwnam', return_value=account), \
             patch.object(admin.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=991)), \
             patch.object(admin.os, 'getgrouplist', return_value=[991, 10]):
            with self.assertRaisesRegex(admin.AdminError, 'supplementary groups'):
                admin.ensure_users()


class DirectorySecurityTests(unittest.TestCase):
    def test_reject_relative_administrative_path(self):
        with self.assertRaises(admin.AdminError):
            admin.secure_dir(Path('relative/install'))

    def _check_bad_path(self, mode, uid=0, bad=Path('/srv/solominer')):
        def info(path):
            return SimpleNamespace(st_mode=mode if path == bad else stat.S_IFDIR | 0o755,
                                   st_uid=uid if path == bad else 0)
        with patch.object(Path, 'exists', return_value=True), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'lstat', autospec=True, side_effect=info), \
                patch.object(admin.os, 'chmod') as chmod:
            with self.assertRaises(admin.AdminError):
                admin.secure_dir(Path('/srv/solominer'))
            chmod.assert_not_called()

    def test_reject_directory_owned_by_service_user(self):
        self._check_bad_path(stat.S_IFDIR | 0o755, uid=2000)

    def test_reject_group_writable_directory(self):
        self._check_bad_path(stat.S_IFDIR | 0o775)

    def test_reject_world_writable_parent(self):
        self._check_bad_path(stat.S_IFDIR | 0o777, bad=Path('/srv'))

    def test_reject_symlink_component(self):
        self._check_bad_path(stat.S_IFLNK | 0o755)


class AtomicFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.secure = patch.object(admin, 'secure_dir')
        self.secure.start()
        self.addCleanup(self.secure.stop)
        self.chown = patch.object(admin.os, 'fchown')
        self.fchown = self.chown.start()
        self.addCleanup(self.chown.stop)

    def test_write_atomically_replaces_contents_and_sets_mode(self):
        destination = self.directory / 'binary'
        destination.write_bytes(b'old')
        admin.atomic_write(destination, b'new release', 0o755, gid=4321)
        self.assertEqual(destination.read_bytes(), b'new release')
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
        self.fchown.assert_called_once()
        self.assertEqual(self.fchown.call_args.args[1:], (0, 4321))
        self.assertEqual(list(self.directory.iterdir()), [destination])

    def test_refuse_symlink_without_changing_its_target(self):
        original = self.directory / 'original'
        original.write_bytes(b'keep')
        destination = self.directory / 'binary'
        destination.symlink_to(original)
        with self.assertRaises(admin.AdminError):
            admin.atomic_write(destination, b'evil')
        self.assertEqual(original.read_bytes(), b'keep')
        self.assertTrue(destination.is_symlink())

    def test_failed_sync_retains_original_and_cleans_temporary_file(self):
        destination = self.directory / 'binary'
        destination.write_bytes(b'old')
        with patch.object(admin.os, 'fsync', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError):
                admin.atomic_write(destination, b'new')
        self.assertEqual(destination.read_bytes(), b'old')
        self.assertEqual(list(self.directory.iterdir()), [destination])

    def test_regular_file_reader_rejects_symlink_and_oversize(self):
        regular = self.directory / 'large'
        regular.write_bytes(b'12345')
        symlink = self.directory / 'link'
        symlink.symlink_to(regular)
        with self.assertRaises(OSError):
            admin.read_regular(symlink)
        with self.assertRaises(admin.AdminError):
            admin.read_regular(regular, limit=4)
        with self.assertRaises((admin.AdminError, OSError)):
            admin.read_regular(self.directory)


class BackupIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.targets = {'binary': self.root / 'installed/cpuminer',
                        'metadata': self.root / 'installed/install.json',
                        'cli': self.root / 'bin/solominer'}
        self.targets['binary'].parent.mkdir()
        self.targets['cli'].parent.mkdir()
        self.targets['binary'].write_bytes(b'original miner')
        self.targets['cli'].write_bytes(b'original wrapper')
        def secure(path, mode=0o755):
            path.mkdir(parents=True, exist_ok=True)
        for replacement in (patch.object(admin, 'ADMIN_DIR', self.root / 'admin'),
                            patch.object(admin, 'TARGETS', self.targets),
                            patch.object(admin, 'secure_dir', side_effect=secure),
                            patch.object(admin.os, 'fchown')):
            replacement.start()
            self.addCleanup(replacement.stop)

    def test_snapshot_restores_present_and_absent_targets(self):
        backup_id = admin.snapshot()
        self.targets['binary'].write_bytes(b'new miner')
        self.targets['cli'].unlink()
        self.targets['metadata'].write_bytes(b'new provenance')
        admin.restore(backup_id)
        self.assertEqual(self.targets['binary'].read_bytes(), b'original miner')
        self.assertEqual(self.targets['cli'].read_bytes(), b'original wrapper')
        self.assertFalse(self.targets['metadata'].exists())
        self.assertEqual(stat.S_IMODE(self.targets['binary'].stat().st_mode), 0o755)

    def test_snapshot_preserves_explicit_service_state(self):
        states = {admin.SERVICE: {'active': True, 'enabled': False},
                  admin.HEALTH_TIMER: {'active': False, 'enabled': True}}
        backup_id = admin.snapshot(states)
        self.assertEqual(admin.restore(backup_id), states)

    def test_tampered_backup_is_rejected_before_any_target_changes(self):
        backup_id = admin.snapshot()
        backup = self.root / 'admin/backups' / backup_id
        (backup / 'cli').write_bytes(b'tampered')
        self.targets['binary'].write_bytes(b'current miner')
        self.targets['cli'].write_bytes(b'current wrapper')
        with self.assertRaises(admin.AdminError):
            admin.restore(backup_id)
        self.assertEqual(self.targets['binary'].read_bytes(), b'current miner')
        self.assertEqual(self.targets['cli'].read_bytes(), b'current wrapper')

    def test_bad_destination_is_rejected_before_any_target_changes(self):
        backup_id = admin.snapshot()
        self.targets['binary'].write_bytes(b'current miner')
        self.targets['cli'].unlink()
        self.targets['cli'].symlink_to(self.targets['binary'])
        with self.assertRaises(admin.AdminError):
            admin.restore(backup_id)
        self.assertEqual(self.targets['binary'].read_bytes(), b'current miner')
        self.assertTrue(self.targets['cli'].is_symlink())

    def test_corrupt_backup_does_not_stop_running_units(self):
        backup_id = admin.snapshot()
        backup = self.root / 'admin/backups' / backup_id
        (backup / 'binary').write_bytes(b'tampered')
        with patch.object(admin, 'stop_units') as stop, patch.object(admin, 'command') as command:
            with self.assertRaises(admin.AdminError):
                admin.restore_backup(backup_id)
        stop.assert_not_called()
        command.assert_not_called()

    def test_invalid_service_state_is_rejected_before_any_target_changes(self):
        backup_id = admin.snapshot()
        path = self.root / 'admin/backups' / backup_id / 'states.json'
        for invalid in ({admin.SERVICE: 'enabled'},
                        {admin.SERVICE: {'active': 'yes', 'enabled': False}},
                        {'unknown.service': {'active': True, 'enabled': True}}):
            with self.subTest(states=invalid):
                path.write_text(json.dumps(invalid))
                with self.assertRaises(admin.AdminError):
                    admin.restore(backup_id)
                self.assertEqual(self.targets['binary'].read_bytes(), b'original miner')

    def test_unexpected_manifest_entry_is_rejected(self):
        backup_id = admin.snapshot()
        path = self.root / 'admin/backups' / backup_id / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['../../escape'] = hashlib.sha256(b'payload').hexdigest()
        path.write_text(json.dumps(manifest))
        with self.assertRaises(admin.AdminError):
            admin.restore(backup_id)
        self.assertEqual(self.targets['binary'].read_bytes(), b'original miner')

    def test_backup_identifier_cannot_escape_storage(self):
        for identifier in ('../manifest.json', '/etc/passwd', '', '20261016T123456Z-deadbeef/extra'):
            with self.subTest(identifier=identifier), self.assertRaises(admin.AdminError):
                admin.restore(identifier)

    def test_snapshot_refuses_symlink_activation_target(self):
        self.targets['cli'].unlink()
        self.targets['cli'].symlink_to(self.targets['binary'])
        with self.assertRaises(admin.AdminError):
            admin.snapshot()


class LockTests(unittest.TestCase):
    def test_concurrent_operation_is_rejected_and_lock_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'update.lock'
            actual_open, actual_fstat = os.open, os.fstat
            def fixture_open(path, flags, mode=0o777):
                self.assertEqual(str(path), '/run/solominer-admin/update.lock')
                return actual_open(lock, flags, mode)
            def root_owned(fd):
                info = actual_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
            with patch.object(admin, 'secure_dir') as secure, \
                    patch.object(admin.os, 'open', side_effect=fixture_open), \
                    patch.object(admin.os, 'fstat', side_effect=root_owned):
                with admin.update_lock():
                    with self.assertRaisesRegex(admin.AdminError, 'in progress'):
                        with admin.update_lock():
                            self.fail('A second administrative operation acquired the lock.')
                with admin.update_lock():
                    pass
            secure.assert_called_with(Path('/run/solominer-admin'), 0o700)


class BuildBoundaryTests(unittest.TestCase):
    def test_interrupted_builder_is_stopped_before_workspace_cleanup(self):
        failure = KeyboardInterrupt()
        with patch.object(admin, 'command', side_effect=[failure, SimpleNamespace(returncode=0)]) as command:
            with self.assertRaises(KeyboardInterrupt):
                admin.run_builder(['/bin/false'], Path('/var/lib/solominer-build/fixture'), timeout=1)
        start = command.call_args_list[0].args[0]
        unit = next(argument.removeprefix('--unit=') for argument in start if argument.startswith('--unit='))
        self.assertEqual(command.call_args_list[1].args[0], ['systemctl', 'stop', unit])

    def test_sandbox_has_separate_uid_no_network_and_bounded_resources(self):
        workspace = Path('/var/lib/solominer-build/private-fixture')
        command = admin.builder_command(['/bin/bash', str(workspace / 'driver.sh')], workspace)
        for required in ('--uid=solominer-build', '--gid=solominer-build',
                         '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict',
                         '--property=PrivateNetwork=yes', '--property=ProtectHome=yes',
                         '--property=CapabilityBoundingSet=', '--property=KillMode=control-group',
                         '--property=MemoryMax=2G', '--property=CPUQuota=200%',
                         '--property=RuntimeMaxSec=30min', f'--property=ReadWritePaths={workspace}'):
            self.assertIn(required, command)
        self.assertIn('/usr/bin/env', command)
        self.assertIn('-i', command)
        self.assertEqual(command[-2:], ['/bin/bash', str(workspace / 'driver.sh')])
        self.assertFalse(any('shell=True' in argument for argument in command))

    def test_source_is_fixed_immutable_revision_and_https_origin(self):
        self.assertRegex(admin.UPSTREAM_REVISION, r'^[a-f0-9]{40}$')
        self.assertEqual(admin.UPSTREAM_REPO, 'https://github.com/JayDDee/cpuminer-opt.git')
        self.assertEqual(admin.UPSTREAM_REVISION, 'b34565bfaca5da9ed894a326e3ba0dfe459550a4')


class ActivationTests(unittest.TestCase):
    def test_failed_activation_restores_previous_installation(self):
        states = {admin.SERVICE: {'active': True, 'enabled': True},
                  admin.HEALTH_TIMER: {'active': True, 'enabled': True}}
        with patch.object(admin, 'secure_install_dir'), \
                patch.object(admin, 'snapshot', return_value='fixture-backup') as snapshot, \
                patch.object(admin, 'unit_states', return_value=states), \
                patch.object(admin, 'stop_units'), \
                patch.object(admin, 'atomic_write') as write, \
                patch.object(admin, 'install_bundle'), \
                patch.object(admin, 'write_units', side_effect=admin.AdminError('fixture validation failure')), \
                patch.object(admin, 'command') as command, \
                patch.object(admin, 'restore_backup') as restore:
            with self.assertRaises(admin.AdminError):
                admin.activate(b'fixture', {}, object())
        snapshot.assert_called_once_with(states)
        restore.assert_called_once_with('fixture-backup')
        command.assert_not_called()
        self.assertFalse(any(call.args[0] == admin.ADMIN_DIR / 'last-backup' for call in write.call_args_list))

    def test_unstable_pid_during_startup_is_rejected(self):
        responses = [SimpleNamespace(stdout=pid) for pid in ('100', '100', '101')]
        with patch.object(admin, 'is_active', return_value=True), \
                patch.object(admin, 'command', side_effect=responses), \
                patch.object(admin.time, 'sleep'):
            with self.assertRaises(admin.AdminError):
                admin.verify_started()

    def test_stable_startup_passes_without_mining_or_network(self):
        with patch.object(admin, 'is_active', return_value=True), \
                patch.object(admin, 'command', return_value=SimpleNamespace(stdout='100')) as command, \
                patch.object(admin.time, 'sleep'):
            admin.verify_started()
        self.assertEqual(command.call_count, 5)

    def test_stage_does_not_activate_or_change_service(self):
        args = SimpleNamespace(install_deps=False, update_packages=False, migrate=False,
                               activate_staged=False, no_restart=True)
        metadata = {'revision': admin.UPSTREAM_REVISION}
        with patch.object(admin, 'require_host'), \
                patch.object(admin, 'update_lock', return_value=nullcontext()), \
                patch.object(admin, 'require_commands'), \
                patch.object(admin, 'prepare_config', return_value=object()), \
                patch.object(admin, 'secure_dir'), \
                patch.object(admin, 'built_candidate', return_value=nullcontext((b'ELF fixture', metadata))), \
                patch.object(admin, 'atomic_write') as write, \
                patch.object(admin, 'activate') as activate, \
                patch.object(admin, 'command') as command:
            admin.install_or_update(args)
        activate.assert_not_called()
        command.assert_not_called()
        self.assertEqual(write.call_count, 2)
        self.assertTrue(all('staged' in str(call.args[0]) for call in write.call_args_list))


if __name__ == '__main__':
    unittest.main()
