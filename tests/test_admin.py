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
import subprocess
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from solominer import admin


class HostPreflightTests(unittest.TestCase):
    def test_atomic_fedora_is_rejected_before_installation_can_mutate_host(self):
        with patch.object(admin.os, 'geteuid', return_value=0), \
             patch.object(Path, 'is_file', return_value=True), \
             patch.object(Path, 'exists', return_value=True), \
             patch.object(admin, 'update_lock') as update_lock:
            with self.assertRaisesRegex(admin.AdminError, 'Atomic/rpm-ostree'):
                admin.install_or_update(SimpleNamespace(install_deps=True))
        update_lock.assert_not_called()


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
                         '--property=MemoryMax=2G', '--property=MemorySwapMax=512M',
                         '--property=TasksMax=256', '--property=CPUQuota=200%',
                         '--property=TemporaryFileSystem=/tmp:rw,size=512M,mode=1777',
                         '--property=InaccessiblePaths=/var/tmp', 'TMPDIR=/tmp',
                         '--property=RuntimeMaxSec=30min', f'--property=ReadWritePaths={workspace}'):
            self.assertIn(required, command)
        self.assertIn('/usr/bin/env', command)
        self.assertIn('-i', command)
        self.assertEqual(command[-2:], ['/bin/bash', str(workspace / 'driver.sh')])
        self.assertFalse(any('shell=True' in argument for argument in command))

    def test_fetch_is_the_only_sandbox_action_with_network(self):
        workspace = Path('/var/lib/solominer-build/private-fixture')
        fetch = admin.builder_command(['git', 'fetch'], workspace, network=True)
        local = admin.builder_command(['git', 'checkout'], workspace)
        self.assertNotIn('--property=PrivateNetwork=yes', fetch)
        self.assertIn('--property=PrivateNetwork=yes', local)
        for required in ('--uid=solominer-build', '--property=NoNewPrivileges=yes',
                         '--property=ProtectSystem=strict', '--property=MemoryMax=2G',
                         f'--property=ReadWritePaths={workspace}'):
            self.assertIn(required, fetch)

    def test_interrupted_fetch_is_stopped_before_workspace_cleanup(self):
        failure = KeyboardInterrupt()
        with patch.object(admin, 'command', side_effect=[failure, SimpleNamespace(returncode=0)]) as command:
            with self.assertRaises(KeyboardInterrupt):
                admin.run_builder(['git', 'fetch'], Path('/var/lib/solominer-build/fixture'),
                                  timeout=1, network=True)
        start = command.call_args_list[0].args[0]
        unit = next(argument.removeprefix('--unit=') for argument in start if argument.startswith('--unit='))
        self.assertTrue(unit.startswith('solominer-fetch-'))
        self.assertEqual(command.call_args_list[1].args[0], ['systemctl', 'stop', unit])

    def test_elf_requires_system_jansson_dependency(self):
        libraries = ' 0x0000000000000001 (NEEDED) Shared library: [libjansson.so.4]\n'
        with patch.object(admin, 'run_builder', return_value=SimpleNamespace(stdout=libraries)):
            self.assertEqual(admin.needed_libraries(Path('/fixture/cpuminer'), Path('/fixture')),
                             ['libjansson.so.4'])
        with patch.object(admin, 'run_builder', return_value=SimpleNamespace(stdout='')):
            with self.assertRaisesRegex(admin.AdminError, 'system Jansson'):
                admin.needed_libraries(Path('/fixture/cpuminer'), Path('/fixture'))

    def test_low_build_disk_space_is_rejected_before_fetch(self):
        with patch.object(admin, 'secure_dir'), \
             patch.object(admin.shutil, 'disk_usage', return_value=SimpleNamespace(free=100 * 1024**2)), \
             patch.object(admin, 'run_builder') as builder:
            with self.assertRaisesRegex(admin.AdminError, '1 GiB'):
                with admin.built_candidate():
                    pass
        builder.assert_not_called()

    def test_source_is_fixed_immutable_revision_and_https_origin(self):
        self.assertRegex(admin.UPSTREAM_REVISION, r'^[a-f0-9]{40}$')
        self.assertEqual(admin.UPSTREAM_REPO, 'https://github.com/JayDDee/cpuminer-opt.git')
        self.assertEqual(admin.UPSTREAM_REVISION, 'b34565bfaca5da9ed894a326e3ba0dfe459550a4')

    def test_candidate_fetch_is_only_network_step_and_records_build_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'builder'
            root.mkdir()
            def secure(path, mode=0o755):
                path.mkdir(parents=True, exist_ok=True)
            def fake_builder(argv, workspace, timeout, **kwargs):
                if argv[:2] == ['git', '-c'] and 'rev-parse' in argv:
                    return SimpleNamespace(stdout=admin.UPSTREAM_REVISION + '\n')
                if argv[:2] == ['/bin/bash', str(workspace / 'build-miner.sh')]:
                    (workspace / 'source/cpuminer').write_bytes(b'\x7fELF-fixture')
                if argv[:3] == ['readelf', '-W', '-d']:
                    return SimpleNamespace(stdout='(NEEDED) Shared library: [libjansson.so.4]\n')
                if argv[:2] == ['gcc', '-dumpfullversion']:
                    return SimpleNamespace(stdout='gcc 16.1')
                return SimpleNamespace(stdout='')
            with patch.object(admin, 'BUILDER_ROOT', root), \
                 patch.object(admin, 'secure_dir', side_effect=secure), \
                 patch.object(admin.shutil, 'disk_usage', return_value=SimpleNamespace(free=2 * 1024**3)), \
                 patch.object(admin.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=991, pw_gid=991)), \
                 patch.object(admin.os, 'chown'), \
                 patch.object(admin, 'run_builder', side_effect=fake_builder) as builder, \
                 patch.object(admin.platform, 'freedesktop_os_release',
                              return_value={'PRETTY_NAME': 'Fedora Linux 44', 'VERSION_ID': '44'}), \
                 patch.object(admin.platform, 'machine', return_value='x86_64'):
                with admin.built_candidate() as (binary, metadata):
                    self.assertEqual(binary, b'\x7fELF-fixture')
                    self.assertEqual(metadata['fedora_version'], '44')
                    self.assertEqual(metadata['architecture'], 'x86_64')
                    self.assertEqual(metadata['compiler'], 'gcc 16.1')
                    self.assertEqual(metadata['linked_libraries'], ['libjansson.so.4'])
            online = [call for call in builder.call_args_list if call.kwargs.get('network')]
            self.assertEqual(len(online), 1)
            self.assertIn('fetch', online[0].args[0])
            self.assertTrue(all('network' not in call.kwargs or not call.kwargs['network']
                                for call in builder.call_args_list if call not in online))


class BuildScriptTests(unittest.TestCase):
    def _run_fixture(self, *, pkg_config_ok, jansson_probe):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            (fake_bin / 'pkg-config').write_text('#!/bin/sh\nexit ' + ('0' if pkg_config_ok else '1') + '\n')
            (fake_bin / 'pkg-config').chmod(0o755)
            (root / 'autogen.sh').write_text('#!/bin/sh\ntouch autogen-ran\n')
            (root / 'autogen.sh').chmod(0o755)
            (root / 'configure').write_text(
                '#!/bin/sh\nprintf "ac_cv_lib_jansson_json_loads=' + jansson_probe + '\\n" > config.log\n')
            (root / 'configure').chmod(0o755)
            (fake_bin / 'make').write_text('#!/bin/sh\ntouch make-ran\n')
            (fake_bin / 'make').chmod(0o755)
            result = subprocess.run(['bash', str(admin.SOURCE_ROOT / 'scripts/build-miner.sh')],
                                    cwd=root, env={'PATH': f'{fake_bin}:/usr/bin:/bin'},
                                    capture_output=True, text=True, check=False)
            return result, (root / 'autogen-ran').exists(), (root / 'make-ran').exists()

    def test_missing_system_jansson_stops_before_autogen(self):
        result, autogen, make = self._run_fixture(pkg_config_ok=False, jansson_probe='yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bundled Jansson fallback', result.stderr)
        self.assertFalse(autogen)
        self.assertFalse(make)

    def test_configure_fallback_stops_before_make(self):
        result, autogen, make = self._run_fixture(pkg_config_ok=True, jansson_probe='no')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(autogen)
        self.assertFalse(make)

    def test_system_jansson_build_path_continues(self):
        result, autogen, make = self._run_fixture(pkg_config_ok=True, jansson_probe='yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(autogen)
        self.assertTrue(make)


class ActivationTests(unittest.TestCase):
    def test_failed_activation_restores_previous_installation(self):
        states = {admin.SERVICE: {'active': True, 'enabled': True},
                  admin.HEALTH_TIMER: {'active': True, 'enabled': True}}
        config = object()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        admin_dir = Path(temporary.name)
        with patch.object(admin, 'ADMIN_DIR', admin_dir), \
                patch.object(admin, 'secure_install_dir'), \
                patch.object(admin, 'snapshot', return_value='fixture-backup') as snapshot, \
                patch.object(admin, 'unit_states', return_value=states), \
                patch.object(admin, 'stop_units'), \
                patch.object(admin, 'atomic_write') as write, \
                patch.object(admin, 'install_bundle'), \
                patch.object(admin, 'config_from_data', return_value=config), \
                patch.object(admin, 'read_regular', return_value=b'validated config'), \
                patch.object(admin, 'write_units', side_effect=admin.AdminError('fixture validation failure')), \
                patch.object(admin, 'command') as command, \
                patch.object(admin, 'restore_backup') as restore:
            with self.assertRaises(admin.AdminError):
                admin.activate(b'fixture', {}, config)
        snapshot.assert_called_once_with(states)
        restore.assert_called_once_with('fixture-backup')
        command.assert_not_called()
        self.assertFalse(any(call.args[0] == admin_dir / 'last-backup' for call in write.call_args_list))
        self.assertFalse(any(call.args[0] == admin_dir / 'last-good-config' for call in write.call_args_list))

    def test_successful_activation_records_last_good_only_after_startup_verification(self):
        events = []
        config = object()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        admin_dir = Path(temporary.name)
        def write(path, data, *args):
            if path == admin_dir / 'last-good-config':
                events.append(('last-good', data))
        with patch.object(admin, 'ADMIN_DIR', admin_dir), \
             patch.object(admin, 'secure_install_dir'), \
             patch.object(admin, 'snapshot', return_value='fixture-backup'), \
             patch.object(admin, 'unit_states', return_value={}), \
             patch.object(admin, 'stop_units'), \
             patch.object(admin, 'atomic_write', side_effect=write), \
             patch.object(admin, 'install_bundle'), \
             patch.object(admin, 'config_from_data', return_value=config), \
             patch.object(admin, 'write_units'), \
             patch.object(admin, 'command'), \
             patch.object(admin, 'read_regular', return_value=b'validated config'), \
             patch.object(admin, 'verify_started', side_effect=lambda: events.append(('verified', None))):
            admin.activate(b'fixture ELF', {}, config)
        self.assertEqual(events, [('verified', None), ('last-good', b'validated config')])

    def test_changed_configuration_aborts_activation_before_downtime(self):
        config = object()
        with patch.object(admin, 'secure_install_dir'), \
             patch.object(admin, 'read_regular', return_value=b'fixture config'), \
             patch.object(admin, 'config_from_data', return_value=object()), \
             patch.object(admin, 'snapshot') as snapshot, \
             patch.object(admin, 'stop_units') as stop:
            with self.assertRaisesRegex(admin.AdminError, 'changed during the build'):
                admin.activate(b'fixture', {}, config)
        snapshot.assert_not_called()
        stop.assert_not_called()

    def test_partial_stop_during_activation_attempts_release_restore(self):
        config = object()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(admin, 'ADMIN_DIR', Path(directory)), \
             patch.object(admin, 'secure_install_dir'), \
             patch.object(admin, 'read_regular', return_value=b'validated config'), \
             patch.object(admin, 'config_from_data', return_value=config), \
             patch.object(admin, 'snapshot', return_value='fixture-backup'), \
             patch.object(admin, 'unit_states', return_value={}), \
             patch.object(admin, 'stop_units', side_effect=admin.AdminError('partial stop')), \
             patch.object(admin, 'atomic_write') as write, \
             patch.object(admin, 'restore_backup') as restore:
            with self.assertRaisesRegex(admin.AdminError, 'partial stop'):
                admin.activate(b'fixture', {}, config)
        restore.assert_called_once_with('fixture-backup')
        write.assert_not_called()

    def test_failed_activation_pointer_write_restores_prior_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / 'current.env'
            live.write_bytes(b'validated config')
            good = root / 'last-good-config'
            good.write_bytes(b'prior good')
            backup = root / 'last-backup'
            backup.write_bytes(b'prior backup')
            config = object()
            original_write = admin.atomic_write
            def secure(path, mode=0o755):
                path.mkdir(parents=True, exist_ok=True)
            def fail_new_pointer(path, data, *args):
                if path == backup and data == b'new-backup':
                    raise OSError('fixture metadata write failed')
                if path in (good, backup):
                    return original_write(path, data, *args)
            with patch.object(admin, 'ADMIN_DIR', root), \
                 patch.object(admin, 'DEFAULT_CONFIG', live), \
                 patch.object(admin, 'secure_dir', side_effect=secure), \
                 patch.object(admin.os, 'fchown'), \
                 patch.object(admin, 'secure_install_dir'), \
                 patch.object(admin, 'config_from_data', return_value=config), \
                 patch.object(admin, 'snapshot', return_value='new-backup'), \
                 patch.object(admin, 'unit_states', return_value={}), \
                 patch.object(admin, 'stop_units'), \
                 patch.object(admin, 'atomic_write', side_effect=fail_new_pointer), \
                 patch.object(admin, 'install_bundle'), \
                 patch.object(admin, 'write_units'), \
                 patch.object(admin, 'command'), \
                 patch.object(admin, 'verify_started') as verify, \
                 patch.object(admin, 'restore_backup') as restore:
                with self.assertRaisesRegex(OSError, 'metadata write failed'):
                    admin.activate(b'fixture', {}, config)
            verify.assert_called_once()
            restore.assert_called_once_with('new-backup')
            self.assertEqual(good.read_bytes(), b'prior good')
            self.assertEqual(backup.read_bytes(), b'prior backup')

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


class ConfigTransactionTests(unittest.TestCase):
    BASE = (b'POOL=stratum+ssl://pool.example.invalid:443\n'
            b'WALLET=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n'
            b'WORKER=ci_fixture\nTHREADS=1\nCPU_QUOTA=50%\n')
    UPDATED = BASE.replace(b'CPU_QUOTA=50%', b'CPU_QUOTA=75%')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.live = self.root / 'etc/sysconfig/btc-solo-cpu'
        self.live.parent.mkdir(parents=True)
        self.live.write_bytes(self.BASE)
        self.admin_dir = self.root / 'admin'
        self.admin_dir.mkdir()
        (self.admin_dir / 'last-good-config').write_bytes(self.BASE)
        self.candidate = self.root / 'candidate.env'
        self.candidate.write_bytes(self.UPDATED)
        def secure(path, mode=0o755):
            path.mkdir(parents=True, exist_ok=True)
        substitutions = (
            patch.object(admin, 'DEFAULT_CONFIG', self.live),
            patch.object(admin, 'ADMIN_DIR', self.admin_dir),
            patch.object(admin, 'require_host'),
            patch.object(admin, 'update_lock', return_value=nullcontext()),
            patch.object(admin, 'secure_dir', side_effect=secure),
            patch.object(admin, 'ensure_users'),
            patch.object(admin.os, 'fchown'),
            patch.object(admin.pwd, 'getpwnam', return_value=SimpleNamespace(pw_gid=991)),
            patch.object(admin, 'unit_states', return_value={
                admin.SERVICE: {'active': True, 'enabled': True},
                admin.HEALTH_TIMER: {'active': True, 'enabled': True}}),
            patch.object(admin, 'snapshot', return_value='fixture-backup'),
            patch.object(admin, 'stop_units'),
            patch.object(admin, 'write_units'),
            patch.object(admin, 'command', return_value=SimpleNamespace(returncode=1)),
            patch.object(admin, 'verify_started'),
            patch.object(admin, 'restore_backup'),
        )
        self.mocks = {}
        for substitution in substitutions:
            mocked = substitution.start()
            self.addCleanup(substitution.stop)
            self.mocks[substitution.attribute] = mocked

    def test_candidate_apply_success_persists_exact_validated_bytes(self):
        admin.apply_config(self.candidate)
        self.assertEqual(self.live.read_bytes(), self.UPDATED)
        self.assertEqual((self.admin_dir / 'last-good-config').read_bytes(), self.UPDATED)
        self.assertEqual((self.admin_dir / 'last-backup').read_bytes(), b'fixture-backup')
        self.assertEqual(self.candidate.read_bytes(), self.UPDATED)
        self.assertFalse((self.admin_dir / 'candidate-config').exists())
        self.assertEqual(self.mocks['write_units'].call_args.args[0].cpu_quota, '75%')
        self.assertIn(['systemctl', 'restart', admin.SERVICE],
                      [call.args[0] for call in self.mocks['command'].call_args_list])
        self.mocks['verify_started'].assert_called_once()
        self.mocks['restore_backup'].assert_not_called()

    def test_invalid_live_edit_restores_last_good_without_stopping_service(self):
        invalid = self.BASE.replace(b'WALLET=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', b'WALLET=not-a-wallet')
        self.live.write_bytes(invalid)
        with self.assertRaisesRegex(admin.AdminError, 'Invalid live configuration restored'):
            admin.apply_config()
        self.assertEqual(self.live.read_bytes(), self.BASE)
        self.assertEqual((self.admin_dir / 'last-good-config').read_bytes(), self.BASE)
        self.assertFalse((self.admin_dir / 'candidate-config').exists())
        rejected = list(self.admin_dir.glob('rejected-config-*'))
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0].read_bytes(), invalid)
        self.mocks['stop_units'].assert_not_called()
        self.mocks['snapshot'].assert_not_called()
        self.assertEqual([call.args[0] for call in self.mocks['command'].call_args_list],
                         [['systemctl', 'is-failed', '--quiet', admin.SERVICE]])
        self.mocks['verify_started'].assert_not_called()

    def test_invalid_live_edit_restarts_service_only_when_failed(self):
        invalid = self.BASE.replace(b'WALLET=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', b'WALLET=not-a-wallet')
        self.live.write_bytes(invalid)
        def systemctl(argv, **kwargs):
            if argv == ['systemctl', 'is-failed', '--quiet', admin.SERVICE]:
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(returncode=0)
        self.mocks['command'].side_effect = systemctl
        with self.assertRaisesRegex(admin.AdminError, 'Invalid live configuration restored'):
            admin.apply_config()
        self.assertEqual(self.live.read_bytes(), self.BASE)
        self.assertEqual([call.args[0] for call in self.mocks['command'].call_args_list],
                         [['systemctl', 'is-failed', '--quiet', admin.SERVICE],
                          ['systemctl', 'restart', admin.SERVICE]])
        self.mocks['verify_started'].assert_called_once()
        self.mocks['stop_units'].assert_not_called()

    def test_failed_restart_restores_previous_config_and_release(self):
        def systemctl(argv, **kwargs):
            if argv == ['systemctl', 'restart', admin.SERVICE]:
                raise admin.AdminError('fixture restart failed')
            return SimpleNamespace(returncode=0)
        self.mocks['command'].side_effect = systemctl
        with self.assertRaisesRegex(admin.AdminError, 'fixture restart failed'):
            admin.apply_config(self.candidate)
        self.assertEqual(self.live.read_bytes(), self.BASE)
        self.assertEqual((self.admin_dir / 'last-good-config').read_bytes(), self.BASE)
        self.assertFalse((self.admin_dir / 'last-backup').exists())
        self.assertFalse((self.admin_dir / 'candidate-config').exists())
        self.mocks['restore_backup'].assert_called_once_with('fixture-backup')

    def test_partial_stop_during_apply_attempts_release_restore(self):
        self.mocks['stop_units'].side_effect = admin.AdminError('partial stop')
        with self.assertRaisesRegex(admin.AdminError, 'partial stop'):
            admin.apply_config(self.candidate)
        self.assertEqual(self.live.read_bytes(), self.BASE)
        self.assertEqual((self.admin_dir / 'last-good-config').read_bytes(), self.BASE)
        self.mocks['restore_backup'].assert_called_once_with('fixture-backup')
        self.mocks['write_units'].assert_not_called()

    def test_live_edit_during_validation_aborts_before_service_stop(self):
        concurrent = self.BASE.replace(b'WORKER=ci_fixture', b'WORKER=concurrent')
        def edit_during_snapshot(states):
            self.live.write_bytes(concurrent)
            return 'fixture-backup'
        self.mocks['snapshot'].side_effect = edit_during_snapshot
        with self.assertRaisesRegex(admin.AdminError, 'changed during validation'):
            admin.apply_config(self.candidate)
        self.assertEqual(self.live.read_bytes(), concurrent)
        self.mocks['stop_units'].assert_not_called()
        self.mocks['restore_backup'].assert_not_called()
        self.assertEqual((self.admin_dir / 'last-good-config').read_bytes(), self.BASE)

    def test_live_edit_after_stop_is_preserved_when_activation_aborts(self):
        concurrent = self.BASE.replace(b'WORKER=ci_fixture', b'WORKER=concurrent')
        self.mocks['stop_units'].side_effect = lambda: self.live.write_bytes(concurrent)
        with self.assertRaisesRegex(admin.AdminError, 'changed during activation'):
            admin.apply_config(self.candidate)
        self.assertEqual(self.live.read_bytes(), concurrent)
        self.mocks['restore_backup'].assert_called_once_with('fixture-backup')
        self.assertEqual((self.admin_dir / 'last-good-config').read_bytes(), self.BASE)

    def test_release_restore_is_attempted_when_config_and_pointer_recovery_fail(self):
        original_write = admin.atomic_write
        def fail_config_restore(path, data, *args):
            if path == self.live and data == self.BASE:
                raise OSError('fixture disk full during config restore')
            return original_write(path, data, *args)
        def fail_restart(argv, **kwargs):
            if argv == ['systemctl', 'restart', admin.SERVICE]:
                raise admin.AdminError('fixture restart failed')
            return SimpleNamespace(returncode=0)
        self.mocks['command'].side_effect = fail_restart
        with patch.object(admin, 'atomic_write', side_effect=fail_config_restore), \
             patch.object(admin, 'restore_record', side_effect=OSError('fixture pointer restore failed')):
            with self.assertRaisesRegex(admin.AdminError, 'recovery is incomplete'):
                admin.apply_config(self.candidate)
        self.mocks['restore_backup'].assert_called_once_with('fixture-backup')


if __name__ == '__main__':
    unittest.main()
