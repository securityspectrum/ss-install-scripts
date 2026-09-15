import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agent_core.fluent_bit_installer import FluentBitInstaller


class RpmAssetTests(unittest.TestCase):
    def setUp(self):
        self.installer = FluentBitInstaller()

    def test_current_and_legacy_release_filenames(self):
        for name in ("fluent-bit-4.0.0-2.ss1.el9.x86_64.rpm",
                     "fluent-bit-4.0.0.centos-9.1.x86_64.rpm",
                     "fluent-bit-3.1.6.centos-9.x86_64.rpm"):
            with self.subTest(name=name):
                self.assertEqual(self.installer.parse_asset_name(name), {
                    "distro": "centos", "distro_version": "9", "arch": "x86_64", "extension": "rpm"})
        for name in ("fluent-bit-4.0.0-2.ss1.el9.x86_64-headers.rpm",
                     "fluent-bit-4.0.0-2.ss1.el9.x86_64.rpm.sha256"):
            self.assertIsNone(self.installer.parse_asset_name(name))

    def test_legacy_debian_and_ubuntu_assets(self):
        self.assertEqual(self.installer.parse_asset_name(
            "fluent-bit-4.0.0.ubuntu-18.04.amd64.deb")['arch'], 'amd64')
        self.assertEqual(self.installer.parse_asset_name(
            "fluent-bit-4.0.0.debian-bookworm.amd64.deb")['distro_version'], 'bookworm')

    @patch('agent_core.fluent_bit_installer.platform.system', return_value='Linux')
    @patch('agent_core.fluent_bit_installer.platform.machine', return_value='x86_64')
    @patch('agent_core.fluent_bit_installer.distro.major_version', return_value='9')
    def test_selects_matching_architecture_for_el_distros(self, *_):
        arm = 'fluent-bit-4.0.0-2.ss1.el9.aarch64.rpm'
        intel = 'fluent-bit-4.0.0-2.ss1.el9.x86_64.rpm'
        assets = self.installer.categorize_assets({arm: 'arm-url', intel: 'intel-url'})
        for name in ('centos', 'rhel', 'rocky', 'almalinux'):
            with self.subTest(distro=name), patch('agent_core.fluent_bit_installer.distro.id', return_value=name):
                self.assertEqual(self.installer.select_asset(assets), (intel, 'intel-url'))

    @patch('agent_core.fluent_bit_installer.subprocess.run')
    def test_version_comes_from_package_metadata_not_filename(self, run):
        run.return_value = Mock(stdout='fluent-bit\n0:4.0.0-2.ss1.el9\n')
        self.assertEqual(self.installer.extract_rpm_version(Path('/tmp/renamed.rpm')), '0:4.0.0-2.ss1.el9')
        self.assertIn('-qp', run.call_args.args[0])
        run.return_value.stdout = 'another-package\n0:4.0.0-1\n'
        with self.assertRaises(ValueError):
            self.installer.extract_rpm_version(Path('/tmp/renamed.rpm'))

    @patch('agent_core.fluent_bit_installer.subprocess.run')
    def test_invalid_version_cannot_reach_rpm_lua(self, run):
        with self.assertRaises(ValueError):
            self.installer._compare_rpm_versions('0:4.0.0-1', '0:4.0.0-1");os.exit()')
        run.assert_not_called()


@unittest.skipUnless(shutil.which('rpm'), 'native RPM comparison requires rpm')
class NativeRpmVersionTests(unittest.TestCase):
    def setUp(self):
        self.installer = FluentBitInstaller()

    def test_release_upgrade_is_not_skipped(self):
        with patch.object(self.installer, '_installed_rpm_versions', return_value=['0:4.0.0-1']):
            self.assertFalse(self.installer.is_package_installed('fluent-bit', '0:4.0.0-2.ss1.el9'))
            self.assertFalse(self.installer.is_newer_version_installed('fluent-bit', '0:4.0.0-2.ss1.el9'))

    def test_native_numeric_epoch_and_prerelease_order(self):
        for older, newer in [('0:4.0.0-2.ss1.el9', '0:4.0.0-10.ss1.el9'),
                             ('0:4.9.0-1', '0:4.10.0-1'),
                             ('0:9.0.0-1', '1:1.0.0-1'),
                             ('0:4.0.0~rc1-1', '0:4.0.0-1')]:
            with self.subTest(older=older, newer=newer):
                self.assertLess(self.installer._compare_rpm_versions(older, newer), 0)
                self.assertGreater(self.installer._compare_rpm_versions(newer, older), 0)
                self.assertEqual(self.installer._compare_rpm_versions(newer, newer), 0)

    def test_equal_and_newer_installs_are_detected(self):
        with patch.object(self.installer, '_installed_rpm_versions', return_value=['0:4.0.0-2.ss1.el9']):
            self.assertTrue(self.installer.is_package_installed('fluent-bit', '0:4.0.0-2.ss1.el9'))
            self.assertTrue(self.installer.is_newer_version_installed('fluent-bit', '0:4.0.0-1'))

    @patch('agent_core.fluent_bit_installer.platform.system', return_value='Linux')
    def test_install_flow_upgrades_release_and_skips_equal_or_newer(self, _):
        real_run = subprocess.run
        candidate = '0:4.0.0-2.ss1.el9'
        for installed, should_install in [('0:4.0.0-1', True), (candidate, False),
                                          ('0:4.0.0-10.ss1.el9', False)]:
            commands = []
            def run(command, **kwargs):
                if command[0] == 'sudo':
                    commands.append(command)
                    return subprocess.CompletedProcess(command, 0)
                return real_run(command, **kwargs)
            with self.subTest(installed=installed), \
                 patch.object(self.installer, 'extract_rpm_version', return_value=candidate), \
                 patch.object(self.installer, '_installed_rpm_versions', return_value=[installed]), \
                 patch('agent_core.fluent_bit_installer.subprocess.run', side_effect=run):
                self.installer.run_installation_command('/tmp/collector.rpm')
            self.assertEqual(bool(commands), should_install)
            if should_install:
                self.assertEqual(commands[0], ['sudo', 'rpm', '--quiet', '-Uvh', '/tmp/collector.rpm'])


if __name__ == '__main__':
    unittest.main()
