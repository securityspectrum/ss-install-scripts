import json
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_core import local_collector as collector
from agent_core.fluent_bit_installer import FluentBitInstaller


class CollectorInstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "prepared-collector"
        self.binary.write_bytes(b"tested binary")
        self.validate = patch.object(collector, "validate_binary", return_value=self.binary)
        self.validate.start()
        self.addCleanup(self.validate.stop)
        self.host = self.root / "new-host"

    def test_empty_host_gets_binary_service_and_override(self):
        installed = collector.install_collector(self.binary, self.host)
        self.assertEqual(installed.read_bytes(), b"tested binary")
        self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
        self.assertTrue((self.host / collector.UNIT_PATH).is_file())
        override = (self.host / collector.DROPIN_PATH).read_text()
        self.assertIn(f"ExecStart=/{collector.BINARY_PATH}", override)
        self.assertNotIn(str(self.root), override)

    def test_package_unit_and_sensor_configuration_are_preserved(self):
        unit = self.host / "usr/lib/systemd/system/fluent-bit.service"
        sensor = self.host / "etc/zeek/node.cfg"
        for path, content in ((unit, "vendor service"), (sensor, "existing interface")):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        collector.install_collector(self.binary, self.host)
        self.assertEqual(unit.read_text(), "vendor service")
        self.assertEqual(sensor.read_text(), "existing interface")
        self.assertFalse((self.host / collector.UNIT_PATH).exists())

    def test_reinstall_updates_binary_and_old_recovery_override(self):
        collector.install_collector(self.binary, self.host)
        old_override = self.host / collector.DROPIN_PATH
        old_override.write_text("ExecStart=/old/cache/path/fluent-bit\n")
        self.binary.write_bytes(b"updated tested binary")
        installed = collector.install_collector(self.binary, self.host)
        self.assertEqual(installed.read_bytes(), b"updated tested binary")
        self.assertNotIn("/old/cache/path", old_override.read_text())
        self.assertEqual(list(installed.parent.iterdir()), [installed])

    @patch("agent_core.fluent_bit_installer.subprocess.run")
    @patch("agent_core.fluent_bit_installer.install_collector")
    def test_prepared_binary_bypasses_release_download(self, install, command):
        installer = FluentBitInstaller()
        with patch.object(installer, "get_latest_release_url") as download:
            installer.install(str(self.binary))
        download.assert_not_called()
        install.assert_called_once_with(str(self.binary))
        command.assert_called_once_with(["sudo", "systemctl", "daemon-reload"], check=True)


class CollectorCacheTests(unittest.TestCase):
    @patch.object(collector, "check_source")
    @patch.object(collector, "validate_binary", side_effect=lambda value: value)
    @patch.object(collector.subprocess, "Popen")
    def test_verified_cache_avoids_building(self, build, _validate, _source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "security-spectrum" / f"fluent-bit-{collector.REVISION[:9]}-{platform.machine()}"
            binary = base / "build/bin/fluent-bit"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"cached binary")
            (base / "build.json").write_text(json.dumps({
                "revision": collector.REVISION, "architecture": platform.machine(),
                "options": collector.CMAKE_OPTIONS, "sha256": collector.digest(binary),
            }))
            self.assertEqual(collector.build_collector(root, root), binary)
            build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
