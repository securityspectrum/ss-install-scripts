import io
import unittest
import zipfile
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch
from unittest.mock import mock_open

import install_agents
from agent_core.preflight import check_installation
from agent_core.secrets_manager import ContextName
from agent_core.ss_agent_installer import SSAgentInstaller


def archive(*names):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as target:
        for name in names:
            target.writestr(name, "test certificate")
    return output.getvalue()


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.context = {key: "test-value" for key in ContextName}
        self.context[ContextName.ORG_SLUG] = "northwest"
        self.config = {
            "organization_key": "test-value",
            "kafka": {"brokers": "localhost:9092", "topics": "events"},
            "key_server": {"host": "localhost", "port": 443, "path": "/api/v1/r/${client_id}/keys"},
            "backend_server": {"host": "localhost", "port": 443, "path": "/api/v1/r/${client_id}/fields"},
            "certificates": [{"certificate_uuid": "kafka", "principal": "test", "sasl_password": "test"}],
        }

    @patch("agent_core.preflight.requests.Session")
    def test_both_archives_are_checked_without_following_redirects(self, session):
        client = session.return_value.__enter__.return_value
        client.get.side_effect = [
            Mock(status_code=200, json=lambda: self.config),
            Mock(status_code=200, json=lambda: {"certificates": [{"uuid": "agent"}]}),
            Mock(status_code=200, content=archive("cacert.crt", "client.crt", "client.key")),
            Mock(status_code=200, content=archive("cacert.crt")),
            Mock(status_code=200, json=lambda: {"entries": []}),
            Mock(status_code=200, json=lambda: {"entries": [{"id": 1}]}),
        ]
        check_installation("https://localhost/api/v1/r/northwest", self.context)
        self.assertEqual(client.get.call_count, 6)
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in client.get.call_args_list))
        headers = client.get.call_args.kwargs["headers"]
        self.assertIsNone(headers["Authorization"])
        self.assertEqual(headers["X-API-SECRET-KEY"], "test-value")

    @patch("agent_core.preflight.requests.Session")
    def test_collector_redirect_fails_before_installation(self, session):
        client = session.return_value.__enter__.return_value
        client.get.side_effect = [
            Mock(status_code=200, json=lambda: self.config),
            Mock(status_code=200, json=lambda: {"certificates": [{"uuid": "agent"}]}),
            Mock(status_code=200, content=archive("cacert.crt", "client.crt", "client.key")),
            Mock(status_code=200, content=archive("cacert.crt")),
            Mock(status_code=200, json=lambda: {"entries": []}),
            Mock(status_code=301),
        ]
        with self.assertRaisesRegex(RuntimeError, "Preflight /keys: HTTP 301"):
            check_installation("https://localhost/api/v1/r/northwest", self.context)

    @patch("agent_core.preflight.requests.Session")
    def test_http_failure_does_not_include_response_body(self, session):
        client = session.return_value.__enter__.return_value
        client.get.return_value = Mock(status_code=401, text="private credentials")
        with self.assertRaisesRegex(RuntimeError, "HTTP 401") as error:
            check_installation("https://localhost/api/v1/r/northwest", self.context)
        self.assertNotIn("private credentials", str(error.exception))
        self.assertEqual(client.get.call_count, 1)

    @patch("agent_core.preflight.subprocess.run", return_value=SimpleNamespace(returncode=3))
    @patch("agent_core.preflight.platform.system", return_value="Linux")
    def test_keep_sensors_requires_active_service(self, _platform, command):
        with self.assertRaisesRegex(RuntimeError, "zeek must already be active"):
            check_installation("https://localhost", self.context, keep_existing_sensors=True)


class SystemdServiceTests(unittest.TestCase):
    @patch("agent_core.ss_agent_installer.SystemUtility.run_command_with_retries", return_value=Mock(returncode=0))
    def test_existing_unit_is_enabled_and_started_without_rewriting(self, command):
        installer = SSAgentInstaller()
        with patch.object(installer, "service_exists", return_value=True), patch("builtins.open") as write:
            installer.setup_systemd_service("/usr/local/bin/ss-agent")
        write.assert_not_called()
        self.assertEqual([item.args[0] for item in command.call_args_list], [
            ["sudo", "systemctl", "enable", "ss-agent"],
            ["sudo", "systemctl", "start", "ss-agent"],
        ])

    @patch("agent_core.ss_agent_installer.subprocess.run")
    @patch("agent_core.ss_agent_installer.SystemUtility.move_with_sudo")
    @patch("agent_core.ss_agent_installer.SystemUtility.run_command_with_retries", return_value=Mock(returncode=0))
    def test_new_unit_is_created_reloaded_enabled_and_started(self, command, move, _run):
        installer = SSAgentInstaller()
        with patch.object(installer, "service_exists", return_value=False), patch("builtins.open", mock_open()) as write:
            installer.setup_systemd_service("/usr/local/bin/ss-agent")
        self.assertIn("ExecStart=/usr/local/bin/ss-agent start", write().write.call_args.args[0])
        move.assert_called_once()
        self.assertEqual([item.args[0] for item in command.call_args_list], [
            ["sudo", "systemctl", "daemon-reload"],
            ["sudo", "systemctl", "enable", "ss-agent"],
            ["sudo", "systemctl", "start", "ss-agent"],
        ])

    @patch("agent_core.ss_agent_installer.SystemUtility.run_command_with_retries")
    def test_enable_or_start_failure_fails_installation(self, command):
        installer = SSAgentInstaller()
        for action, results in (("enable", [None]), ("start", [Mock(returncode=0), None])):
            with self.subTest(action=action), patch.object(installer, "service_exists", return_value=True):
                command.reset_mock(side_effect=True)
                command.side_effect = results
                with self.assertRaisesRegex(RuntimeError, f"Failed to {action} service 'ss-agent'"):
                    installer.setup_systemd_service("/usr/local/bin/ss-agent")
                self.assertEqual(command.call_count, len(results))


class InstallFlowTests(unittest.TestCase):
    def run_install(self, check):
        names = ("check_installation", "SystemUtility", "SecretsManager", "SSAgentInstaller",
                 "CertificateManager", "FluentBitInstaller", "FluentBitConfigurator",
                 "SSAgentConfigurator", "ZeekInstaller", "OsqueryInstaller")
        with ExitStack() as stack:
            mocks = {name: stack.enter_context(patch.object(install_agents, name)) for name in names}
            stack.enter_context(patch.object(install_agents.platform, "system", return_value="Linux"))
            stack.enter_context(patch.object(install_agents.subprocess, "run"))
            stack.enter_context(patch.object(install_agents.time, "sleep"))
            install_agents.install(SimpleNamespace(check=check, keep_existing_sensors=True, fluent_bit_binary=None))
        return mocks

    def test_check_does_not_elevate_or_install(self):
        mocks = self.run_install(check=True)
        mocks["check_installation"].assert_called_once()
        mocks["SystemUtility"].elevate_privileges.assert_not_called()
        mocks["SSAgentInstaller"].assert_not_called()
        mocks["FluentBitInstaller"].assert_not_called()

    def test_keep_sensors_does_not_stop_or_reconfigure_them(self):
        mocks = self.run_install(check=False)
        mocks["ZeekInstaller"].assert_not_called()
        mocks["OsqueryInstaller"].assert_not_called()
        agent = mocks["SSAgentInstaller"].return_value
        agent.stop_all_services_ss_agent.assert_not_called()
        agent.start_all_services_ss_agent.assert_not_called()
        agent.install.assert_called_once()
        mocks["FluentBitInstaller"].return_value.install.assert_called_once()


if __name__ == "__main__":
    unittest.main()
