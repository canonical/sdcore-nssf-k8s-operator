# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer
from scenario import Container, Context, Model, Mount, Relation, State  # type: ignore[import]

from charm import NSSFOperatorCharm


@patch("charm.KubernetesServicePatch", new=Mock)
class TestCharm(unittest.TestCase):
    def setUp(self):
        self.ctx = Context(NSSFOperatorCharm)
        self.container = Container(name="nssf", can_connect=True)
        self.nrf_relation = Relation(
            endpoint="fiveg_nrf",
            remote_app_name="remote",
            remote_app_data={"url": "http://nrf:8081"},
        )
        self.tls_relation = Relation(
            endpoint="certificates",
            remote_app_name="tls-provider",
        )

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        state_in = State(containers=[self.container], leader=True)

        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(
        self,
    ):
        nrf_relation = Relation("fiveg_nrf")
        state_in = State(
            leader=True,
            containers=[self.container],
            relations=[nrf_relation],
        )

        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for NRF data to be available"),
        )
        self.assertEqual(
            state_out.deferred[0].name,
            "nssf_pebble_ready",
        )

    def test_given_relation_created_and_nrf_data_available_and_storage_not_attached_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
    ):
        state_in = State(
            leader=True,
            containers=[self.container],
            relations=[self.nrf_relation],
        )

        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for storage to be attached"),
        )
        self.assertEqual(
            state_out.deferred[0].name,
            "nssf_pebble_ready",
        )

    @patch("charm.check_output")
    def test_given_relations_created_and_nrf_data_available_when_pebble_ready_then_config_file_rendered_and_pushed(  # noqa: E501
        self,
        patch_check_output,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = b"1.1.1.1"

        self.ctx.run(container.pebble_ready_event, state_in)

        with (
            open(Path(config_dir.name) / "nssfcfg.conf") as actual,
            open(Path(__file__).parent / "expected_config" / "config.conf") as expected,
        ):
            actual_content = actual.read()
            expected_content = expected.read().strip()
            self.assertEqual(actual_content, expected_content)

    @patch("charm.check_output")
    def test_config_pushed_but_content_changed_when_pebble_ready_then_new_config_content_is_pushed(  # noqa: E501
        self,
        patch_check_output,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = "1.1.1.1".encode()
        with open(Path(config_dir.name) / "nssfcfg.conf", "w") as existing_config:
            existing_config.write("never gonna give you up")

        self.ctx.run(container.pebble_ready_event, state_in)

        with (
            open(Path(config_dir.name) / "nssfcfg.conf") as actual,
            open(Path(__file__).parent / "expected_config" / "config.conf") as expected,
        ):
            actual_content = actual.read()
            expected_content = expected.read().strip()
            self.assertEqual(actual_content, expected_content)

    @patch("charm.check_output")
    def test_given_relation_available_and_config_pushed_when_pebble_ready_then_pebble_layer_is_added_correctly(  # noqa: E501
        self,
        patch_check_output,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        expected_plan = {
            "services": {
                "nssf": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "/bin/nssf --nssfcfg /free5gc/config/nssfcfg.conf",
                    "environment": {
                        "GOTRACEBACK": "crash",
                        "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                        "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                        "GRPC_TRACE": "all",
                        "GRPC_VERBOSITY": "DEBUG",
                        "POD_IP": "1.1.1.1",
                        "MANAGED_BY_CONFIG_POD": "true",
                    },
                }
            }
        }
        updated_plan = state_out.containers[0].layers["nssf"]
        self.assertEqual(expected_plan, updated_plan)

    @patch("charm.check_output")
    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_status_is_active(  # noqa: E501
        self,
        patch_check_output,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            ActiveStatus(),
        )

    @patch("charm.check_output")
    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        patch_check_output,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
        )
        patch_check_output.return_value = "".encode()

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_service_is_restarted(  # noqa: E501
        self,
        patch_check_output,
        patch_restart,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        self.ctx.run(container.pebble_ready_event, state_in)

        patch_restart.assert_called_with("nssf")

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    def test_relations_available_and_config_pushed_and_pebble_layer_already_applied_when_pebble_ready_then_service_is_not_restarted(  # noqa: E501
        self,
        patch_check_output,
        patch_restart,
    ):
        applied_plan = Layer(
            {
                "services": {
                    "nssf": {
                        "startup": "enabled",
                        "override": "replace",
                        "command": "/bin/nssf --nssfcfg /free5gc/config/nssfcfg.conf",
                        "environment": {
                            "GOTRACEBACK": "crash",
                            "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                            "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                            "GRPC_TRACE": "all",
                            "GRPC_VERBOSITY": "DEBUG",
                            "POD_IP": "1.1.1.1",
                            "MANAGED_BY_CONFIG_POD": "true",
                        },
                    }
                }
            }
        )
        container = self.container.replace(
            mounts={
                "config_dir": Mount(
                    "/free5gc/config/nssfcfg.conf",
                    Path(__file__).parent / "expected_config" / "config.conf",
                )
            },
            layers={"nssf": applied_plan},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        self.ctx.run(container.pebble_ready_event, state_in)

        patch_restart.assert_not_called()

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    def test_config_pushed_but_content_changed_and_layer_already_applied_when_pebble_ready_then_nssf_service_is_restarted(  # noqa: E501
        self,
        patch_check_output,
        patch_restart,
    ):
        config_dir = tempfile.TemporaryDirectory()
        applied_plan = Layer(
            {
                "services": {
                    "nssf": {
                        "startup": "enabled",
                        "override": "replace",
                        "command": "/bin/nssf --nssfcfg /free5gc/config/nssfcfg.conf",
                        "environment": {
                            "GOTRACEBACK": "crash",
                            "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                            "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                            "GRPC_TRACE": "all",
                            "GRPC_VERBOSITY": "DEBUG",
                            "POD_IP": "1.1.1.1",
                            "MANAGED_BY_CONFIG_POD": "true",
                        },
                    }
                }
            }
        )
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
            layers={"nssf": applied_plan},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        self.ctx.run(container.pebble_ready_event, state_in)

        patch_restart.assert_called_with("nssf")

    def test_given_cannot_connect_to_container_when_nrf_available_then_status_is_waiting(
        self,
    ):
        container = self.container.replace(can_connect=False)
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
        )

        state_out = self.ctx.run(self.nrf_relation.changed_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for container to start"),
        )
        self.assertEqual(
            state_out.deferred[0].name,
            "nrf_available",
        )

    @patch("charm.generate_private_key")
    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, patch_generate_private_key
    ):
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"cert_dir": Mount("/support/TLS", cert_dir.name)},
        )
        private_key = b"private key content"
        patch_generate_private_key.return_value = private_key
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        self.ctx.run(self.tls_relation.created_event, state_in)

        with open(Path(cert_dir.name) / "nssf.key") as nssf_key_file:
            actual_content = nssf_key_file.read()
            self.assertEqual(actual_content, private_key.decode())

    @patch("charm.check_output")
    @patch("ops.model.Container.remove_path")
    @patch("ops.model.Container.exists")
    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self, patch_exists, patch_remove_path, patch_check_output
    ):
        patch_check_output.return_value = "1.1.1.1".encode()
        patch_exists.return_value = True
        state_in = State(
            leader=True,
            containers=[self.container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        self.ctx.run(self.tls_relation.broken_event, state_in)

        patch_remove_path.assert_any_call(path="/support/TLS/nssf.pem")
        patch_remove_path.assert_any_call(path="/support/TLS/nssf.key")
        patch_remove_path.assert_any_call(path="/support/TLS/nssf.csr")

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
        new=Mock,
    )
    @patch("charm.generate_csr")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_generate_csr
    ):
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"cert_dir": Mount("/support/TLS", cert_dir.name)},
        )
        with open(Path(cert_dir.name) / "nssf.key", "w") as nssf_key_file:
            nssf_key_file.write("never gonna let you down")
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )
        self.ctx.run(self.tls_relation.joined_event, state_in)

        with open(Path(cert_dir.name) / "nssf.csr") as nssf_csr_file:
            actual_content = nssf_csr_file.read()
            self.assertEqual(actual_content, csr.decode())

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.generate_csr")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_cert_is_requested(
        self,
        patch_generate_csr,
        patch_request_certificate_creation,
    ):
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"cert_dir": Mount("/support/TLS", cert_dir.name)},
        )
        with open(Path(cert_dir.name) / "nssf.key", "w") as nssf_key_file:
            nssf_key_file.write("never gonna run around and desert you")
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        self.ctx.run(self.tls_relation.joined_event, state_in)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)

    @patch("charm.check_output")
    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
        patch_check_output,
    ):
        csr = "never gonna make you cry"
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"cert_dir": Mount("/support/TLS", cert_dir.name)},
        )
        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)
        patch_check_output.return_value = b"1.2.3.4"

        certificate = "Whatever certificate content"
        tls_relation = Relation(
            endpoint="certificates",
            remote_app_name="tls-provider",
            local_unit_data={
                "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": csr,
                            "ca": "abc",
                            "chain": ["abc", "def"],
                        }
                    ]
                )
            },
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, tls_relation],
        )

        self.ctx.run(tls_relation.changed_event, state_in)

        with open(Path(cert_dir.name) / "nssf.pem") as nssf_pem_file:
            actual_content = nssf_pem_file.read()
            self.assertEqual(actual_content, certificate)

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self,
    ):
        stored_csr = "never gonna say goodbye"
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"cert_dir": Mount("/support/TLS", cert_dir.name)},
        )
        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(stored_csr)

        relation_csr = "CSR in relation data (different from stored)"
        certificate = "Whatever certificate content"
        tls_relation = Relation(
            endpoint="certificates",
            remote_app_name="tls-provider",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": relation_csr}]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": certificate,
                            "certificate_signing_request": relation_csr,
                            "ca": "abc",
                            "chain": ["abc", "def"],
                        }
                    ]
                )
            },
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, tls_relation],
        )

        self.ctx.run(tls_relation.changed_event, state_in)

        with pytest.raises(FileNotFoundError):
            open(Path(cert_dir.name) / "nssf.pem")
