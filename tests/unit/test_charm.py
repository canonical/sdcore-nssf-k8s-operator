# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    ProviderCertificate,
)
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer
from scenario import Container, Context, Model, Mount, Relation, State  # type: ignore[import]

from charm import NSSFOperatorCharm

CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"


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

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(self):
        state_in = State(containers=[self.container], leader=True)

        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    def test_given_certificates_relation_not_created_when_pebble_ready_then_status_is_blocked(
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
            BlockedStatus("Waiting for certificates relation"),
        )

    @patch("charm.check_output")
    def test_given_nssf_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self, patch_check_output
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
            unit_status=ActiveStatus(),
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        state_out = self.ctx.run(self.nrf_relation.broken_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    def test_given_nssf_charm_in_active_status_when_certificates_relation_breaks_then_status_is_blocked(  # noqa: E501
        self,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
            unit_status=ActiveStatus(),
        )

        state_out = self.ctx.run(self.tls_relation.broken_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            BlockedStatus("Waiting for certificates relation"),
        )

    def test_given_container_cannot_connect_when_certificates_relation_breaks_then_event_defer(  # noqa: E501
        self,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
            can_connect=False,
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        state_out = self.ctx.run(self.tls_relation.broken_event, state_in)

        self.assertEqual(state_out.deferred[0].name, "certificates_relation_broken")

    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(self):
        nrf_relation = Relation("fiveg_nrf")
        state_in = State(
            leader=True,
            containers=[self.container],
            relations=[nrf_relation, self.tls_relation],
        )

        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for NRF data to be available"),
        )

    def test_given_relation_created_and_nrf_data_available_and_config_storage_not_attached_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
    ):
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"cert_dir": Mount("/support/TLS", cert_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for storage to be attached"),
        )
        self.assertEqual(len(state_out.deferred), 0)

    def test_given_relations_created_and_nrf_data_available_and_certs_storage_not_attached_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
    ):
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for storage to be attached"),
        )
        self.assertEqual(len(state_out.deferred), 0)

    @patch("charm.check_output")
    def test_given_relations_created_and_nrf_data_available_and_certificates_not_stored_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self, patch_check_output
    ):
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        patch_check_output.return_value = b"1.1.1.1"
        state_out = self.ctx.run(self.container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for certificates to be stored"),
        )

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("charm.check_output")
    def test_given_relations_created_and_nrf_data_available_and_certificates_stored_when_pebble_ready_then_config_file_rendered_and_pushed(  # noqa: E501
        self, patch_check_output, patch_get_assigned_certificates
    ):
        csr = "whatever csr content"
        certificate = "Whatever certificate content"
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )

        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
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

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("charm.check_output")
    def test_config_pushed_but_content_changed_when_pebble_ready_then_new_config_content_is_pushed(  # noqa: E501
        self, patch_check_output, patch_get_assigned_certificates
    ):
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        certificate = "Whatever certificate content"
        csr = "never gonna say goodbye"

        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        with open(Path(config_dir.name) / "nssfcfg.conf", "w") as existing_config:
            existing_config.write("never gonna give you up")

        state_out = self.ctx.run(container.pebble_ready_event, state_in)
        self.assertEqual(
            state_out.unit_status,
            ActiveStatus(),
        )
        with (
            open(Path(config_dir.name) / "nssfcfg.conf") as actual,
            open(Path(__file__).parent / "expected_config" / "config.conf") as expected,
        ):
            actual_content = actual.read()
            expected_content = expected.read().strip()
            self.assertEqual(actual_content, expected_content)

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("charm.check_output")
    def test_given_relations_available_and_config_pushed_when_pebble_ready_then_pebble_layer_is_added_correctly(  # noqa: E501
        self, patch_check_output, patch_get_assigned_certificates
    ):
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        csr = "never gonna say goodbye"
        certificate = "Whatever certificate content"
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)
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

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("charm.check_output")
    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_status_is_active(  # noqa: E501
        self, patch_check_output, patch_get_assigned_certificates
    ):
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        csr = "never gonna say goodbye"
        certificate = "Whatever certificate content"

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(state_out.unit_status, ActiveStatus())

    @patch("charm.check_output")
    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self, patch_check_output
    ):
        config_dir = tempfile.TemporaryDirectory()
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )
        patch_check_output.return_value = "".encode()

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_service_is_restarted(  # noqa: E501
        self, patch_check_output, patch_restart, patch_get_assigned_certificates
    ):

        config_dir = tempfile.TemporaryDirectory()
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        csr = "never gonna say goodbye"
        certificate = "Whatever certificate content"

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)

        with open(Path(cert_dir.name) / "nssf.pem", "w") as nssf_cert_file:
            nssf_cert_file.write(certificate)
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        self.ctx.run(container.pebble_ready_event, state_in)

        patch_restart.assert_called_with("nssf")

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    def test_relations_available_and_config_pushed_and_pebble_layer_already_applied_when_pebble_ready_then_service_is_not_restarted(  # noqa: E501
        self, patch_check_output, patch_restart, patch_get_assigned_certificates
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
        cert_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount(
                    "/free5gc/config/nssfcfg.conf",
                    Path(__file__).parent / "expected_config" / "config.conf",
                ),
            },
            layers={"nssf": applied_plan},
        )
        csr = "never gonna say goodbye"
        certificate = "Whatever certificate content"
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)

        with open(Path(cert_dir.name) / "nssf.pem", "w") as nssf_cert_file:
            nssf_cert_file.write(certificate)

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        self.ctx.run(container.pebble_ready_event, state_in)

        patch_restart.assert_not_called()

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    def test_config_pushed_but_content_changed_and_layer_already_applied_when_pebble_ready_then_nssf_service_is_restarted(  # noqa: E501
        self, patch_check_output, patch_restart, patch_get_assigned_certificates
    ):
        config_dir = tempfile.TemporaryDirectory()
        cert_dir = tempfile.TemporaryDirectory()
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
        csr = "never gonna make you cry"
        container = self.container.replace(
            mounts={
                "config_dir": Mount("/free5gc/config", config_dir.name),
                "cert_dir": Mount("/support/TLS", cert_dir.name),
            },
            layers={"nssf": applied_plan},
        )
        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)

        certificate = "Whatever certificate content"

        with open(Path(cert_dir.name) / "nssf.pem", "w") as nssf_cert_file:
            nssf_cert_file.write(certificate)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        self.ctx.run(container.pebble_ready_event, state_in)

        patch_restart.assert_called_with("nssf")

    def test_given_cannot_connect_to_container_when_nrf_available_then_status_is_waiting(self):
        container = self.container.replace(can_connect=False)
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation],
        )

        state_out = self.ctx.run(self.nrf_relation.changed_event, state_in)

        self.assertEqual(state_out.unit_status, WaitingStatus("Waiting for container to start"))

    def test_given_cannot_connect_to_container_when_certificates_relation_changed_then_status_is_waiting(  # noqa: E501
        self,
    ):
        container = self.container.replace(can_connect=False)
        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        state_out = self.ctx.run(self.tls_relation.joined_event, state_in)

        self.assertEqual(state_out.unit_status, WaitingStatus("Waiting for container to start"))

    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    def test_given_can_connect_and_private_key_doesnt_exist_when_certificates_relation_joined_then_private_key_is_generated(  # noqa: E501
        self, patch_generate_private_key, patch_check_output
    ):
        patch_check_output.return_value = "1.1.1.1".encode()
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        private_key = b"private key content"
        patch_generate_private_key.return_value = private_key
        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write("some csr")

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        self.ctx.run(self.tls_relation.joined_event, state_in)

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
        f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation",  # noqa: E501
        new=Mock,
    )
    @patch("charm.check_output")
    @patch("charm.generate_csr")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_generate_csr, patch_check_output
    ):
        patch_check_output.return_value = "1.1.1.1".encode()
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
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
        f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.check_output")
    @patch("charm.generate_csr")
    def test_given_private_key_exists_and_certificate_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        patch_generate_csr,
        patch_check_output,
        patch_request_certificate_creation,
    ):
        patch_check_output.return_value = "1.1.1.1".encode()
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
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

    @patch(
        f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.check_output")
    def test_given_certificate_already_requested_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self,
        patch_check_output,
        patch_request_certificate_creation,
    ):
        patch_check_output.return_value = "1.1.1.1".encode()
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )
        with open(Path(cert_dir.name) / "nssf.key", "w") as nssf_key_file:
            nssf_key_file.write("never gonna run around and desert you")
        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write("whatever csr content")

        state_in = State(
            leader=True,
            containers=[container],
            relations=[self.nrf_relation, self.tls_relation],
        )

        self.ctx.run(self.tls_relation.joined_event, state_in)

        patch_request_certificate_creation.assert_not_called()

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("charm.check_output")
    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self, patch_check_output, patch_get_assigned_certificates
    ):
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
        )

        patch_check_output.return_value = b"1.2.3.4"
        csr = "never gonna make you cry"
        certificate = "Whatever certificate content"
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = certificate
        provider_certificate.csr = csr
        patch_get_assigned_certificates.return_value = [provider_certificate]

        with open(Path(cert_dir.name) / "nssf.csr", "w") as nssf_csr_file:
            nssf_csr_file.write(csr)

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

    @patch(f"{CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("charm.check_output")
    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_status_is_waiting(  # noqa: E501
        self, patch_check_output, patch_get_assigned_certificates
    ):
        patch_check_output.return_value = b"1.2.3.4"
        stored_csr = "never gonna say goodbye"
        cert_dir = tempfile.TemporaryDirectory()
        config_dir = tempfile.TemporaryDirectory()
        container = self.container.replace(
            mounts={
                "cert_dir": Mount("/support/TLS", cert_dir.name),
                "config_dir": Mount("/free5gc/config", config_dir.name),
            },
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

        state_out = self.ctx.run(tls_relation.changed_event, state_in)
        self.assertEqual(
            state_out.unit_status,
            WaitingStatus("Waiting for certificates to be stored"),
        )

        with pytest.raises(FileNotFoundError):
            open(Path(cert_dir.name) / "nssf.pem")
