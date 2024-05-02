# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, PropertyMock, patch

import yaml
from charm import CONFIG_FILE_NAME, NRF_RELATION_NAME, TLS_RELATION_NAME, NSSFOperatorCharm
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    ProviderCertificate,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

POD_IP = b"1.1.1.1"
PRIVATE_KEY = b"whatever key content"
VALID_NRF_URL = "http://nrf:8081"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_config/config.conf"
CSR_PATH = "support/TLS/nssf.csr"
KEY_PATH = "support/TLS/nssf.key"
CERT_PATH = "support/TLS/nssf.pem"
CONFIG_PATH = f"free5gc/config/{CONFIG_FILE_NAME}"
CERTIFICATES_LIB = (
    "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3"
)
STORED_CERTIFICATE = "whatever certificate content"
STORED_CSR = b"whatever csr content"
EXPECTED_PEBBLE_PLAN = {
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


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.namespace = "whatever"
        self.metadata = self._get_metadata()
        self.container_name = list(self.metadata["containers"].keys())[0]
        self.harness = testing.Harness(NSSFOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

    @staticmethod
    def _get_metadata() -> dict:
        """Read `charmcraft.yaml` and returns it as a dictionary.

        Returns:
            dics: charmcraft.yaml as a dictionary.
        """
        with open("charmcraft.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    @staticmethod
    def _read_file(path: str) -> str:
        """Read a file and returns as a string.

        Args:
            path (str): path to the file.

        Returns:
            str: content of the file.
        """
        with open(path, "r") as f:
            content = f.read()
        return content

    def _create_nrf_relation(self) -> int:
        """Create NRF relation.

        Returns:
            int: relation id.
        """
        relation_id = self.harness.add_relation(
            relation_name=NRF_RELATION_NAME, remote_app="nrf-operator"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="nrf-operator/0")
        return relation_id

    def _create_certificates_relation(self) -> int:
        """Create certificates relation.

        Returns:
            int: relation id.
        """
        relation_id = self.harness.add_relation(
            relation_name=TLS_RELATION_NAME, remote_app="tls-certificates-operator"
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="tls-certificates-operator/0"
        )
        return relation_id

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    def test_given_certificates_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_nrf_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for certificates relation"),
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_nssf_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self, _, patched_nrf_url, patch_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self._create_certificates_relation()
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        nrf_relation_id = self._create_nrf_relation()

        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(nrf_relation_id)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_nssf_charm_in_active_status_when_certificates_relation_breaks_then_status_is_blocked(  # noqa: E501
        self, _, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self._create_nrf_relation()
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        cert_rel_id = self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())
        self.harness.remove_relation(cert_rel_id)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.charm.unit.status, BlockedStatus("Waiting for certificates relation")
        )

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_container_cannot_connect_when_certificates_relation_breaks_then_waiting_for_container_to_start(  # noqa: E501
        self, _, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        self._create_nrf_relation()
        patch_check_output.return_value = POD_IP
        patch_nrf_url.return_value = VALID_NRF_URL
        cert_rel_id = self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        patch_get_assigned_certificates.return_value = [provider_certificate]

        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.remove_relation(cert_rel_id)
        self.harness.set_can_connect(container=self.container_name, val=False)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.charm.unit.status, WaitingStatus("Waiting for container to start")
        )

    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(self):
        self.harness.add_relation(relation_name=NRF_RELATION_NAME, remote_app="some_nrf_app")
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for NRF data to be available")
        )

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_relation_created_and_nrf_data_available_and_config_storage_not_attached_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self, _, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)

        self._create_nrf_relation()
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        patch_get_assigned_certificates.return_value = [provider_certificate]

        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.charm.unit.status, WaitingStatus("Waiting for storage to be attached")
        )

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_relations_created_and_nrf_data_available_and_certs_storage_not_attached_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self, _, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)

        self._create_nrf_relation()
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        patch_get_assigned_certificates.return_value = [provider_certificate]

        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.charm.unit.status, WaitingStatus("Waiting for storage to be attached")
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_relations_created_and_nrf_data_available_and_certificates_not_stored_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
        _,
        patch_nrf_url,
        patch_check_output,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)

        self._create_nrf_relation()
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_certificates_relation()

        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.charm.unit.status, WaitingStatus("Waiting for certificates to be stored")
        )

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_relations_created_and_nrf_data_available_and_certificates_stored_when_pebble_ready_then_config_file_rendered_and_pushed(  # noqa: E501
        self,
        patch_nrf_url,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_generate_private_key.return_value = PRIVATE_KEY
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)

        self.harness.container_pebble_ready(self.container_name)

        with open(EXPECTED_CONFIG_FILE_PATH) as expected_config_file:
            expected_content = expected_config_file.read()
        self.assertEqual((root / KEY_PATH).read_text(), PRIVATE_KEY.decode())
        self.assertEqual((root / CERT_PATH).read_text(), STORED_CERTIFICATE)
        self.assertEqual((root / CONFIG_PATH).read_text(), expected_content.strip())

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_config_pushed_but_content_changed_when_pebble_ready_then_new_config_content_is_pushed(  # noqa: E501
        self,
        patch_nrf_url,
        patch_generate_private_key,
        patch_check_output,
        patch_generate_csr,
        patch_get_assigned_certificates,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_generate_private_key.return_value = PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("Dummy content")

        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_certificates_relation()
        self._create_nrf_relation()

        self.harness.container_pebble_ready("nssf")

        with open(EXPECTED_CONFIG_FILE_PATH) as expected_config_file:
            expected_content = expected_config_file.read()
        self.assertEqual((root / KEY_PATH).read_text(), PRIVATE_KEY.decode())
        self.assertEqual((root / CERT_PATH).read_text(), STORED_CERTIFICATE)
        self.assertEqual((root / CONFIG_PATH).read_text(), expected_content.strip())

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_relations_available_and_config_pushed_when_pebble_ready_then_pebble_layer_is_added_correctly(  # noqa: E501
        self, _, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.container_pebble_ready(self.container_name)
        updated_plan = self.harness.get_container_pebble_plan(self.container_name).to_dict()
        self.assertEqual(EXPECTED_PEBBLE_PLAN, updated_plan)

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_status_is_active(  # noqa: E501
        self, _, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / KEY_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self, _, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_check_output.return_value = "".encode()
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        patch_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_service_is_restarted(  # noqa: E501
        self, patch_restart, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())
        patch_restart.assert_called_with(self.container_name)

    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("ops.model.Container.restart")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    def test_relations_available_and_config_pushed_and_pebble_layer_already_applied_when_pebble_ready_then_service_is_not_restarted(  # noqa: E501
        self,
        patch_check_output,
        patch_get_assigned_certificates,
        patch_nrf_url,
        patch_restart,
        patch_generate_private_key,
        patch_generate_csr,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_generate_private_key.return_value = PRIVATE_KEY
        patch_generate_csr.return_value = STORED_CSR

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        patch_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text(self._read_file(EXPECTED_CONFIG_FILE_PATH))

        patch_nrf_url.return_value = VALID_NRF_URL
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)
        patch_restart.assert_not_called()

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_config_pushed_but_content_changed_and_layer_already_applied_when_pebble_ready_then_nssf_service_is_restarted(  # noqa: E501
        self, patch_restart, patch_nrf_url, patch_check_output, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(self.container_name)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text(self._read_file(EXPECTED_CONFIG_FILE_PATH))

        patch_check_output.return_value = b"1.2.3.4"
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus(""))
        patch_restart.assert_called_once_with(self.container_name)

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_cannot_connect_to_container_when_nrf_available_then_status_is_waiting(
        self, patch_nrf_url
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_certificates_relation()
        self._create_nrf_relation()
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for container to start"),
        )

    def test_given_cannot_connect_to_container_when_certificates_relation_changed_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for container to start"),
        )

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("charm.check_output")
    def test_given_can_connect_and_private_key_doesnt_exist_when_certificates_relation_joined_then_private_key_is_generated(  # noqa: E501
        self, patch_check_output, patch_generate_private_key, patch_generate_csr, patched_nrf_url
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)

        patch_generate_private_key.return_value = PRIVATE_KEY
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_generate_csr.return_value = STORED_CSR
        patched_nrf_url.return_value = VALID_NRF_URL

        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)

        self.assertEqual((root / KEY_PATH).read_text(), PRIVATE_KEY.decode())

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with self.assertRaises(FileNotFoundError):
            (root / CERT_PATH).read_text()
        with self.assertRaises(FileNotFoundError):
            (root / KEY_PATH).read_text()
        with self.assertRaises(FileNotFoundError):
            (root / CSR_PATH).read_text()

    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_check_output, patch_generate_csr, patched_nrf_url
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())

        patch_generate_csr.return_value = STORED_CSR
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.assertEqual((root / CSR_PATH).read_text(), STORED_CSR.decode())

    @patch(
        f"{CERTIFICATES_LIB}.request_certificate_creation",
    )
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.generate_csr")
    @patch("charm.check_output")
    def test_given_private_key_exists_and_certificate_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        patch_check_output,
        patch_generate_csr,
        patched_nrf_url,
        patch_request_certificate_creation,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())

        patch_generate_csr.return_value = STORED_CSR
        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL

        self._create_nrf_relation()
        self._create_certificates_relation()

        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=STORED_CSR
        )

    @patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    def test_given_certificate_already_requested_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self, patch_check_output, patched_nrf_url, patch_request_certificate_creation
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_certificates_relation()

        patch_request_certificate_creation.assert_not_called()

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self, patch_check_output, patched_nrf_url, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        patch_get_assigned_certificates.return_value = [provider_certificate]

        self.harness.container_pebble_ready(self.container_name)

        self.assertEqual((root / CERT_PATH).read_text(), STORED_CERTIFICATE)

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_status_is_waiting(
        self, patch_check_output, patched_nrf_url, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = "Relation CSR content (different from stored one)"
        patch_get_assigned_certificates.return_value = [provider_certificate]

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for certificates to be stored"),
        )

    @patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    @patch("charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("charm.check_output")
    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_cert_is_not_pushed(
        self, patch_check_output, patched_nrf_url, patch_get_assigned_certificates
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        root = self.harness.get_filesystem_root(self.container_name)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())

        patch_check_output.return_value = POD_IP
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = "Relation CSR content (different from stored one)"
        patch_get_assigned_certificates.return_value = [provider_certificate]

        self.harness.container_pebble_ready(self.container_name)

        with self.assertRaises(FileNotFoundError):
            (root / CERT_PATH).read_text()
