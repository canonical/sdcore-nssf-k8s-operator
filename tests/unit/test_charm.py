# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import os
from typing import Generator
from unittest.mock import Mock, PropertyMock, patch

import pytest
import yaml
from charm import CONFIG_FILE_NAME, NRF_RELATION_NAME, TLS_RELATION_NAME, NSSFOperatorCharm
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    ProviderCertificate,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

CONTAINER_NAME = "nssf"
NAMESPACE = "whatever"
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
WEBUI_URL = "sdcore-webui:9876"
SDCORE_CONFIG_RELATION_NAME = "sdcore-config"
NMS_APPLICATION_NAME = "sdcore-nms-operator"
EXPECTED_PEBBLE_PLAN = {
    "services": {
        CONTAINER_NAME: {
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


class TestCharm:
    patcher_check_output = patch("charm.check_output")
    patcher_nrf_url = patch(
        "charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock
    )
    patcher_webui_url = patch(
        "charms.sdcore_nms_k8s.v0.sdcore_config.SdcoreConfigRequires.webui_url",
        new_callable=PropertyMock,
    )
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_assigned_certificates = patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"
    )
    patcher_request_certificate_creation = patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    patcher_restart = patch("ops.model.Container.restart")

    @pytest.fixture()
    def setup(self):
        self.mock_check_output = TestCharm.patcher_check_output.start()
        self.mock_check_output.return_value = POD_IP
        self.mock_nrf_url = TestCharm.patcher_nrf_url.start()
        self.mock_nrf_url.return_value = VALID_NRF_URL
        self.mock_generate_csr = TestCharm.patcher_generate_csr.start()
        self.mock_generate_csr.return_value = STORED_CSR
        self.mock_generate_private_key = TestCharm.patcher_generate_private_key.start()
        self.mock_generate_private_key.return_value = PRIVATE_KEY
        self.mock_get_assigned_certificates = TestCharm.patcher_get_assigned_certificates.start()
        self.mock_request_certificate_creation = (
            TestCharm.patcher_request_certificate_creation.start()
        )
        self.mock_restart = TestCharm.patcher_restart.start()
        self.mock_webui_url = TestCharm.patcher_webui_url.start()

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def create_harness(self, setup, request):
        self.harness = testing.Harness(NSSFOperatorCharm)
        self.harness.set_model_name(name=NAMESPACE)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.teardown)

    @pytest.fixture()
    def add_storage(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

    @pytest.fixture()
    def fiveg_nrf_relation_id(self) -> Generator[int, None, None]:
        relation_id = self.harness.add_relation(
            relation_name=NRF_RELATION_NAME,
            remote_app="whatever-nrf",
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="whatever-nrf/0")
        yield relation_id

    @pytest.fixture()
    def certificates_relation_id(self) -> Generator[int, None, None]:
        relation_id = self.harness.add_relation(
            relation_name=TLS_RELATION_NAME,
            remote_app="tls-certificates-operator",
        )
        yield relation_id

    @pytest.fixture()
    def sdcore_config_relation_id(self) -> Generator[int, None, None]:
        sdcore_config_relation_id = self.harness.add_relation(  # type:ignore
            relation_name=SDCORE_CONFIG_RELATION_NAME,
            remote_app=NMS_APPLICATION_NAME,
        )
        self.harness.add_relation_unit(  # type:ignore
            relation_id=sdcore_config_relation_id, remote_unit_name=f"{NMS_APPLICATION_NAME}/0"
        )
        self.harness.update_relation_data(  # type:ignore
            relation_id=sdcore_config_relation_id,
            app_or_unit=NMS_APPLICATION_NAME,
            key_values={
                "webui_url": WEBUI_URL,
            },
        )
        yield sdcore_config_relation_id

    @staticmethod
    def _get_metadata() -> dict:
        """Read `charmcraft.yaml` and returns it as a dictionary."""
        with open("charmcraft.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    @staticmethod
    def _read_file(path: str) -> str:
        """Read a file and returns as a string."""
        with open(path, "r") as f:
            content = f.read()
        return content

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self, certificates_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation(s)")

    def test_given_certificates_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self, fiveg_nrf_relation_id, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for certificates relation(s)"
        )

    def test_given_sdcore_config_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self, fiveg_nrf_relation_id, certificates_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore-config relation(s)"
        )

    def test_given_nssf_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self,
        add_storage,
        fiveg_nrf_relation_id,
        sdcore_config_relation_id,
        certificates_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.harness.remove_relation(fiveg_nrf_relation_id)
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation(s)")

    def test_given_nssf_charm_in_active_status_when_certificates_relation_breaks_then_status_is_blocked(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == ActiveStatus()
        self.harness.remove_relation(certificates_relation_id)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == BlockedStatus(
            "Waiting for certificates relation(s)"
        )

    def test_given_nssf_charm_in_active_status_when_sdcore_config_relation_breaks_then_status_is_blocked(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == ActiveStatus()
        self.harness.remove_relation(sdcore_config_relation_id)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == BlockedStatus(
            "Waiting for sdcore-config relation(s)"
        )

    def test_given_container_cannot_connect_when_certificates_relation_breaks_then_waiting_for_container_to_start(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.remove_relation(certificates_relation_id)
        self.harness.set_can_connect(container=CONTAINER_NAME, val=False)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == WaitingStatus("Waiting for container to start")

    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(
        self, fiveg_nrf_relation_id, certificates_relation_id, sdcore_config_relation_id
    ):
        self.mock_nrf_url.return_value = ""
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for NRF data to be available"
        )

    def test_given_webui_data_not_available_when_pebble_ready_then_status_is_waiting(
        self, fiveg_nrf_relation_id, certificates_relation_id, sdcore_config_relation_id
    ):
        self.mock_nrf_url.return_value = VALID_NRF_URL
        self.mock_webui_url.return_value = ""
        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for Webui data to be available"
        )

    @pytest.mark.parametrize("storage", ["certs", "config"])
    def test_given_relation_created_and_nrf_data_available_and_storage_not_attached_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self, fiveg_nrf_relation_id, certificates_relation_id, sdcore_config_relation_id, storage
    ):
        self.harness.add_storage(storage_name=storage, attach=True)

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == WaitingStatus(
            "Waiting for storage to be attached"
        )

    def test_given_relations_created_and_nrf_data_available_and_certificates_not_stored_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == WaitingStatus(
            "Waiting for certificates to be stored"
        )

    def test_given_relations_created_and_nrf_data_available_and_certificates_stored_when_pebble_ready_then_config_file_rendered_and_pushed(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        self.mock_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.mock_webui_url.return_value = WEBUI_URL
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)

        self.harness.container_pebble_ready(CONTAINER_NAME)

        with open(EXPECTED_CONFIG_FILE_PATH) as expected_config_file:
            expected_content = expected_config_file.read()
        assert (root / KEY_PATH).read_text() == PRIVATE_KEY.decode()
        assert (root / CERT_PATH).read_text() == STORED_CERTIFICATE
        assert (root / CONFIG_PATH).read_text() == expected_content.strip()

    def test_config_pushed_but_content_changed_when_pebble_ready_then_new_config_content_is_pushed(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_generate_csr.return_value = STORED_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.mock_webui_url.return_value = WEBUI_URL
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("Dummy content")

        self.harness.container_pebble_ready(CONTAINER_NAME)

        with open(EXPECTED_CONFIG_FILE_PATH) as expected_config_file:
            expected_content = expected_config_file.read()
        assert (root / KEY_PATH).read_text() == PRIVATE_KEY.decode()
        assert (root / CERT_PATH).read_text() == STORED_CERTIFICATE
        assert (root / CONFIG_PATH).read_text() == expected_content.strip()

    def test_given_relations_available_and_config_pushed_when_pebble_ready_then_pebble_layer_is_added_correctly(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.container_pebble_ready(CONTAINER_NAME)
        updated_plan = self.harness.get_container_pebble_plan(CONTAINER_NAME).to_dict()
        assert EXPECTED_PEBBLE_PLAN == updated_plan

    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_status_is_active(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / KEY_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == ActiveStatus()

    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        self.mock_check_output.return_value = "".encode()

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == WaitingStatus(
            "Waiting for pod IP address to be available"
        )

    def test_relations_available_and_config_pushed_and_pebble_updated_when_pebble_ready_then_service_is_restarted(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text("super different config file content")

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()
        self.mock_restart.assert_called_with(CONTAINER_NAME)

    def test_relations_available_and_config_pushed_and_pebble_layer_already_applied_when_pebble_ready_then_service_is_not_restarted(  # noqa: E501
        self, add_storage, fiveg_nrf_relation_id, certificates_relation_id
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text(self._read_file(EXPECTED_CONFIG_FILE_PATH))

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.mock_restart.assert_not_called()

    def test_config_pushed_but_content_changed_and_layer_already_applied_when_pebble_ready_then_nssf_service_is_restarted(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text(self._read_file(EXPECTED_CONFIG_FILE_PATH))

        self.mock_check_output.return_value = b"1.2.3.4"
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.mock_restart.assert_called_once_with(CONTAINER_NAME)

    def test_config_pushed_but_webui_data_changed_and_layer_already_applied_when_pebble_ready_then_nssf_service_is_restarted(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)
        (root / CONFIG_PATH).write_text(self._read_file(EXPECTED_CONFIG_FILE_PATH))

        self.mock_webui_url.return_value = "mywebui:9876"
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.mock_restart.assert_called_once_with(CONTAINER_NAME)

    def test_given_cannot_connect_to_container_then_status_is_waiting(
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus("Waiting for container to start")

    def test_given_can_connect_and_private_key_doesnt_exist_when_certificates_relation_joined_then_private_key_is_generated(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.container_pebble_ready(CONTAINER_NAME)

        assert (root / KEY_PATH).read_text() == PRIVATE_KEY.decode()

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)

        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with pytest.raises(FileNotFoundError):
            (root / CERT_PATH).read_text()
        with pytest.raises(FileNotFoundError):
            (root / KEY_PATH).read_text()
        with pytest.raises(FileNotFoundError):
            (root / CSR_PATH).read_text()

    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())

        self.harness.container_pebble_ready(CONTAINER_NAME)

        assert (root / CSR_PATH).read_text() == STORED_CSR.decode()

    def test_given_private_key_exists_and_certificate_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.harness.container_pebble_ready(CONTAINER_NAME)

        self.mock_request_certificate_creation.assert_called_with(
            certificate_signing_request=STORED_CSR
        )

    def test_given_certificate_already_requested_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self, add_storage, certificates_relation_id, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CERT_PATH).write_text(STORED_CERTIFICATE)

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_request_certificate_creation.assert_not_called()

    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = STORED_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        self.harness.container_pebble_ready(CONTAINER_NAME)

        assert (root / CERT_PATH).read_text() == STORED_CERTIFICATE

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_status_is_waiting(
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = "Relation CSR content (different from stored one)"
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        self.harness.container_pebble_ready(CONTAINER_NAME)
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for certificates to be stored"
        )

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_cert_is_not_pushed(
        self,
        add_storage,
        fiveg_nrf_relation_id,
        certificates_relation_id,
        sdcore_config_relation_id,
    ):
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / KEY_PATH).write_text(PRIVATE_KEY.decode())
        (root / CSR_PATH).write_text(STORED_CSR.decode())

        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = STORED_CERTIFICATE
        provider_certificate.csr = "Relation CSR content (different from stored one)"
        self.mock_get_assigned_certificates.return_value = [provider_certificate]

        self.harness.container_pebble_ready(CONTAINER_NAME)

        with pytest.raises(FileNotFoundError):
            (root / CERT_PATH).read_text()

    def test_given_no_workload_version_file_when_pebble_ready_then_workload_version_not_set(  # noqa: E501
        self,
        add_storage,
    ):
        self.harness.container_pebble_ready(container_name=CONTAINER_NAME)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == ""

    def test_given_workload_version_file_when_pebble_ready_then_workload_version_set(
        self,
    ):
        expected_version = "1.2.3"
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        os.mkdir(f"{root}/etc")
        (root / "etc/workload-version").write_text(expected_version)
        self.harness.container_pebble_ready(container_name=CONTAINER_NAME)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == expected_version
