#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core NSSF service for K8s."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import List, Optional, cast

from charms.loki_k8s.v1.loki_push_api import LogForwarder  # type: ignore[import]
from charms.sdcore_nrf_k8s.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.sdcore_webui_k8s.v0.sdcore_config import (  # type: ignore[import]
    SdcoreConfigRequires,
)
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    CertificateExpiringEvent,
    TLSCertificatesRequiresV3,
    generate_csr,
    generate_private_key,
)
from jinja2 import Environment, FileSystemLoader
from ops import (
    ActiveStatus,
    BlockedStatus,
    CollectStatusEvent,
    ModelError,
    RelationBrokenEvent,
    WaitingStatus,
)
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.pebble import Layer, PathError

logger = logging.getLogger(__name__)

SBI_PORT = 29531
CONFIG_DIR = "/free5gc/config"
CONFIG_FILE_NAME = "nssfcfg.conf"
CONFIG_TEMPLATE_DIR = "src/templates/"
CONFIG_TEMPLATE_NAME = "nssfcfg.conf.j2"
CERTS_DIR_PATH = "/support/TLS"  # Certificate paths are hardcoded in NSSF code
PRIVATE_KEY_NAME = "nssf.key"
CSR_NAME = "nssf.csr"
CERTIFICATE_NAME = "nssf.pem"
CERTIFICATE_COMMON_NAME = "nssf.sdcore"
LOGGING_RELATION_NAME = "logging"
TLS_RELATION_NAME = "certificates"
NRF_RELATION_NAME = "fiveg_nrf"
SDCORE_CONFIG_RELATION_NAME = "sdcore_config"


class NSSFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the SD-Core NSSF operator for K8s."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to perform if we're removing the
            # charm.
            return
        self._container_name = self._service_name = "nssf"
        self._container = self.unit.get_container(self._container_name)
        self._nrf_requires = NRFRequires(charm=self, relation_name=NRF_RELATION_NAME)
        self._webui_requires = SdcoreConfigRequires(
            charm=self, relation_name=SDCORE_CONFIG_RELATION_NAME
        )
        self.unit.set_ports(SBI_PORT)
        self._certificates = TLSCertificatesRequiresV3(self, TLS_RELATION_NAME)
        self._logging = LogForwarder(charm=self, relation_name=LOGGING_RELATION_NAME)
        self.framework.observe(self.on.config_changed, self._configure_nssf)
        self.framework.observe(self.on.update_status, self._configure_nssf)
        self.framework.observe(self.on.nssf_pebble_ready, self._configure_nssf)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_nssf)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_nssf)
        self.framework.observe(self.on.certificates_relation_joined, self._configure_nssf)
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(self._certificates.on.certificate_available, self._configure_nssf)
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self._webui_requires.on.webui_url_available,
            self._configure_nssf
        )
        self.framework.observe(self.on.sdcore_config_relation_joined, self._configure_nssf)

    def _on_collect_unit_status(self, event: CollectStatusEvent):  # noqa C901
        """Check the unit status and set to Unit when CollectStatusEvent is fired.

        Args:
            event: CollectStatusEvent
        """
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to perform if we're removing the
            # charm.
            event.add_status(BlockedStatus("Scaling is not implemented for this charm"))
            logger.info("Scaling is not implemented for this charm")
            return

        if not self._container.can_connect():
            event.add_status(WaitingStatus("Waiting for container to start"))
            logger.info("Waiting for container to start")
            return

        if invalid_configs := self._get_invalid_configs():
            event.add_status(
                BlockedStatus(f"The following configurations are not valid: {invalid_configs}")
            )
            logger.info("The following configurations are not valid: %s", invalid_configs)
            return

        if missing_relations := self._missing_relations():
            event.add_status(
                BlockedStatus(f"Waiting for {', '.join(missing_relations)} relation(s)")
            )
            logger.info("Waiting for %s  relation(s)", ', '.join(missing_relations))
            return

        if not self._nrf_data_is_available:
            event.add_status(WaitingStatus("Waiting for NRF data to be available"))
            logger.info("Waiting for NRF data to be available")
            return

        if not self._webui_requires.webui_url:
            event.add_status(WaitingStatus("Waiting for Webui data to be available"))
            logger.info("Waiting for Webui data to be available")
            return

        if not self._container.exists(path=CONFIG_DIR) or not self._container.exists(
            path=CERTS_DIR_PATH
        ):
            event.add_status(WaitingStatus("Waiting for storage to be attached"))
            logger.info("Waiting for storage to be attached")
            return

        if not _get_pod_ip():
            event.add_status(WaitingStatus("Waiting for pod IP address to be available"))
            logger.info("Waiting for pod IP address to be available")
            return

        if self._csr_is_stored() and not self._get_current_provider_certificate():
            event.add_status(WaitingStatus("Waiting for certificates to be stored"))
            logger.info("Waiting for certificates to be stored")
            return

        if not self._nssf_service_is_running():
            event.add_status(WaitingStatus("Waiting for NSSF service to start"))
            logger.info("Waiting for NSSF service to start")
            return

        event.add_status(ActiveStatus())

    def _ready_to_configure(self) -> bool:
        """Return whether the preconditions are met to proceed with the configuration.

        Returns:
            ready_to_configure: True if all conditions are met else False
        """
        if not self._container.can_connect():
            return False

        if self._get_invalid_configs():
            return False

        if self._missing_relations():
            return False

        if not self._nrf_data_is_available:
            return False

        if not self._storage_is_attached():
            return False

        if not _get_pod_ip():
            return False

        return True

    def _storage_is_attached(self) -> bool:
        """Return whether storage is attached to the workload container.

        Returns:
            bool: Whether storage is attached.
        """
        return self._container.exists(path=CONFIG_DIR) and self._container.exists(
            path=CERTS_DIR_PATH
        )

    def _missing_relations(self) -> List[str]:
        """Return list of missing relations.

        If all the relations are created, it returns an empty list.

        Returns:
            list: missing relation names.
        """
        missing_relations = []
        for relation in [NRF_RELATION_NAME,
                         TLS_RELATION_NAME,
                         SDCORE_CONFIG_RELATION_NAME]:
            if not self._relation_created(relation):
                missing_relations.append(relation)
        return missing_relations

    def _nssf_service_is_running(self) -> bool:
        """Check if the NSSF service is running.

        Returns:
            bool: Whether the NSSF service is running.
        """
        if not self._container.can_connect():
            return False
        try:
            service = self._container.get_service(self._service_name)
        except ModelError:
            return False
        return service.is_running()

    def _configure_nssf(self, _: EventBase) -> None:  # noqa: C901
        """Configure NSSF configuration file and pebble service.

        Args:
            _ (EventBase): Juju event
        """
        if not self._ready_to_configure():
            logger.info("The preconditions for the configuration are not met yet.")
            return

        if not self._private_key_is_stored():
            self._generate_private_key()

        if not self._csr_is_stored():
            self._request_new_certificate()

        provider_certificate = self._get_current_provider_certificate()
        if not provider_certificate:
            return

        if certificate_update_required := self._is_certificate_update_required(
            provider_certificate
        ):
            self._store_certificate(certificate=provider_certificate)

        desired_config_file = self._generate_nssf_config_file()
        if config_update_required := self._is_config_update_required(desired_config_file):
            self._push_config_file(content=desired_config_file)

        should_restart = config_update_required or certificate_update_required
        self._configure_pebble(restart=should_restart)

    def _is_config_update_required(self, content: str) -> bool:
        """Decide whether config update is required by checking existence and config content.

        Args:
            content (str): desired config file content

        Returns:
            True if config update is required else False
        """
        return not self._config_file_is_written() or not self._config_file_content_matches(
            content=content
        )

    def _config_file_is_written(self) -> bool:
        """Return whether the config file was written to the workload container.

        Returns:
            bool: Whether the config file was written.
        """
        return bool(self._container.exists(f"{CONFIG_DIR}/{CONFIG_FILE_NAME}"))

    def _configure_pebble(self, restart: bool = False) -> None:
        """Configure the Pebble layer.

        Args:
            restart (bool): Whether to restart the Pebble service. Defaults to False.
        """
        plan = self._container.get_plan()
        if plan.services != self._pebble_layer.services:
            self._container.add_layer(
                self._container_name, self._pebble_layer, combine=True
            )
            self._container.replan()
            logger.info("New layer added: %s", self._pebble_layer)
        if restart:
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)
            return

    def _is_certificate_update_required(self, provider_certificate) -> bool:
        """Check the provided certificate and existing certificate.

        Returns True if update is required.

        Args:
            provider_certificate: str
        Returns:
            True if update is required else False
        """
        return self._get_existing_certificate() != provider_certificate

    def _get_existing_certificate(self) -> str:
        """Return the existing certificate if present else empty string."""
        return self._get_stored_certificate() if self._certificate_is_stored() else ""

    def _generate_nssf_config_file(self) -> str:
        """Handle creation of the NSSF config file based on a given template.

        Returns:
            content (str): desired config file content
        """
        return self._render_config_file(
            sbi_port=SBI_PORT,
            nrf_url=self._nrf_requires.nrf_url,
            nssf_ip=_get_pod_ip(),  # type: ignore[arg-type]
            sst=self._get_sst_config(),  # type: ignore[arg-type]
            sd=self._get_sd_config(),  # type: ignore[arg-type]
            scheme="https",
            webui_uri=self._webui_requires.webui_url,
        )

    def _on_certificates_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Delete TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()

    def _get_current_provider_certificate(self) -> str | None:
        """Compare the current certificate request to what is in the interface.

        Returns The current valid provider certificate if present
        """
        csr = self._get_stored_csr()
        for provider_certificate in self._certificates.get_assigned_certificates():
            if provider_certificate.csr == csr:
                return provider_certificate.certificate
        return None

    def _update_certificate(self, provider_certificate) -> bool:
        """Compare the provided certificate to what is stored.

        Returns True if the certificate was updated
        """
        existing_certificate = (
            self._get_stored_certificate() if self._certificate_is_stored() else ""
        )

        if existing_certificate != provider_certificate:
            self._store_certificate(certificate=provider_certificate)
            return True
        return False

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Request new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if event.certificate != self._get_stored_certificate():
            logger.debug("Expiring certificate is not the one stored")
            return
        self._request_new_certificate()

    def _generate_private_key(self) -> None:
        """Generate and stores private key."""
        private_key = generate_private_key()
        self._store_private_key(private_key)

    def _request_new_certificate(self) -> None:
        """Generate and stores CSR, and uses it to request a new certificate."""
        private_key = self._get_stored_private_key()
        csr = generate_csr(
            private_key=private_key,
            subject=CERTIFICATE_COMMON_NAME,
            sans_dns=[CERTIFICATE_COMMON_NAME],
        )
        self._store_csr(csr)
        self._certificates.request_certificate_creation(certificate_signing_request=csr)

    def _delete_private_key(self) -> None:
        """Remove private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_csr(self) -> None:
        """Delete CSR from workload."""
        if not self._csr_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")
        logger.info("Removed CSR from workload")

    def _delete_certificate(self) -> None:
        """Delete certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Return whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _csr_is_stored(self) -> bool:
        """Return whether CSR is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")

    def _get_stored_certificate(self) -> str:
        """Return stored certificate."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())

    def _get_stored_csr(self) -> str:
        """Return stored CSR."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CSR_NAME}").read())

    def _get_stored_private_key(self) -> bytes:
        """Return stored private key."""
        return str(
            self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read()
        ).encode()

    def _certificate_is_stored(self) -> bool:
        """Return whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: str) -> None:
        """Store certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=certificate)
        logger.info("Pushed certificate pushed to workload")

    def _store_private_key(self, private_key: bytes) -> None:
        """Store private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=private_key.decode(),
        )
        logger.info("Pushed private key to workload")

    def _store_csr(self, csr: bytes) -> None:
        """Store CSR in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CSR_NAME}", source=csr.decode().strip())
        logger.info("Pushed CSR to workload")

    def _get_invalid_configs(self) -> list[str]:
        """Return list of invalid configurations.

        Returns:
            list: List of strings matching config keys.
        """
        invalid_configs = []
        if not self._get_sd_config():
            invalid_configs.append("sd")
        if not self._get_sst_config():
            invalid_configs.append("sst")
        return invalid_configs

    @staticmethod
    def _render_config_file(
        *,
        nssf_ip: str,
        sbi_port: int,
        nrf_url: str,
        sst: int,
        sd: str,
        scheme: str,
        webui_uri: str,
    ):
        """Render the NSSF config file.

        Args:
            nssf_ip (str): IP address of the NSSF.
            sbi_port (int): NSSF SBi port.
            nrf_url (str): URL of the NRF.
            sst (int): Slice Selection Type
            sd (str): Slice ID
            scheme (str): SBI interface scheme ("http" or "https")
            webui_uri (str) : URL of the Webui
        """
        jinja2_environment = Environment(loader=FileSystemLoader(CONFIG_TEMPLATE_DIR))
        template = jinja2_environment.get_template(CONFIG_TEMPLATE_NAME)
        content = template.render(
            sbi_port=sbi_port,
            nrf_url=nrf_url,
            nssf_ip=nssf_ip,
            sst=sst,
            sd=sd,
            scheme=scheme,
            webui_uri=webui_uri,
        )
        return content

    def _config_file_content_matches(self, content: str) -> bool:
        """Return whether the config file content matches the provided content.

        Returns:
            bool: Whether the config file content matches
        """
        try:
            existing_content = self._container.pull(path=f"{CONFIG_DIR}/{CONFIG_FILE_NAME}")
            return existing_content.read().strip() == content.strip()
        except PathError:
            return False

    def _push_config_file(
        self,
        content: str,
    ) -> None:
        """Push the NSSF config file to the container.

        Args:
            content (str): Content of the config file.
        """
        self._container.push(
            path=f"{CONFIG_DIR}/{CONFIG_FILE_NAME}",
            source=content,
            make_dirs=True,
        )
        logger.info("Pushed %s config file", CONFIG_FILE_NAME)

    def _configure_nssf_service(self, *, force_restart: bool = False) -> None:
        """Manage NSSF's pebble layer and service.

        Updates the pebble layer if the proposed config is different from the current one. If layer
        has been updated also restart the workload service.

        Args:
            force_restart (bool): Allows for forcibly restarting the service even if Pebble plan
                didn't change.
        """
        pebble_layer = self._pebble_layer
        plan = self._container.get_plan()
        if plan.services != pebble_layer.services or force_restart:
            self._container.add_layer(self._container_name, pebble_layer, combine=True)
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)

    def _relation_created(self, relation_name: str) -> bool:
        """Return True if the relation is created, False otherwise.

        Args:
            relation_name (str): Name of the relation.

        Returns:
            bool: True if the relation is created, False otherwise.
        """
        return bool(self.model.get_relation(relation_name))

    @property
    def _pebble_layer(self) -> Layer:
        """Return pebble layer for the NSSF container.

        Returns:
            Layer: Pebble Layer
        """
        return Layer(
            {
                "services": {
                    self._service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"/bin/nssf --nssfcfg {CONFIG_DIR}/{CONFIG_FILE_NAME}",  # noqa: E501
                        "environment": self._nssf_environment_variables,
                    },
                },
            }
        )

    @property
    def _nssf_environment_variables(self) -> dict:
        """Return environment variables for the nssf container.

        Returns:
            dict: Environment variables.
        """
        return {
            "GOTRACEBACK": "crash",
            "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
            "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
            "GRPC_TRACE": "all",
            "GRPC_VERBOSITY": "DEBUG",
            "POD_IP": _get_pod_ip(),
            "MANAGED_BY_CONFIG_POD": "true",
        }

    def _get_sd_config(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("sd"))

    def _get_sst_config(self) -> Optional[int]:
        return int(self.model.config.get("sst"))  # type: ignore[arg-type]

    @property
    def _nrf_data_is_available(self) -> bool:
        """Return whether the NRF data is available.

        Returns:
            bool: Whether the NRF data is available.
        """
        return bool(self._nrf_requires.nrf_url)


def _get_pod_ip() -> Optional[str]:
    """Return the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    ip_address = check_output(["unit-get", "private-address"])
    return str(IPv4Address(ip_address.decode().strip())) if ip_address else None


if __name__ == "__main__":  # pragma: no cover
    main(NSSFOperatorCharm)
