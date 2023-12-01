#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core NSSF service."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.sdcore_nrf.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from jinja2 import Environment, FileSystemLoader
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
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


class NSSFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the SD-Core NSSF operator."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to preform if we're removing the
            # charm.
            self.unit.status = BlockedStatus("Scaling is not implemented for this charm")
            return
        self._container_name = self._service_name = "nssf"
        self._container = self.unit.get_container(self._container_name)
        self._nrf_requires = NRFRequires(charm=self, relation_name="fiveg_nrf")
        self.unit.set_ports(SBI_PORT)
        self._certificates = TLSCertificatesRequiresV2(self, "certificates")

        self.framework.observe(self.on.config_changed, self._configure_nssf)
        self.framework.observe(self.on.nssf_pebble_ready, self._configure_nssf)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_nssf)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_nssf)
        self.framework.observe(self._nrf_requires.on.nrf_broken, self._on_nrf_broken)
        self.framework.observe(
            self.on.certificates_relation_created, self._on_certificates_relation_created
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(
            self._certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )

    def _configure_nssf(
        self,
        event: EventBase,
    ) -> None:
        """Configure NSSF configuration file and pebble service.

        Args:
            event (EventBase): Juju event
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to start")
            event.defer()
            return
        if invalid_configs := self._get_invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configurations are not valid: {invalid_configs}"
            )
            return
        for relation in ["fiveg_nrf", "certificates"]:
            if not self._relation_created(relation):
                self.unit.status = BlockedStatus(f"Waiting for {relation} relation")
                return
        if not self._nrf_data_is_available:
            self.unit.status = WaitingStatus("Waiting for NRF data to be available")
            event.defer()
            return
        if not self._container.exists(path=CONFIG_DIR):
            self.unit.status = WaitingStatus("Waiting for storage to be attached")
            event.defer()
            return
        if not _get_pod_ip():
            self.unit.status = WaitingStatus("Waiting for pod IP address to be available")
            event.defer()
            return
        if not self._certificate_is_stored():
            self.unit.status = WaitingStatus("Waiting for certificates to be stored")
            event.defer()
            return
        config_file_changed = self._apply_nssf_config()
        self._configure_nssf_service(force_restart=config_file_changed)
        self.unit.status = ActiveStatus()

    def _on_nrf_broken(self, event: EventBase) -> None:
        """Event handler for NRF relation broken.

        Args:
            event (NRFBrokenEvent): Juju event
        """
        self.unit.status = BlockedStatus("Waiting for fiveg_nrf relation")

    def _on_certificates_relation_created(self, event: EventBase) -> None:
        """Generates Private key."""
        if not self._container.can_connect():
            event.defer()
            return
        self._generate_private_key()

    def _on_certificates_relation_broken(self, event: EventBase) -> None:
        """Deletes TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()
        self.unit.status = BlockedStatus("Waiting for certificates relation")

    def _on_certificates_relation_joined(self, event: EventBase) -> None:
        """Generates CSR and requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._private_key_is_stored():
            event.defer()
            return
        if self._certificate_is_stored():
            return

        self._request_new_certificate()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Pushes certificate to workload and configures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._csr_is_stored():
            logger.warning("Certificate is available but no CSR is stored")
            return
        if event.certificate_signing_request != self._get_stored_csr():
            logger.debug("Stored CSR doesn't match one in certificate available event")
            return
        self._store_certificate(event.certificate)
        self._configure_nssf(event)

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if event.certificate != self._get_stored_certificate():
            logger.debug("Expiring certificate is not the one stored")
            return
        self._request_new_certificate()

    def _generate_private_key(self) -> None:
        """Generates and stores private key."""
        private_key = generate_private_key()
        self._store_private_key(private_key)

    def _request_new_certificate(self) -> None:
        """Generates and stores CSR, and uses it to request a new certificate."""
        private_key = self._get_stored_private_key()
        csr = generate_csr(
            private_key=private_key,
            subject=CERTIFICATE_COMMON_NAME,
            sans_dns=[CERTIFICATE_COMMON_NAME],
        )
        self._store_csr(csr)
        self._certificates.request_certificate_creation(certificate_signing_request=csr)

    def _delete_private_key(self) -> None:
        """Removes private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_csr(self) -> None:
        """Deletes CSR from workload."""
        if not self._csr_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")
        logger.info("Removed CSR from workload")

    def _delete_certificate(self) -> None:
        """Deletes certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _csr_is_stored(self) -> bool:
        """Returns whether CSR is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")

    def _get_stored_certificate(self) -> str:
        """Returns stored certificate."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())

    def _get_stored_csr(self) -> str:
        """Returns stored CSR."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CSR_NAME}").read())

    def _get_stored_private_key(self) -> bytes:
        """Returns stored private key."""
        return str(
            self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read()
        ).encode()

    def _certificate_is_stored(self) -> bool:
        """Returns whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: str) -> None:
        """Stores certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=certificate)
        logger.info("Pushed certificate pushed to workload")

    def _store_private_key(self, private_key: bytes) -> None:
        """Stores private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=private_key.decode(),
        )
        logger.info("Pushed private key to workload")

    def _store_csr(self, csr: bytes) -> None:
        """Stores CSR in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CSR_NAME}", source=csr.decode().strip())
        logger.info("Pushed CSR to workload")

    def _get_invalid_configs(self) -> list[str]:
        """Returns list of invalid configurations.

        Returns:
            list: List of strings matching config keys.
        """
        invalid_configs = []
        if not self._get_sd_config():
            invalid_configs.append("sd")
        if not self._get_sst_config():
            invalid_configs.append("sst")
        return invalid_configs

    def _apply_nssf_config(self) -> bool:
        """Generate and push NSSF configuration file.

        Returns:
            bool: True if the configuration file was changed.
        """
        content = self._render_config_file(
            sbi_port=SBI_PORT,
            nrf_url=self._nrf_requires.nrf_url,
            nssf_ip=_get_pod_ip(),  # type: ignore[arg-type]
            sst=self._get_sst_config(),  # type: ignore[arg-type]
            sd=self._get_sd_config(),  # type: ignore[arg-type]
            scheme="https",
        )
        if not self._config_file_content_matches(content):
            self._push_config_file(
                content=content,
            )
            return True
        return False

    def _render_config_file(
        self,
        *,
        nssf_ip: str,
        sbi_port: int,
        nrf_url: str,
        sst: int,
        sd: str,
        scheme: str,
    ):
        """Render the NSSF config file.

        Args:
            nssf_ip (str): IP address of the NSSF.
            sbi_port (int): NSSF SBi port.
            nrf_url (str): URL of the NRF.
            sst (int): Slice Selection Type
            sd (str): Slice ID
            scheme (str): SBI interface scheme ("http" or "https")
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
        """Return pebble layer for the nssf container.

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
        return self.model.config.get("sd")

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
    """Returns the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    ip_address = check_output(["unit-get", "private-address"])
    return str(IPv4Address(ip_address.decode().strip())) if ip_address else None


if __name__ == "__main__":  # pragma: no cover
    main(NSSFOperatorCharm)
