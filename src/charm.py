#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core NSSF service."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]
    KubernetesServicePatch,
)
from charms.sdcore_nrf.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
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


class NSSFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the SD-Core NSSF operator."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self._container_name = self._service_name = "nssf"
        self._container = self.unit.get_container(self._container_name)
        self._nrf_requires = NRFRequires(charm=self, relation_name="fiveg_nrf")
        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[
                ServicePort(name="sbi", port=SBI_PORT),
            ],
        )

        self.framework.observe(self.on.config_changed, self._configure_nssf)
        self.framework.observe(self.on.nssf_pebble_ready, self._configure_nssf)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_nssf)

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
        if not self._relation_created("fiveg_nrf"):
            self.unit.status = BlockedStatus("Waiting for fiveg_nrf relation")
            return
        if not self._nrf_data_is_available:
            self.unit.status = WaitingStatus("Waiting for NRF data to be available")
            event.defer()
            return
        if not self._container.exists(path=CONFIG_DIR):
            self.unit.status = WaitingStatus("Waiting for storage to be attached")
            event.defer()
            return
        config_file_changed = self._apply_nssf_config()
        self._configure_nssf_service(force_restart=config_file_changed)
        self.unit.status = ActiveStatus()

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
            nssf_ip=self._pod_ip,
            sst=self._get_sst_config(),
            sd=self._get_sd_config(),
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
    ):
        """Render the NSSF config file.

        Args:
            nssf_ip (str): IP address of the NSSF.
            sbi_port (int): NSSF SBi port.
            nrf_url (str): URL of the NRF.
            sst (int): Slice Selection Type
            sd (str): Slice ID
        """
        jinja2_environment = Environment(loader=FileSystemLoader(CONFIG_TEMPLATE_DIR))
        template = jinja2_environment.get_template(CONFIG_TEMPLATE_NAME)
        content = template.render(
            sbi_port=sbi_port,
            nrf_url=nrf_url,
            nssf_ip=nssf_ip,
            sst=sst,
            sd=sd,
        )
        return content

    def _config_file_content_matches(self, content: str) -> bool:
        """Return whether the config file content matches the provided content.

        Returns:
            bool: Whether the config file content matches
        """
        f"{CONFIG_DIR}/{CONFIG_FILE_NAME}"
        try:
            existing_content = self._container.pull(path=f"{CONFIG_DIR}/{CONFIG_FILE_NAME}")
            return existing_content.read() == content
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
                        "command": f"/free5gc/nssf/nssf --nssfcfg {CONFIG_DIR}/{CONFIG_FILE_NAME}",  # noqa: E501
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
            "POD_IP": self._pod_ip,
            "MANAGED_BY_CONFIG_POD": "true",
        }

    def _get_sd_config(self) -> Optional[str]:
        return self.model.config.get("sd")

    def _get_sst_config(self) -> Optional[int]:
        return int(self.model.config.get("sst"))

    @property
    def _pod_ip(
        self,
    ) -> str:
        """Return the pod IP using juju client.

        Returns:
            str: The pod IP.
        """
        return str(IPv4Address(check_output(["unit-get", "private-address"]).decode().strip()))

    @property
    def _nrf_data_is_available(self) -> bool:
        """Return whether the NRF data is available.

        Returns:
            bool: Whether the NRF data is available.
        """
        return bool(self._nrf_requires.nrf_url)


if __name__ == "__main__":  # pragma: no cover
    main(NSSFOperatorCharm)
