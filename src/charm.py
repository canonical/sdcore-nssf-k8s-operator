#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SDCORE NSSF service."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output

from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]
    KubernetesServicePatch,
)
from charms.sdcore_nrf.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer

logger = logging.getLogger(__name__)

SBI_PORT = 29531
CONFIG_DIR = "/free5gc/config"
CONFIG_FILE_NAME = "nssfcfg.conf"
CONFIG_TEMPLATE_DIR = "src/templates/"
CONFIG_TEMPLATE_NAME = "nssfcfg.conf.j2"


class NSSFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the 5G NSSF operator."""

    def __init__(self, *args):
        super().__init__(*args)
        self._nssf_container_name = self._nssf_service_name = "nssf"
        self._nssf_container = self.unit.get_container(self._nssf_container_name)
        self._nrf_requires = NRFRequires(charm=self, relation_name="fiveg_nrf")
        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[
                ServicePort(name="sbi", port=SBI_PORT),
            ],
        )

        self.framework.observe(self.on.nssf_pebble_ready, self._on_nssf_pebble_ready)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._on_nssf_pebble_ready)

    def _on_nssf_pebble_ready(
        self,
        event: EventBase,
    ) -> None:
        """Handle pebble ready event for NSSF container.

        Args:
            event (EventBase): Juju event
        """
        if not self._nssf_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to start")
            event.defer()
            return
        if not self._relation_created("fiveg_nrf"):
            self.unit.status = BlockedStatus("Waiting for fiveg_nrf relation")
            return
        if not self._nrf_data_is_available:
            self.unit.status = WaitingStatus("Waiting for NRF data to be available")
            event.defer()
            return
        if not self._nssf_container.exists(path=CONFIG_DIR):
            self.unit.status = WaitingStatus("Waiting for storage to be attached")
            event.defer()
            return
        content = self._render_config_file(
            sbi_port=SBI_PORT,
            nrf_url=self._nrf_requires.nrf_url,
            nssf_url=self._nssf_hostname,
        )
        self._push_config_file(
            content=content,
        )
        self._nssf_container.add_layer("nssf", self._nssf_pebble_layer, combine=True)
        self.unit.status = ActiveStatus()

    def _render_config_file(
        self,
        nssf_url: str,
        sbi_port: int,
        nrf_url: str,
    ):
        """Renders the NSSF config file.

        Args:
            nssf_url (str): URL of the NSSF.
            sbi_port (int): NSSF SBi port.
            nrf_url (str): URL of the NRF.
        """
        jinja2_environment = Environment(loader=FileSystemLoader(CONFIG_TEMPLATE_DIR))
        template = jinja2_environment.get_template(CONFIG_TEMPLATE_NAME)
        content = template.render(
            sbi_port=sbi_port,
            nrf_url=nrf_url,
            nssf_url=nssf_url,
        )
        return content

    def _push_config_file(
        self,
        content: str,
    ) -> None:
        """Pushes the NSSF config file to the container.

        Args:
            content (str): Content of the config file.
        """
        self._nssf_container.push(
            path=f"{CONFIG_DIR}/{CONFIG_FILE_NAME}",
            source=content,
            make_dirs=True,
        )
        logger.info("Pushed %s config file", CONFIG_FILE_NAME)

    def _relation_created(self, relation_name: str) -> bool:
        """Returns True if the relation is created, False otherwise.

        Args:
            relation_name (str): Name of the relation.

        Returns:
            bool: True if the relation is created, False otherwise.
        """
        return bool(self.model.get_relation(relation_name))

    @property
    def _nssf_pebble_layer(self) -> Layer:
        """Returns pebble layer for the nssf container.

        Returns:
            Layer: Pebble Layer
        """
        return Layer(
            {
                "services": {
                    self._nssf_service_name: {
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
        """Returns environment variables for the nssf container.

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

    @property
    def _pod_ip(
        self,
    ) -> str:
        """Returns the pod IP using juju client.

        Returns:
            str: The pod IP.
        """
        return str(IPv4Address(check_output(["unit-get", "private-address"]).decode().strip()))

    @property
    def _nrf_data_is_available(self) -> bool:
        """Returns whether the NRF data is available.

        Returns:
            bool: Whether the NRF data is available.
        """
        return bool(self._nrf_requires.nrf_url)

    @property
    def _nssf_hostname(self) -> str:
        """Builds and returns the NSSF hostname in the cluster.

        Returns:
            str: The NSSF hostname.
        """
        return f"{self.model.app.name}.{self.model.name}.svc.cluster.local"


if __name__ == "__main__":  # pragma: no cover
    main(NSSFOperatorCharm)
