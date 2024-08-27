import tempfile

import pytest
import scenario
from interface_tester import InterfaceTester
from ops.pebble import Layer, ServiceStatus

from charm import NSSFOperatorCharm


@pytest.fixture
def interface_tester(interface_tester: InterfaceTester):
    with tempfile.TemporaryDirectory() as tempdir:
        config_mount = scenario.Mount(
            location="/etc/nssf/",
            src=tempdir,
        )
        certs_mount = scenario.Mount(
            location="/support/TLS/",
            src=tempdir,
        )
        container = scenario.Container(
            name="nssf",
            can_connect=True,
            layers={"nssf": Layer({"services": {"nssf": {}}})},
            service_status={
                "nssf": ServiceStatus.ACTIVE,
            },
            mounts={
                "config": config_mount,
                "certs": certs_mount,
            },
        )
        interface_tester.configure(
            charm_type=NSSFOperatorCharm,
            state_template=scenario.State(
                leader=True,
                containers=[container],
            ),
        )
        yield interface_tester
