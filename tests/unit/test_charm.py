# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from scenario import Container, Context, Model, Mount, Relation, State  # type: ignore[import]

from charm import NSSFOperatorCharm


@patch("charm.KubernetesServicePatch", new=Mock)
class TestCharm(unittest.TestCase):
    def setUp(self):
        self.ctx = Context(NSSFOperatorCharm)

    def test_given_fiveg_nrf_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        container = Container(name="nssf", can_connect=True)
        state_in = State(
            containers=[
                container,
            ]
        )

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.status.unit,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    def test_given_nrf_data_not_available_when_pebble_ready_then_status_is_waiting(
        self,
    ):
        container = Container(name="nssf", can_connect=True)
        nrf_relation = Relation("fiveg_nrf")
        state_in = State(
            containers=[container],
            relations=[nrf_relation],
        )

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.status.unit,
            WaitingStatus("Waiting for NRF data to be available"),
        )
        self.assertEqual(
            state_out.deferred[0].name,
            "nssf_pebble_ready",
        )

    def test_given_relations_created_and_nrf_data_available_and_storage_not_attached_when_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
    ):
        container = Container(name="nssf", can_connect=True)
        nrf_relation = Relation(
            endpoint="fiveg_nrf",
            remote_app_name="remote",
            remote_app_data={"url": "http://nrf:8081"},
        )
        state_in = State(
            containers=[container],
            relations=[nrf_relation],
        )

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.status.unit,
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
        container = Container(
            name="nssf",
            can_connect=True,
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        nrf_relation = Relation(
            endpoint="fiveg_nrf",
            remote_app_name="remote",
            remote_app_data={"url": "http://nrf:8081"},
        )
        state_in = State(
            containers=[container],
            relations=[nrf_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = "1.1.1.1".encode()

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
        container = Container(
            name="nssf",
            can_connect=True,
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        nrf_relation = Relation(
            endpoint="fiveg_nrf",
            remote_app_name="remote",
            remote_app_data={"url": "http://nrf:8081"},
        )
        state_in = State(
            containers=[container],
            relations=[nrf_relation],
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
        container = Container(
            name="nssf",
            can_connect=True,
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        nrf_relation = Relation(
            endpoint="fiveg_nrf",
            remote_app_name="remote",
            remote_app_data={"url": "http://nrf:8081"},
        )
        state_in = State(
            containers=[container],
            relations=[nrf_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        expected_plan = {
            "services": {
                "nssf": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "/free5gc/nssf/nssf --nssfcfg /free5gc/config/nssfcfg.conf",
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
        container = Container(
            name="nssf",
            can_connect=True,
            mounts={"config_dir": Mount("/free5gc/config", config_dir.name)},
        )
        nrf_relation = Relation(
            endpoint="fiveg_nrf",
            remote_app_name="remote",
            remote_app_data={"url": "http://nrf:8081"},
        )
        state_in = State(
            containers=[container],
            relations=[nrf_relation],
            model=Model(name="whatever"),
        )
        patch_check_output.return_value = "1.1.1.1".encode()

        state_out = self.ctx.run(container.pebble_ready_event, state_in)

        self.assertEqual(
            state_out.status.unit,
            ActiveStatus(),
        )

    def test_given_cannot_connect_to_container_when_nrf_available_then_status_is_waiting(
        self,
    ):
        container = Container(name="nssf", can_connect=False)
        nrf_relation = Relation(
            endpoint="fiveg_nrf",
            remote_app_name="remote",
            remote_app_data={"url": "http://nrf:8081"},
        )
        state_in = State(
            containers=[container],
            relations=[nrf_relation],
        )

        state_out = self.ctx.run(nrf_relation.changed_event, state_in)

        self.assertEqual(
            state_out.status.unit,
            WaitingStatus("Waiting for container to start"),
        )
        self.assertEqual(
            state_out.deferred[0].name,
            "nrf_available",
        )
