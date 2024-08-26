# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import datetime
import os
import tempfile

import scenario
from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
)
from ops.pebble import Layer

from tests.unit.fixtures import NSSFUnitTestFixtures


class TestCharmConfigure(NSSFUnitTestFixtures):
    def test_given_workload_ready_when_configure_then_config_file_is_rendered_and_pushed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = scenario.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = scenario.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = scenario.Mount(
                location="/free5gc/config/",
                src=temp_dir,
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=temp_dir,
            )
            container = scenario.Container(
                name="nssf",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "http://nrf:8081"
            self.mock_sdcore_config_webui_url.return_value = "sdcore-webui:9876"
            self.mock_check_output.return_value = b"1.1.1.1"
            self.mock_get_assigned_certificates.return_value = [
                ProviderCertificate(
                    relation_id=certificates_relation.relation_id,
                    application_name="nssf",
                    csr="whatever csr",
                    certificate="whatever cert",
                    ca="whatever ca",
                    chain=["whatever ca", "whatever cert"],
                    revoked=False,
                    expiry_time=datetime.datetime.now(),
                )
            ]
            with open(f"{temp_dir}/nssf.csr", "w") as f:
                f.write("whatever csr")

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/nssfcfg.conf", "r") as config_file:
                config_content = config_file.read()

            with open("tests/unit/expected_config/config.conf", "r") as expected_config_file:
                expected_content = expected_config_file.read()

            assert config_content.strip() == expected_content.strip()

    def test_given_content_of_config_file_not_changed_when_pebble_ready_then_config_file_is_not_pushed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = scenario.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = scenario.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = scenario.Mount(
                location="/free5gc/config/",
                src=temp_dir,
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=temp_dir,
            )
            container = scenario.Container(
                name="nssf",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "http://nrf:8081"
            self.mock_sdcore_config_webui_url.return_value = "sdcore-webui:9876"
            self.mock_check_output.return_value = b"1.2.3.4"
            self.mock_get_assigned_certificates.return_value = [
                ProviderCertificate(
                    relation_id=certificates_relation.relation_id,
                    application_name="nssf",
                    csr="whatever csr",
                    certificate="whatever cert",
                    ca="whatever ca",
                    chain=["whatever ca", "whatever cert"],
                    revoked=False,
                    expiry_time=datetime.datetime.now(),
                )
            ]
            with open(f"{temp_dir}/nrf.csr", "w") as f:
                f.write("whatever csr")
            with open("tests/unit/expected_config/config.conf", "r") as expected_config_file:
                expected_content = expected_config_file.read()
            with open(f"{temp_dir}/nssfcfg.conf", "w") as config_file:
                config_file.write(expected_content.strip())
            config_modification_time = os.stat(temp_dir + "/nssfcfg.conf").st_mtime

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/nssfcfg.conf", "r") as config_file:
                config_content = config_file.read()

            with open("tests/unit/expected_config/config.conf", "r") as expected_config_file:
                expected_content = expected_config_file.read()

            assert config_content.strip() == expected_content.strip()
            assert os.stat(temp_dir + "/nssfcfg.conf").st_mtime == config_modification_time

    def test_given_given_workload_ready_when_configure_then_config_file_is_rendered_and_pushed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = scenario.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = scenario.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = scenario.Mount(
                location="/free5gc/config/",
                src=temp_dir,
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=temp_dir,
            )
            container = scenario.Container(
                name="nssf",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "http://nrf:8081"
            self.mock_sdcore_config_webui_url.return_value = "sdcore-webui:9876"
            self.mock_check_output.return_value = b"1.1.1.1"
            self.mock_get_assigned_certificates.return_value = [
                ProviderCertificate(
                    relation_id=certificates_relation.relation_id,
                    application_name="nssf",
                    csr="whatever csr",
                    certificate="whatever cert",
                    ca="whatever ca",
                    chain=["whatever ca", "whatever cert"],
                    revoked=False,
                    expiry_time=datetime.datetime.now(),
                )
            ]
            with open(f"{temp_dir}/nssf.csr", "w") as f:
                f.write("whatever csr")

            state_out = self.ctx.run(container.pebble_ready_event, state_in)

            assert state_out.containers[0].layers == {
                "nssf": Layer(
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
            }
