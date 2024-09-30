# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import tempfile

import scenario

from tests.unit.fixtures import NSSFUnitTestFixtures


class TestCharmCertificatesRelationBroken(NSSFUnitTestFixtures):
    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            certificates_relation = scenario.Relation(
                endpoint="certificates", interface="tls-certificates"
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = scenario.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = scenario.Container(
                name="nssf",
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            os.mkdir(f"{tempdir}/support")
            os.mkdir(f"{tempdir}/support/TLS")
            with open(f"{tempdir}/nssf.pem", "w") as f:
                f.write("certificate")

            with open(f"{tempdir}/nssf.key", "w") as f:
                f.write("private key")

            state_in = scenario.State(
                relations=[certificates_relation],
                containers=[container],
                leader=True,
            )

            self.ctx.run(self.ctx.on.relation_broken(certificates_relation), state_in)

            assert not os.path.exists(f"{tempdir}/nssf.pem")
            assert not os.path.exists(f"{tempdir}/nssf.key")
