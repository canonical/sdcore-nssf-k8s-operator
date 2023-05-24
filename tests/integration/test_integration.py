#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
NRF_CHARM_NAME = "sdcore-nrf"


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it."""
    charm = await ops_test.build_charm(".")
    resources = {
        "nssf-image": METADATA["resources"]["nssf-image"]["upstream-source"],
    }
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APP_NAME,
        trust=True,
    )
    await ops_test.model.deploy(
        NRF_CHARM_NAME,
        application_name=NRF_CHARM_NAME,
        channel="edge",
        trust=True,
    )


@pytest.mark.abort_on_fail
async def test_relate_and_wait_for_active_status(
    ops_test,
    build_and_deploy,
):
    await ops_test.model.add_relation(relation1=APP_NAME, relation2=NRF_CHARM_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )