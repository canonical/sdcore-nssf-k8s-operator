#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import asyncio
from collections import Counter
import logging
from pathlib import Path
from juju.application import Application

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]

DB_APPLICATION_NAME = "mongodb-k8s"
NRF_APPLICATION_NAME = "sdcore-nrf"
TLS_PROVIDER_NAME = "self-signed-certificates"


async def _deploy_mongodb(ops_test: OpsTest):
    await ops_test.model.deploy(  # type: ignore[union-attr]
        DB_APPLICATION_NAME,
        application_name=DB_APPLICATION_NAME,
        channel="5/edge",
        trust=True,
    )


async def _deploy_sdcore_nrf_operator(ops_test: OpsTest):
    await _deploy_mongodb(ops_test)
    await ops_test.model.deploy(  # type: ignore[union-attr]
        NRF_APPLICATION_NAME,
        application_name=NRF_APPLICATION_NAME,
        channel="edge",
        trust=True,
    )
    await ops_test.model.add_relation(  # type: ignore[union-attr]
        relation1=DB_APPLICATION_NAME, relation2=NRF_APPLICATION_NAME
    )
    await ops_test.model.add_relation(  # type: ignore[union-attr]
        relation1=NRF_APPLICATION_NAME, relation2=TLS_PROVIDER_NAME
    )


async def _deploy_tls_provider(ops_test: OpsTest):
    await ops_test.model.deploy(  # type: ignore[union-attr]
        TLS_PROVIDER_NAME,
        application_name=TLS_PROVIDER_NAME,
        channel="beta",
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    deploy_nrf = asyncio.create_task(_deploy_sdcore_nrf_operator(ops_test))
    deploy_tls_provider = asyncio.create_task(_deploy_tls_provider(ops_test))
    charm = await ops_test.build_charm(".")
    await deploy_tls_provider
    await deploy_nrf
    resources = {
        "nssf-image": METADATA["resources"]["nssf-image"]["upstream-source"],
    }
    await ops_test.model.deploy(  # type: ignore[union-attr]
        charm,
        resources=resources,
        application_name=APP_NAME,
        trust=True,
    )


@pytest.mark.abort_on_fail
async def test_relate_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    await ops_test.model.add_relation(relation1=APP_NAME, relation2=NRF_APPLICATION_NAME)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.add_relation(relation1=APP_NAME, relation2=TLS_PROVIDER_NAME)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_remove_nrf_and_wait_for_blocked_status(ops_test: OpsTest, build_and_deploy):
    await ops_test.model.remove_application(NRF_APPLICATION_NAME, block_until_done=True)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=60)  # type: ignore[union-attr]  # noqa: E501


@pytest.mark.abort_on_fail
async def test_restore_nrf_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    await ops_test.model.deploy(  # type: ignore[union-attr]
        NRF_APPLICATION_NAME,
        application_name=NRF_APPLICATION_NAME,
        channel="edge",
        trust=True,
    )
    await ops_test.model.add_relation(  # type: ignore[union-attr]
        relation1=f"{NRF_APPLICATION_NAME}:database", relation2=f"{DB_APPLICATION_NAME}"
    )
    await ops_test.model.add_relation(relation1=NRF_APPLICATION_NAME, relation2=TLS_PROVIDER_NAME)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.add_relation(relation1=APP_NAME, relation2=NRF_APPLICATION_NAME)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)  # type: ignore[union-attr]  # noqa: E501


@pytest.mark.abort_on_fail
async def test_remove_tls_and_wait_for_blocked_status(ops_test, build_and_deploy):
    await ops_test.model.remove_application(TLS_PROVIDER_NAME, block_until_done=True)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=60)  # type: ignore[union-attr]  # noqa: E501


@pytest.mark.abort_on_fail
async def test_restore_tls_and_wait_for_active_status(ops_test, build_and_deploy):
    await ops_test.model.deploy(  # type: ignore[union-attr]
        TLS_PROVIDER_NAME,
        application_name=TLS_PROVIDER_NAME,
        channel="beta",
        trust=True,
    )
    await ops_test.model.add_relation(  # type: ignore[union-attr]
        relation1=APP_NAME, relation2=TLS_PROVIDER_NAME
    )
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)  # type: ignore[union-attr]  # noqa: E501


@pytest.mark.abort_on_fail
async def test_when_scale_app_beyond_1_then_only_one_unit_is_active(
    ops_test: OpsTest, build_and_deploy
):
    assert ops_test.model
    assert isinstance(app := ops_test.model.applications[APP_NAME], Application)
    await app.scale(3)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_at_least_units=3)
    unit_statuses = Counter(unit.workload_status for unit in app.units)
    assert unit_statuses.get("active") == 1
    assert unit_statuses.get("blocked") == 2


async def test_remove_app(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.remove_application(APP_NAME, block_until_done=True)
