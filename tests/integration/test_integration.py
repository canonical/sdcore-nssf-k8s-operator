#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import asyncio
import logging
from collections import Counter
from pathlib import Path

import pytest
import yaml
from juju.application import Application
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]

DB_APPLICATION_NAME = "mongodb-k8s"
DB_APPLICATION_CHANNEL = "6/beta"
NRF_APPLICATION_NAME = "sdcore-nrf-k8s"
NRF_APPLICATION_CHANNEL = "1.5/edge"
TLS_PROVIDER_NAME = "self-signed-certificates"
TLS_PROVIDER_CHANNEL = "latest/stable"
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent-k8s"
GRAFANA_AGENT_APPLICATION_CHANNEL = "latest/stable"


async def _deploy_mongodb(ops_test: OpsTest):
    assert ops_test.model
    await ops_test.model.deploy(
        DB_APPLICATION_NAME,
        application_name=DB_APPLICATION_NAME,
        channel=DB_APPLICATION_CHANNEL,
        trust=True,
    )


async def _deploy_grafana_agent(ops_test: OpsTest):
    assert ops_test.model
    await ops_test.model.deploy(
        GRAFANA_AGENT_APPLICATION_NAME,
        application_name=GRAFANA_AGENT_APPLICATION_NAME,
        channel=GRAFANA_AGENT_APPLICATION_CHANNEL,
    )


async def _deploy_sdcore_nrf_operator(ops_test: OpsTest):
    assert ops_test.model
    await _deploy_mongodb(ops_test)
    await ops_test.model.deploy(
        NRF_APPLICATION_NAME,
        application_name=NRF_APPLICATION_NAME,
        channel=NRF_APPLICATION_CHANNEL,
        trust=True,
    )
    await ops_test.model.integrate(relation1=DB_APPLICATION_NAME, relation2=NRF_APPLICATION_NAME)
    await ops_test.model.integrate(relation1=NRF_APPLICATION_NAME, relation2=TLS_PROVIDER_NAME)


async def _deploy_tls_provider(ops_test: OpsTest):
    assert ops_test.model
    await ops_test.model.deploy(
        TLS_PROVIDER_NAME,
        application_name=TLS_PROVIDER_NAME,
        channel=TLS_PROVIDER_CHANNEL,
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def deploy(ops_test: OpsTest, request):
    """Deploy necessary components."""
    assert ops_test.model
    deploy_nrf = asyncio.create_task(_deploy_sdcore_nrf_operator(ops_test))
    deploy_tls_provider = asyncio.create_task(_deploy_tls_provider(ops_test))
    deploy_grafana_agent = asyncio.create_task(_deploy_grafana_agent(ops_test))
    charm = Path(request.config.getoption("--charm_path")).resolve()
    await deploy_tls_provider
    await deploy_nrf
    await deploy_grafana_agent
    resources = {
        "nssf-image": METADATA["resources"]["nssf-image"]["upstream-source"],
    }
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APP_NAME,
        trust=True,
    )


@pytest.mark.abort_on_fail
async def test_relate_and_wait_for_active_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.integrate(relation1=APP_NAME, relation2=NRF_APPLICATION_NAME)
    await ops_test.model.integrate(relation1=APP_NAME, relation2=TLS_PROVIDER_NAME)
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:logging", relation2=GRAFANA_AGENT_APPLICATION_NAME
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_remove_nrf_and_wait_for_blocked_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.remove_application(NRF_APPLICATION_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=60)


@pytest.mark.abort_on_fail
async def test_restore_nrf_and_wait_for_active_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.deploy(
        NRF_APPLICATION_NAME,
        application_name=NRF_APPLICATION_NAME,
        channel="edge",
        trust=True,
    )
    await ops_test.model.integrate(
        relation1=f"{NRF_APPLICATION_NAME}:database", relation2=f"{DB_APPLICATION_NAME}"
    )
    await ops_test.model.integrate(relation1=NRF_APPLICATION_NAME, relation2=TLS_PROVIDER_NAME)
    await ops_test.model.integrate(relation1=APP_NAME, relation2=NRF_APPLICATION_NAME)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_remove_tls_and_wait_for_blocked_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.remove_application(TLS_PROVIDER_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=60)


@pytest.mark.abort_on_fail
async def test_restore_tls_and_wait_for_active_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.deploy(
        TLS_PROVIDER_NAME,
        application_name=TLS_PROVIDER_NAME,
        channel="beta",
        trust=True,
    )
    await ops_test.model.integrate(relation1=APP_NAME, relation2=TLS_PROVIDER_NAME)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_when_scale_app_beyond_1_then_only_one_unit_is_active(
    ops_test: OpsTest, deploy
):
    assert ops_test.model
    assert isinstance(app := ops_test.model.applications[APP_NAME], Application)
    await app.scale(3)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_at_least_units=3)
    unit_statuses = Counter(unit.workload_status for unit in app.units)
    assert unit_statuses.get("active") == 1
    assert unit_statuses.get("blocked") == 2


async def test_remove_app(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.remove_application(APP_NAME, block_until_done=True)
