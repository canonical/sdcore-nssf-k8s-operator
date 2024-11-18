# Aether SD-Core NSSF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-nssf-k8s/badge.svg)](https://charmhub.io/sdcore-nssf-k8s)

Charmed Operator for the Aether SD-Core Network Slice Selection Function (NSSF) for K8s.

## Usage
```bash
juju deploy mongodb-k8s --trust --channel=6/beta
juju deploy sdcore-nrf-k8s --channel=1.5/edge
juju deploy sdcore-nssf-k8s --channel=1.5/edge
juju deploy sdcore-nms-k8s --channel=1.5/edge
juju integrate sdcore-nms-k8s:common_database mongodb-k8s:database
juju integrate sdcore-nms-k8s:auth_database mongodb-k8s:database
juju deploy self-signed-certificates
juju integrate mongodb-k8s sdcore-nrf
juju integrate sdcore-nrf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-nrf-k8s sdcore-nssf-k8s
juju integrate sdcore-nrf-k8s:sdcore_config sdcore-nms-k8s:sdcore_config
juju integrate sdcore-nssf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-nssf-k8s:sdcore_config sdcore-nms-k8s:sdcore_config
```

## Image

- **nssf**: `ghcr.io/canonical/sdcore-nssf:1.5.1`
