# SD-Core NSSF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-nssf-k8s/badge.svg)](https://charmhub.io/sdcore-nssf-k8s)

Charmed Operator for the SD-Core Network Slice Selection Function (NSSF) for K8s.

## Usage
```bash
juju deploy mongodb-k8s --trust --channel=5/edge
juju deploy sdcore-nrf-k8s --channel=edge
juju deploy sdcore-nssf-k8s --channel=edge
juju deploy self-signed-certificates --channel=beta
juju integrate mongodb-k8s sdcore-nrf
juju integrate sdcore-nrf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-nrf-k8s sdcore-nssf-k8s
juju integrate sdcore-nssf-k8s:certificates self-signed-certificates:certificates
```

## Image

- **nssf**: `ghcr.io/canonical/sdcore-nssf:1.3`

