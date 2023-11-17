# SD-Core NSSF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-nssf/badge.svg)](https://charmhub.io/sdcore-nssf)

Charmed Operator for the SD-Core Network Slice Selection Function (NSSF).

## Usage
```bash
juju deploy mongodb-k8s --trust --channel=5/edge
juju deploy sdcore-nrf --trust --channel=edge
juju deploy sdcore-nssf --trust --channel=edge
juju deploy self-signed-certificates --channel=beta
juju integrate mongodb-k8s sdcore-nrf
juju integrate sdcore-nrf:certificates self-signed-certificates:certificates
juju integrate sdcore-nrf sdcore-nssf
juju integrate sdcore-nssf:certificates self-signed-certificates:certificates
```

## Image

- **nssf**: `ghcr.io/canonical/sdcore-nssf:1.3`
