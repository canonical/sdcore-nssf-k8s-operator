<div align="center">
  <img src="./icon.svg" alt="ONF Icon" width="200" height="200">
</div>
<br/>
<div align="center">
  <a href="https://charmhub.io/sdcore-udr"><img src="https://charmhub.io/sdcore-nssf/badge.svg" alt="CharmHub Badge"></a>
  <a href="https://github.com/canonical/sdcore-nssf-operator/actions/workflows/publish-charm.yaml">
    <img src="https://github.com/canonical/sdcore-nssf-operator/actions/workflows/publish-charm.yaml/badge.svg?branch=main" alt=".github/workflows/publish-charm.yaml">
  </a>
  <br/>
  <br/>
  <h1>SD-Core NSSF Operator</h1>
</div>

Charmed Operator for the SD-Core Network Slice Selection Function (NSSF).

## Usage
```bash
juju deploy mongodb-k8s --trust --channel=5/edge
juju deploy sdcore-nrf --trust --channel=edge
juju deploy sdcore-nssf --trust --channel=edge
juju integrate mongodb-k8s sdcore-nrf
juju integrate sdcore-nrf sdcore-nssf
```

## Optional

```bash
juju deploy self-signed-certificates --channel=edge
juju integrate sdcore-nssf:certificates self-signed-certificates:certificates
```

## Image

- **nssf**: `ghcr.io/canonical/sdcore-nssf:1.3`
