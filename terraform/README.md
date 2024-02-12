# SD-Core NSSF K8s Terraform Module

This folder contains a base [Terraform][Terraform] module for the sdcore-nssf-k8s charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto any Kubernetes environment managed by [Juju][Juju].

The base module is not intended to be deployed in separation (it is possible though), but should
rather serve as a building block for higher level modules.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Except for exposing the deployment
  options (Juju model name, channel or application name) also allows overwriting charm's default
  configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily
  by defining potential integration endpoints (charm integrations), but also by exposing
  the application name.
- **terraform.tf** - Defines the Terraform provider.

## Using sdcore-nssf-k8s base module in higher level modules

If you want to use `sdcore-nssf-k8s` base module as part of your Terraform module, import it
like shown below:

```text
module "nssf" {
  source = "git::https://github.com/canonical/sdcore-nssf-k8s-operator//terraform"
  
  model_name = "juju_model_name"
  config = Optional config map
}
```

Create integrations, for instance:

```text
resource "juju_integration" "nssf-nrf" {
  model = var.model_name
  application {
    name     = module.nssf.app_name
    endpoint = module.nssf.fiveg_nrf_endpoint
  }
  application {
    name     = module.nrf.app_name
    endpoint = module.nrf.fiveg_nrf_endpoint
  }
}
```

The complete list of available integrations can be found [here][nssf-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[nssf-integrations]: https://charmhub.io/sdcore-nssf-k8s/integrations
