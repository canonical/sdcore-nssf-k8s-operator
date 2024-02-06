resource "juju_application" "nssf" {
  name  = "nssf"
  model = var.model_name

  charm {
    name    = "sdcore-nssf-k8s"
    channel = var.channel
  }
  config = var.nssf-config
  units  = 1
  trust  = true
}

resource "juju_integration" "nssf-certs" {
  model = var.model_name

  application {
    name     = juju_application.nssf.name
    endpoint = "certificates"
  }

  application {
    name     = var.certs_application_name
    endpoint = "certificates"
  }
}

resource "juju_integration" "nssf-nrf" {
  model = var.model_name

  application {
    name     = juju_application.nssf.name
    endpoint = "fiveg_nrf"
  }

  application {
    name     = var.nrf_application_name
    endpoint = "fiveg-nrf"
  }
}

