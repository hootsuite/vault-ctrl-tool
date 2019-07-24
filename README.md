
# Welcome

Hi! Thanks for taking a look at `vault-ctrl-tool`. This is a little tool that manages, authentication, 
applying secrets, and refreshing leases for services.

If you're curious on how to build this in your environment, see [BUILDING.md](docs/BUILDING.md). 

If you're integrating with Kubernetes, see [KUBERNETES.md](docs/KUBERNETES.md).

To understand how the configuration file works, see [CONFIGURATION.md](docs/CONFIGURATION.md).

To play with a few examples, see [examples](docs/examples).

## Authentication

| Backend | Supported |
|---|---|
| Kubernetes Service Account Tokens | Yes |
| Passed in Vault tokens | Yes |
| EC2 Metadata | Desired |

##  Secrets

| Backend | Supported |
|---|---
|  KV | Yes |
|  SSH (key signing) | Yes |
| AWS | Yes |
| Database  | Desired |
