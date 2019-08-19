
# Welcome

Hi! Thanks for taking a look at `vault-ctrl-tool`. This is a little tool that manages, authentication, 
applying secrets, and refreshing leases for services.

If you're curious on how to build this in your environment, see [BUILDING.md](docs/BUILDING.md). 

If you're integrating with Kubernetes, see [KUBERNETES.md](docs/KUBERNETES.md).

If you're integrating with EC2, see [EC2.md](docs/EC2.md).

To understand how the configuration file works, see [CONFIGURATION.md](docs/CONFIGURATION.md).

To play with a few examples, see [examples](docs/examples).

## Authentication

| Backend | Supported |
|---|---|
| Kubernetes Service Account Tokens | Yes |
| Passed in Vault tokens | Yes |
| EC2 Metadata | Yes |

##  Secrets

| Backend | Supported |
|---|---
|  KV | Yes |
| KV v2 | Yes |
|  SSH (key signing) | Yes |
| AWS | Yes |
| Database  | Desired |
