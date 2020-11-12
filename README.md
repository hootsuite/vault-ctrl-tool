[![Go Report Card](https://goreportcard.com/badge/github.com/hootsuite/vault-ctrl-tool)](https://goreportcard.com/report/github.com/hootsuite/vault-ctrl-tool)

# Welcome

Hi! Thanks for taking a look at `vault-ctrl-tool`. This is a little tool that manages, authentication, 
applying secrets, and refreshing leases for services. It knows how to authenticate using Kubernetes (ServiceAccounts),
EC2 (registered AMIs and IAM roles), as well as existing Vault tokens for other integration purposes.

## Version

This is version 2 of the Vault Control Tool -- the previous version is on a `v1` branch.
 
It is a refactoring, replacing the logging library, and
simplifying the main code logic. It also now supports secrets whose lifetime is scoped to the token being used,
and has a defined failure mode. Lastly, it does away with the "file scrubber". 

Its configuration file is backwards compatible, as are all the command line arguments.

### Upgrading

Confusing, this version of Vault Control Tool supports `version: 3` in your vault-config files. To upgrade your
configuration file, you will need to add a correct `lifetime` to your `secrets` and `templates`. If the secrets
you're fetching from Vault are token-scoped (ie, credentials created dynamically, such as from a database backend),
then set `lifetime: token`. Otherwise if your secrets are "static", then specify `lifetime: static`. Templates follow
a similar pattern. If your template is using token-scoped secrets, specify `lifetime: token`, otherwise `lifetime: static`.

## Failure Mode

Vault Control Tool will now re-authenticate if the token it is using ceases to work (hits a tuned backend limit,
cannot reach the server to renew it for too long, etc). The tool now understands that some secrets will be invalid with the
new token and will fetch new values and rewrite files as needed - these values are called said to have a "token-scoped
lifetime". Note that files with "static" lifetimes are never rewritten.

Failure is most likely caused by a Vault outage. For consumers, Vault outages have two forms: pre-revocation and
post-revocation. Outages in pre-revocation mean token-lifetime secrets managed by Vault (database credentials, etc)
will remain valid during the outage. Services can continue to happily use these until Vault restarts. This is
the case if Vault is hard-down.

Outages in post-revocation mean secrets have been removed by Vault, but Vault Control Tool is unable to perform operations
to obtain fresh secrets (database management is unavailable, networking issues, configuration problems, etc). In these
situations the service is unable to function. 

Lastly, in both situations, when a service has credentials that are _externally_ managed (SSH certificates, AWS STS
sessions), they naturally become invalid which will also cause a service to be unable to function.

Kubernetes services unable to dynamically re-read secrets are encouraged to run with a `restartPolicy: Always`, and delete 
token-scoped files after they are consumed. Services should also fail-fast if they're unable to continue to use the credentials (ie,
authentication calls to remote services return errors). Kubernetes will restart the service. This will put the service
into a crashloopbackoff until the Vault Control Tool is able to fetch fresh secrets.


## Other Documents

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
| EC2 IAM | Yes |

##  Secrets

| Backend | Supported |
|---|---
|  KV | Yes |
| KV v2 | Yes |
| SSH (certificates) | Yes |
| AWS | Yes |
| Token-scoped Secrets  | Yes |
