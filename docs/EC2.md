# Using EC2

Vault Control Tool can run both on startup to authenticate an EC2 instance to Vault, as well as periodically
in a cronjob to keep various secrets fresh for your system.

Note that EC2 support is new, please file issues as you encounter them.

## Setup

Your AMI creation process will ultimately generate an AMI id for your disk image. This AMI needs to be
registered with Vault and given specific policies.

```bash
vault write auth/aws-ec2/ami-6a616d6573 bound_ami_id=ami-6a616d6573 policies=service-policy bound_subnet_id=subnet-....
```

This creates an AWS role called `ami-6a616d6573` associated with the same AMI.

Vault Control Tool will automatically use the current AMI as the role name when authenticating without any
other configuration needed.

## Testing

The first time an AMI authenticates a nonce is established. If you are wanting to test Vault Control Tool
that is using a different mechanism already, you will need to collect its nonce to do testing (or reset
the nonce for the instance in the whitelist).

## On Startup

Assuming you have a `vault-config.yml` in `/etc/vault-ctrl-tool`, initialization is as easy as:

```bash
export VAULT_ADDR=https://vault.service.consul:8200/
vault-ctrl-tool --ec2-auth --init --input-prefix=/etc/vault-ctrl-tool --output-prefix=/etc/vault-ctrl-tool
```

## Sidecar

You can either launch Vault Control Tool as a process, or call it from cron. The later is the recommended
mechanism:

```bash
export VAULT_ADDR=https://vault.service.consul:8200/
vault-ctrl-tool --sidecar --one-shot --input-prefix=/etc/vault-ctrl-tool --output-prefix=/etc/vault-ctrl-tool
```
