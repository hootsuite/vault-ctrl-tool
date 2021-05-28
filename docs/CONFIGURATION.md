# Tour Of vault-config.yml

* [Concepts](#concepts)
* [Vault Token](#vaultToken)
* [Templates](#templates)
* [Secrets](#secrets)
* [SSH Keys](#ssh)
* [AWS](#aws)


### Concepts

At the top of your configuration file, is a `version`. Upgrading from one configuration version to another may
require some small changes to your configuration file.  See the README and CHANGELOG at the root of the project.

Secrets and templates both have a `lifetime`. Lifetimes are how the tool knows when it needs to rewrite your
secrets or templates. Templates and secrets can use `token` and `static`. There is a third lifetime of
`version` discussed below. Secrets and templates with static lifetimes are never rewritten once they're
initially created. It is assumed the secrets in those files are static, and as a service using this tool,
you would rather have to force restarting things in order to get new secrets (either by restarting your
Kubernetes pod, terminating an EC2 instance in an ASG, or deleting the briefcase file - causing the tool to lose state).

The lifetime of `token` indicates that the secrets contained in the files become invalid if the Vault token
being used expires. These secrets will be fetched again, and files will be rewritten out of necessity after the tool
re-authenticates.

The lifetime of `version` is quite special, only valid on secrets stored in a KVv2 backend, and has a limited use case. 
Secrets that do not have an `output` may use `version`. When the tool runs, it will always fetch a copy of the secret from
Vault. If the version in Vault is newer than the one in the briefcase, and the new secret is older than 30 seconds, any
fields that specify an `output` will be overwritten. See the [Secrets](#secrets) section below before using this.

These examples assume you're running with `--input-prefix /etc/vault-config --output-prefix /etc/secrets`.

### VaultToken

```yaml
#
# Write a copy of the token to /etc/secrets/example/target/vault-token - This can be used by your
# service if you interact with Vault directly and want to take care of keeping your credentials
# refreshed, etc. This is useful if you have some use case not covered by the tool and want
# to interact with Vault directly. Note that vault-ctrl-tool may rewrite this file if it needs
# to relogin to Vault when running in sidecar mode.
vaultToken:
  output: example/target/vault-token
  mode: 0777
```

### Templates

```yaml
#
# Templates allow you to make your own custom output files using golang templates, secrets will
# be written to the file as specified. Templates should be included with the ConfigMap where
# the vault-config.yml is specified
templates:
  - input: example-test.tpl
    output: example/target/test
    mode: 0777
    lifetime: static
# Read template from /etc/vault-config/example-test.tpl and write to /etc/secrets/example/target/test
```

### Secrets

Secrets are a core piece of Vault, so there are a few examples here.

#### Secrets: Original Example

```yaml
#
# The /secret/ backend (aka the v1 kv secrets backend). The specified "path" is read from Vault,
# and the keys returned are made available in templates prefixed with the "key" value below. If
# an "output" file is specified the keys and values are written in JSON format to the output file.
# If "path" is relative, it is prefixed with "/secret/application-config/services/". If "use_key_as_prefix"
# is set to true, then the fields written to the JSON file will be prefixed with the key followed by
# an underscore (so "ex_api_key" and "ex_api_secret" in the example below).
# Note that "key" must be unique across all secrets.
secrets:
    - key: ex
      path: example/keys
      output: example/target/example.secrets
      use_key_as_prefix: true
      mode: 0777
      owner: root
      missingOk: true
      lifetime: static
      fields:
        - name: api_key
          output: api/key
        - name: api_secret
          output: api/secret
        - name: license
          output: license.key
          encoding: base64

# If "example/keys" had a secret of "foo" with the value "bar", then templates could
# reference {{.ex_foo}} to get "bar", and the file /etc/secrets/example/target/example.secrets would
# have the JSON of '{"ex_foo": "bar"}' in it (as "use_key_as_prefix" is set to true).
# If Vault doesn't have an "example/keys", then it will be
# noisily ignored as 'missingOk' is set to true -- the tool cannot tell the difference between a path it
# cannot access and a path with no secrets. Be warned. The contents of the individual fields in the
# secret ("api_key" and "api_secret") will be written verbatim to "/etc/secrets/api/key" and
# "/etc/secrets/api/secret" if the fields present. The field "license" will be written to 
# "/etc/secrets/license.key", but the value stored in Vault will be manually base64 decoded. Fields must
# be manually base64 encoded before being written to take advangate of "encoding: base64".
# If owner is specified, the ownership of all secret files will be changed to the owner.
# NOTE: All files share the same file mode.
# NOTE: If you have multiple secrets sharing the same output file, they will use the file mode
# of the first stanza.
```

#### Secrets: Pinned Version

```yaml
# A small example using "pinnedVersion". This only works on KVv2 secrets and is very dangerous to use.
# If you forget that pinnedVersion is set and update your secrets, systems using the old version will cease to function
# which can easily lead to outages. Use only sparingly for testing. Do not use this defensively "just in case someone"
# changes the secret.

secrets:
    - path: example/keys
      output: example.secrets
      mode: 0700
      missingOk: false
      pinnedVersion: 2
      lifetime: static

```

#### Secrets: "Version" Lifetime

```yaml
# Version lifetimes are available for secrets that do not have an "output". They inherently go against the
# existing workflow that one would expect from vault-ctrl-tool. 

secrets:
  - key: ex
    path: example/keys
    mode: 0777
    missingOk: false
    lifetime: version
    touchfile: /etc/third-party/last-refresh
    fields:
      - name: api_key
        output: api/key
      - name: api_secret
        output: api/secret

# Each time vault-ctrl-tool runs to synchronize the on-disk output with what is in Vault, it will fetch the above
# secret from Vault. If the version in Vault is newer, and at least 30 seconds old, it will rewrite the output
# of the fields (in this case "api/key" and "api/secret"). After it rewrites the fields, it will "touch" the
# listed "touchfile" (in this case "/etc/third-party/last-refresh"). Services that want to be notified when there
# are changes must watch the "touchfile" which will be touched after all the fields are updated.
```

### SSH

```yaml
#
# The tool will create a public/private keypair and have the public key signed by Vault at the
# mount point specified requesting the role specified. Files written are only readable by the
# owner and will all exist in the  "/etc/secrets/ssh-key/" directory under the names "id_rsa",
# "id_rsa.pub" and "id_rsa-cert.pub". Services can use the files directly
# ( ssh -i /etc/secrets/ssh-key/id_rsa ), or do with them as they wish.  In sidecar mode, the public
# key will be signed periodically to ensure it doesn't expire, writing it to the same
# location. Services that copy the file elsewhere will need to periodically update their copy.
sshCertificates:
  - vaultMountPoint: ssh/keyprovider
    vaultRole: jenkins
    outputPath: ssh-key
```

### AWS

```yaml
# The tool will fetch AWS credentials from Vault on your behalf (Vault has permission to
# sts:AssumeRole a number of roles). It will manage these credentials and pass them to your
# service. Running in sidecar mode, the credentials will be kept refreshed and will be rewritten
# hourly so they're always fresh. Services that copy the output file somewhere else will need to
# periodically update their copy. Services are instead encouraged to set AWS_CONFIG_FILE and
# AWS_SHARED_CREDENTIALS_FILE to the config and credentials files in outputPath.
aws:
  - awsProfile: default
    vaultMountPoint: aws
    vaultRole: jenkins
    awsRegion: us-east-1
    outputPath: aws
    mode: 0777
  - awsProfile: special
    vaultMountPoint: aws
    vaultRole: special-role
    awsRegion: us-east-1
    outputPath: aws
    mode: 0777
 # The above will output a "/etc/secrets/aws/config" and "/etc/secrets/aws/credentials" with
 # two AWS profiles ("default", and "special") which can  be specified with AWS_PROFILE. 
```
