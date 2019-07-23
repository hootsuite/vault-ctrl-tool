
# Welcome

Hi! Thanks for taking a look at `vault-ctrl-tool`. This is a quick tool that manages, authentication, 
applying secrets, and refreshing leases for services.

# Tour Of vault-config.yml

* [Vault Token](#vaultToken)
* [Templates](#templates)
* [Secrets](#secrets)
* [SSH Keys](#ssh)
* [AWS](#aws)
* [Databases](#databases)

```yaml

# Important! vault-ctrl-tool runs with "--output-prefix /etc/secrets", so all output files you see
# below are actually inside /etc/secrets. The tool will build all necessary subdirectories.

# Also Important! vault-ctrl-tool runs with "--input-prefix /etc/vault-config", so all template
# files, and the  config file are looked for in /etc/vault-config.
```

### VaultToken

```yaml
#
# Write a copy of the token to /etc/secrets/example/target/vault-token - This can be used by your
# service if you interact with Vault directly and want to take care of keeping your credentials
# refreshed, etc..   This is useful if you have some use case not covered by the tool and want
# to interact with Vault directly.
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
# Read template from /etc/vault-config/example-test.tpl and write to /etc/secrets/example/target/test
```

### Secrets

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
      missingOk: true
      fields:
        - name: api_key
          output: api/key
        - name: api_secret
          output: api/secret
# If "example/keys" had a secret of "foo" with the value "bar", then templates could
# reference {{.ex_foo}} to get "bar", and the file /etc/secrets/example/target/example.secrets would
# have the JSON of '{"ex_foo": "bar"}' in it (as "use_key_as_prefix" is set to true).
# If Vault doesn't have an "example/keys", then it will be
# noisily ignored as 'missingOk' is set -- the tool cannot tell the difference between a path it
# cannot access and a path with no secrets. Be warned. The contents of the individual fields in the
# secret ("api_key" and "api_secret") will be written verbatim to "/etc/secrets/api/key" and
# "/etc/secrets/api/secret" if they're present. All files share the same file mode.
# NOTE: If you have multiple secrets sharing the same output file, they will use the file mode
# of the first stanza.
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
  - vaultMountPoint: ssh/hootca
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

### Databases

```yaml
# This does not work yet.
databases:
  - connection:
      vault_role: mydb1
      key: mydb1
      output: /tmp/mydb1.secrets
  - connection:
      vault_role: mydb2
      key: mydb2
      output: /tmp/mydb2.secrets
```
