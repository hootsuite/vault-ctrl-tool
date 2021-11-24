module github.com/hootsuite/vault-ctrl-tool/v2

go 1.17

require (
	github.com/aws/aws-sdk-go v1.35.25
	github.com/golang/mock v1.5.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/prometheus/client_golang v1.11.0
	github.com/rs/zerolog v1.20.0
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.20.8
	k8s.io/apimachinery v0.20.8
	k8s.io/client-go v0.20.8
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
)
