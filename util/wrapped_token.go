package util

import "github.com/hashicorp/vault/api"

type WrappedToken struct {
	*api.Secret
	Renewable bool
}

func NewWrappedToken(secret *api.Secret, renewable bool) *WrappedToken {
	return &WrappedToken{
		Secret:    secret,
		Renewable: renewable,
	}
}
