package vaulttoken

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	mock_vaultclient "github.com/hootsuite/vault-ctrl-tool/v2/vaultclient/mocks"
	"github.com/stretchr/testify/assert"
)

const exampleToken1 = `{
  "request_id": "cd08f32e-f7be-60e9-4af7-d76929bd2a14",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "8FvDM61Vc23jht83if5bFWlC",
    "creation_time": 1598732682,
    "creation_ttl": 32400,
    "display_name": "ldap-test1",
    "entity_id": "07ef9c85-9f14-1272-eb56-92b7bfd21500",
    "expire_time": "2020-07-29T22:24:42.348650363-07:00",
    "explicit_max_ttl": 0,
    "id": "s.eD8onDKEpvQqNCrSZDwxPLld",
    "issue_time": "2020-07-29T13:24:42.348663695-07:00",
    "meta": {
      "username": "test1"
    },
    "num_uses": 0,
    "orphan": true,
    "path": "auth/ldap/login/test1",
    "policies": [
      "default"
    ],
    "renewable": true,
    "ttl": 32382,
    "type": "service"
  },
  "warnings": null
}`

func makeToken(t *testing.T, id string) api.Secret {
	var secret api.Secret
	err := json.Unmarshal([]byte(exampleToken1), &secret)
	assert.NoError(t, err, "could not deserialize example token: %v", err)

	secret.Data["id"] = id
	secret.Data["accessor"] = "accessor:" + id

	return secret
}

func TestEmptyVaultToken(t *testing.T) {
	ctrl := gomock.NewController(t)

	vaultClient := mock_vaultclient.NewMockVaultClient(ctrl)
	newAPIClient, err := api.NewClient(nil)
	assert.NoError(t, err, "could not create default hashicorp/vault/api client")
	vaultClient.EXPECT().Delegate().Return(newAPIClient)

	bc := briefcase.NewBriefcase()
	vaultToken := NewVaultToken(bc, vaultClient, "")

	assert.Equal(t, "", vaultToken.Accessor(), "freshly created vault token must not have a token in it")
	assert.Equal(t, "", vaultToken.TokenID(), "freshly crated vault token must not have a token in it")
}

func TestGetAndSetVaultToken(t *testing.T) {
	ctrl := gomock.NewController(t)

	vaultClient := mock_vaultclient.NewMockVaultClient(ctrl)
	newAPIClient, err := api.NewClient(nil)
	assert.NoError(t, err, "could not create default hashicorp/vault/api client")
	vaultClient.EXPECT().Delegate().Return(newAPIClient)

	bc := briefcase.NewBriefcase()
	vaultToken := NewVaultToken(bc, vaultClient, "")

	token := makeToken(t, "token-1")
	err = vaultToken.Set(&token)
	assert.NoError(t, err, "must be able to set token")

	assert.Equal(t, "accessor:token-1", vaultToken.Accessor(), "accessor must match value in token")
	assert.Equal(t, "token-1", vaultToken.TokenID(), "token must match value in token")
}

// TestVerifyBriefcaseIfSet ensures that if there's a valid vault token in the briefcase, it is used.
func TestVerifyBriefcaseIfSet(t *testing.T) {
	ctrl := gomock.NewController(t)

	vaultClient := mock_vaultclient.NewMockVaultClient(ctrl)
	newAPIClient, err := api.NewClient(nil)
	assert.NoError(t, err, "could not create default hashicorp/vault/api client")
	vaultClient.EXPECT().Delegate().Return(newAPIClient)

	bc := briefcase.NewBriefcase()
	vaultToken := NewVaultToken(bc, vaultClient, "")

	token := makeToken(t, "token-1")
	assert.NoError(t, err, bc.EnrollVaultToken(context.TODO(), &token), "must be able to enroll example vault token in briefcase")

	vaultClient.EXPECT().VerifyVaultToken("token-1").Return(&token, nil)

	err = vaultToken.CheckAndRefresh()
	assert.NoError(t, err, "must accept valid briefcase token if set")

	assert.Equal(t, "accessor:token-1", vaultToken.Accessor(), "accessor must match value in token")
	assert.Equal(t, "token-1", vaultToken.TokenID(), "token must match value in token")
}

func TestBadBriefcaseGoodCLI(t *testing.T) {
	ctrl := gomock.NewController(t)

	vaultClient := mock_vaultclient.NewMockVaultClient(ctrl)
	newAPIClient, err := api.NewClient(nil)
	assert.NoError(t, err, "could not create default hashicorp/vault/api client")
	vaultClient.EXPECT().Delegate().Return(newAPIClient)

	bc := briefcase.NewBriefcase()
	briefcaseToken := makeToken(t, "token-1")
	assert.NoError(t, err, bc.EnrollVaultToken(context.TODO(), &briefcaseToken), "must be able to enroll example vault token in briefcase")

	cliToken := makeToken(t, "token-2")
	vaultToken := NewVaultToken(bc, vaultClient, "token-2")

	vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).DoAndReturn(
		func(token string) (*api.Secret, error) {
			if token == "token-2" {
				return &cliToken, nil
			}
			return nil, errors.New("any error goes here")
		}).Times(2)

	err = vaultToken.CheckAndRefresh()
	assert.NoError(t, err, "must accept valid CLI token if set")

	assert.Equal(t, "token-2", vaultToken.TokenID(), "token must match value in token")
	assert.Equal(t, "accessor:token-2", vaultToken.Accessor(), "accessor must match value in token")
}

// TestVerifySequence ensures that first the briefcase is checked, then the CLI arg, then env vars, ultimately
// returning ErrNoValidVaultTokenAvailable.
func TestVerifySequence(t *testing.T) {
	ctrl := gomock.NewController(t)

	vaultClient := mock_vaultclient.NewMockVaultClient(ctrl)
	newAPIClient, err := api.NewClient(nil)
	assert.NoError(t, err, "could not create default hashicorp/vault/api client")
	vaultClient.EXPECT().Delegate().Return(newAPIClient)

	bc := briefcase.NewBriefcase()
	briefcaseToken := makeToken(t, "token-1")
	assert.NoError(t, err, bc.EnrollVaultToken(context.TODO(), &briefcaseToken), "must be able to enroll example vault token in briefcase")

	vaultToken := NewVaultToken(bc, vaultClient, "token-2")
	os.Setenv("VAULT_TOKEN", "token-3")

	gomock.InOrder(
		vaultClient.EXPECT().VerifyVaultToken("token-1").Return(nil, errors.New("some error 1")),
		vaultClient.EXPECT().VerifyVaultToken("token-2").Return(nil, errors.New("some error 2")),
		vaultClient.EXPECT().VerifyVaultToken("token-3").Return(nil, errors.New("some error 3")),
	)

	err = vaultToken.CheckAndRefresh()
	assert.True(t, errors.Is(err, ErrNoValidVaultTokenAvailable), "CheckAndReturn must return ErrNoValidVaultTokenAvailable if there isn't")
}

// TODO if token is valid, but TTL is less than 3 seconds, then it's not valid
// TODO if token is valid for 3..59 seconds, then ensure it's refreshed
//			if refresh fails, then token is no good
// TODO if refresh succeeds, but only gets 30 seconds left, then token is no good
