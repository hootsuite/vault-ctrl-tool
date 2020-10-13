package vaultclient

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
)

func (auth *ec2amiAuthenticator) Authenticate() (*util.WrappedToken, error) {

	secret, err := auth.performEC2AMIAuth()
	if err != nil {
		auth.log.Error().Err(err).Msg("ec2 ami authentication failed")
		return nil, err
	}
	return secret, nil
}

func (auth *ec2amiAuthenticator) performEC2AMIAuth() (*util.WrappedToken, error) {

	type login struct {
		Role  string `json:"role"`
		Pkcs7 string `json:"pkcs7"`
		Nonce string `json:"nonce,omitempty"`
	}

	pkcs7, err := auth.fetchPKCS7()

	if err != nil {
		return nil, err
	}
	auth.log.Debug().Int("len(pkcs7)", len(pkcs7)).Msg("fetched PKCS7 payload")

	ami, err := auth.fetchAMI()
	if err != nil {
		return nil, err
	}
	auth.log.Debug().Str("ami", ami).Msg("found current AMI")

	req := auth.vaultClient.Delegate().NewRequest(http.MethodPost, util.VaultEC2AuthPath)

	authValues := login{Role: ami, Pkcs7: pkcs7, Nonce: auth.ec2Nonce}
	err = req.SetJSONBody(authValues)
	if err != nil {
		auth.log.Error().Err(err).Str("ami", ami).Msg("failed to create authentication request")
		return nil, fmt.Errorf("failed to create authentication request: %w", err)
	}

	auth.log.Info().Str("url", req.URL.String()).Str("ami", ami).Msg("sending EC2 AMI request")

	response, err := auth.vaultClient.Delegate().RawRequest(req)
	if err != nil {
		auth.log.Error().Err(err).Msg("failed to process authentication request")
		return nil, err
	}

	if response.Error() != nil {
		auth.log.Error().Err(response.Error()).Msg("authentication request failed")
		return nil, fmt.Errorf("authentication request failed: %w", response.Error())
	}

	var secret api.Secret

	err = json.NewDecoder(response.Body).Decode(&secret)
	if err != nil {
		return nil, fmt.Errorf("could not parse response: %w", err)
	}

	return util.NewWrappedToken(&secret, true), nil
}

func (auth *ec2amiAuthenticator) fetchAMI() (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/ami-id")

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (auth *ec2amiAuthenticator) fetchPKCS7() (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	pkcs7 := strings.Replace(string(body), "\n", "", -1)

	return pkcs7, nil
}
