package vaultclient

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/util"
	jww "github.com/spf13/jwalterweatherman"
)

func (vc *VaultClient) fetchAMI() (string, error) {
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

func (vc *VaultClient) fetchPKCS7() (string, error) {
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

func (vc *VaultClient) performEC2Auth() error {

	type login struct {
		Role  string `json:"role"`
		Pkcs7 string `json:"pkcs7"`
		Nonce string `json:"nonce,omitempty"`
	}

	pkcs7, err := vc.fetchPKCS7()

	if err != nil {
		return err
	}

	jww.DEBUG.Printf("Fetched PKCS7 payload of %d bytes.", len(pkcs7))

	ami, err := vc.fetchAMI()

	if err != nil {
		return err
	}

	jww.DEBUG.Printf("Looked up AMI is %q.", ami)

	req := vc.Delegate.NewRequest("POST", util.VaultEC2AuthPath)

	authValues := login{Role: ami, Pkcs7: pkcs7, Nonce: util.Flags.EC2VaultNonce}
	err = req.SetJSONBody(authValues)

	if err != nil {
		return fmt.Errorf("could not perform EC2 authentication: %w", err)
	}

	jww.DEBUG.Printf("Sending EC2 Auth request to %q", req.URL)

	resp, err := vc.Delegate.RawRequest(req)
	if err != nil {
		return err
	}

	if resp.Error() != nil {
		return resp.Error()
	}

	var secret api.Secret

	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return fmt.Errorf("could not parse response: %w", err)
	}

	jww.DEBUG.Printf("Result: %v", secret)

	token, err := secret.TokenID()
	if err != nil {
		return fmt.Errorf("could not extract Vault token: %w", err)
	}

	vc.AuthToken = &secret
	vc.Delegate.SetToken(token)

	return nil
}
