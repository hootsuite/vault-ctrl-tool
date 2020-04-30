package vaultclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/util"
	jww "github.com/spf13/jwalterweatherman"
)

//stsSigningResolver is borrowed from https://github.com/hashicorp/vault/blob/master/builtin/credential/aws/cli.go
func stsSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	defaultEndpoint, err := endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	if err != nil {
		return defaultEndpoint, err
	}

	defaultEndpoint.SigningRegion = region
	return defaultEndpoint, nil
}

//generateLoginData is borrowed from https://github.com/hashicorp/vault/blob/master/builtin/credential/aws/cli.go
func generateLoginData(creds *credentials.Credentials, configuredRegion string) (map[string]interface{}, error) {
	loginData := make(map[string]interface{})

	stsSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials:      creds,
			Region:           &configuredRegion,
			EndpointResolver: endpoints.ResolverFunc(stsSigningResolver),
		},
	})
	if err != nil {
		return nil, err
	}

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	stsRequest.Sign()

	// Now extract out the relevant parts of the request
	headersJson, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}

	loginData["iam_http_request_method"] = stsRequest.HTTPRequest.Method
	loginData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	loginData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headersJson)
	loginData["iam_request_body"] = base64.StdEncoding.EncodeToString(requestBody)

	return loginData, nil
}

func getSecret(c *api.Client, creds *credentials.Credentials, authBackendName string) (*api.Secret, error) {
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "us-east-1"
	}

	loginData, err := generateLoginData(creds, region)
	if err != nil {
		return nil, err
	}
	if loginData == nil {
		return nil, fmt.Errorf("got nil response from generateLoginData")
	}

	loginData["role"] = util.Flags.IamAuthRole

	secret, err := c.Logical().Write(fmt.Sprintf("auth/%s/login", authBackendName), loginData)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

func getCredentialsFromRole() (*credentials.Credentials, error) {
	awsSession, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("could not create a new session to use with the AWS SDK: %w", err)
	}

	roleProvider := &ec2rolecreds.EC2RoleProvider{
		Client: ec2metadata.New(awsSession),
	}
	creds := credentials.NewCredentials(roleProvider)

	_, err = creds.Get()
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func (vc *VaultClient) performIAMAuth() error {

	jww.INFO.Printf("Getting AWS IAM Role credentials")
	creds, err := getCredentialsFromRole()
	if err != nil {
		return fmt.Errorf("could not get IAM Role credentials: %w", err)
	}

	jww.INFO.Printf("Authenticating to vault at %q using role %s against the %s backend", vc.Config.Address, util.Flags.IamAuthRole, util.Flags.IamVaultAuthBackend)
	secret, err := getSecret(vc.Delegate, creds, util.Flags.IamVaultAuthBackend)

	if err != nil {
		return fmt.Errorf("could not authenticate to vault using IAM role authentication: %w", err)
	}

	token, err := secret.TokenID()
	if err != nil {
		return fmt.Errorf("could not extract Vault token: %w", err)
	}

	vc.AuthToken = secret
	vc.Delegate.SetToken(token)

	return nil
}
