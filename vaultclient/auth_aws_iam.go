package vaultclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"
)

func (auth *ec2iamAuthenticator) Authenticate() (*api.Secret, error) {
	secret, err := auth.performEC2IAMAuth()
	if err != nil {
		auth.log.Error().Err(err).Msg("ec2 iam authentication failed")
		return nil, err
	}
	return secret, nil
}

//stsSigningResolver is borrowed from https://github.com/hashicorp/vault/blob/master/builtin/credential/aws/cli.go
func (auth *ec2iamAuthenticator) stsSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	defaultEndpoint, err := endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	if err != nil {
		return defaultEndpoint, err
	}

	defaultEndpoint.SigningRegion = region
	return defaultEndpoint, nil
}

//generateLoginData is borrowed from https://github.com/hashicorp/vault/blob/master/builtin/credential/aws/cli.go
func (auth *ec2iamAuthenticator) generateLoginData(creds *credentials.Credentials, configuredRegion string) (map[string]interface{}, error) {
	loginData := make(map[string]interface{})

	stsSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials:      creds,
			Region:           &configuredRegion,
			EndpointResolver: endpoints.ResolverFunc(auth.stsSigningResolver),
		},
	})
	if err != nil {
		return nil, err
	}

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	if err := stsRequest.Sign(); err != nil {
		return nil, err
	}

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

func (auth *ec2iamAuthenticator) getSecret(creds *credentials.Credentials) (*api.Secret, error) {

	loginData, err := auth.generateLoginData(creds, auth.awsRegion)
	if err != nil {
		return nil, err
	}
	if loginData == nil {
		return nil, fmt.Errorf("got nil response from generateLoginData")
	}

	loginData["role"] = auth.iamAuthRole

	secret, err := auth.vaultClient.Delegate().Logical().Write(fmt.Sprintf("auth/%s/login", auth.iamVaultAuthBackend), loginData)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

func (auth *authenticator) getCredentialsFromRole() (*credentials.Credentials, error) {
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

func (auth *ec2iamAuthenticator) performEC2IAMAuth() (*api.Secret, error) {

	auth.log.Info().Msg("starting authenticating with IAM role")

	creds, err := auth.getCredentialsFromRole()
	if err != nil {
		return nil, fmt.Errorf("could not get IAM Role credentials: %w", err)
	}

	auth.log.Info().Str("role", auth.iamAuthRole).Str("vault_auth_path", auth.iamVaultAuthBackend).Msg("performing authentication")

	secret, err := auth.getSecret(creds)

	if err != nil {
		return nil, fmt.Errorf("could not authenticate to vault using IAM role authentication: %w", err)
	}

	return secret, nil
}
