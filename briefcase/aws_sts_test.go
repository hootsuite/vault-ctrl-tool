package briefcase

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"
	"github.com/stretchr/testify/assert"
	testing2 "k8s.io/utils/clock/testing"
)

const stsCreds = `
{
  "request_id": "117d1888-501c-7d83-16fd-9a4dab95268e",
  "lease_id": "aws/creds/user-readonly/0c5fUcbvbZ10OW9aa4BEV7UX",
  "lease_duration": 3600,
  "renewable": false,
  "data": {
    "access_key": "ASIARUFKCQPWQGZBN2D5",
    "secret_key": "rQFWMmrTgKPOC0EzhE095RZ1BTufIH59vx+Iwicc",
    "security_token": "FwoGZXIvYXdzEIT//////////wEaDGpHUM2Pj5PZ7cX9CCLeAWWKevneTafapQ3fEj2sVN/g0kamUHQmsBpIOSsI7Ew/D1XnUTa+ufswXhMDcG09LOqea+OSzCJj+w5GBJIVZ81vw/sAHKNhBtX3t+gcITxDttR3RFEhRpqLe2s/yI73/Ral6t644OfQv7Xs/G1A6WWMDT79B5GNVLFmI+uhNLEuDcBlPmC5aLyb6DZps/PvBAu23mUNZXKTGL2PA7gg/rIADdgcMn9P3dwPqOlQQ7Oc87J3HuU9plHE4y8jZPTwh555cTSJIrfk7h+z+4z90ZKcXz07J/zAkgDhcItPvyiw67b6BTItlUahvc5Bg3yZJe1IPufdUk3UKRn7tGaReOaEXCtuEVevkrGc9xTN/ELeSsaf"
  },
  "warnings": null
}`

func mySTSCreds(t *testing.T) api.Secret {
	var secret api.Secret
	err := json.Unmarshal([]byte(stsCreds), &secret)
	assert.NoError(t, err, "could not deserialize example STS lease: %v", err)
	return secret
}

func TestAWSCredentialExpireCheck(t *testing.T) {
	awsCreds := mySTSCreds(t)
	awsConfig := config.AWSType{
		VaultMountPoint: "aws",
		VaultRole:       "user-readonly",
		Profile:         "default",
		Region:          "us-east-1",
		OutputPath:      "/tmp",
		Mode:            "0700",
	}

	testTime := time.Unix(1443332960, 0)

	ctx := clock.Set(context.Background(), testing2.NewFakeClock(testTime))

	bc := NewBriefcase(nil)
	bc.EnrollAWSCredential(ctx, &awsCreds, awsConfig)

	assert.False(t, bc.AWSCredentialExpiresBefore(awsConfig, testTime), "freshly enrolled STS token must not need refreshing")
	assert.False(t, bc.AWSCredentialExpiresBefore(awsConfig, testTime.Add(3599*time.Second)), "must not return true before the expiry of the STS token")
	assert.True(t, bc.AWSCredentialExpiresBefore(awsConfig, testTime.Add(time.Hour)), "must return true on the expiry of the token")
	assert.True(t, bc.AWSCredentialExpiresBefore(awsConfig, testTime.Add(3601*time.Second)), "must return true when creds are expired")
}
