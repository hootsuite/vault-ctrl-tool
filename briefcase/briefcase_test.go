package briefcase

import (
	"context"
	"encoding/json"
	"github.com/hootsuite/vault-ctrl-tool/v2/metrics"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"
	testing2 "k8s.io/utils/clock/testing"
	"os"
	"path"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

const exampleToken = `{
  "request_id": "cd08f32e-f7be-60e9-4af7-d76929bd2a14",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "8FvDM61Vc23jht83if5bFWlC",
    "creation_time": 1598732682,
    "creation_ttl": 32400,
    "display_name": "ldap-james.atwill",
    "entity_id": "07ef9c85-9f14-1272-eb56-92b7bfd21500",
    "expire_time": "2020-07-29T22:24:42.348650363-07:00",
    "explicit_max_ttl": 0,
    "id": "s.eD8onDKEpvQqNCrSZDwxPLld",
    "issue_time": "2020-07-29T13:24:42.348663695-07:00",
    "meta": {
      "username": "james.atwill"
    },
    "num_uses": 0,
    "orphan": true,
    "path": "auth/ldap/login/james.atwill",
    "policies": [
		"a",
		"b",
		"c",
		"default"
    ],
    "renewable": true,
    "ttl": 32382,
    "type": "service"
  },
  "warnings": null
}`

func myToken(t *testing.T) api.Secret {
	var secret api.Secret
	err := json.Unmarshal([]byte(exampleToken), &secret)
	assert.NoError(t, err, "could not deserialize example token: %v", err)
	return secret
}

func TestSavePermissions(t *testing.T) {
	tempDir := t.TempDir()
	defer os.RemoveAll(tempDir)
	filename := path.Join(tempDir, "briefcase")

	emptyBriefcase := NewBriefcase(nil)
	err := emptyBriefcase.SaveAs(filename)
	assert.NoError(t, err, "must be able to save empty briefcase. filename=%q", filename)

	stat, err := os.Stat(filename)
	assert.NoError(t, err, "must be able to Stat() briefcase. filename=%q", filename)

	// bitwise 'and' the "group" and "other" modes which should both be zero, so the result should be 0.
	assert.Zero(t, stat.Mode()&0077, "briefcase must only be accessible to owner")
}

func TestSaveAndLoadEmpty(t *testing.T) {
	tempDir := t.TempDir()
	defer os.RemoveAll(tempDir)
	filename := path.Join(tempDir, "briefcase")

	emptyBriefcase := NewBriefcase(nil)
	err := emptyBriefcase.SaveAs(filename)
	assert.NoError(t, err, "must be able to save empty briefcase. filename=%q", filename)

	loadedBriefcase, err := LoadBriefcase(filename, nil)
	assert.NoError(t, err, "must be able to load empty briefcase. filename=%q", filename)

	assert.EqualValues(t, emptyBriefcase, loadedBriefcase, "empty briefcase and loaded empty briefcase must be the same")
}

func TestSaveAndLoadEnrolledToken(t *testing.T) {
	tempDir := t.TempDir()
	defer os.RemoveAll(tempDir)
	filename := path.Join(tempDir, "briefcase")

	bc := NewBriefcase(nil)

	token := myToken(t)

	assert.NoError(t, bc.EnrollVaultToken(context.Background(), util.NewWrappedToken(&token, true)), "must be able to enroll example token in briefcase")
	assert.NoError(t, bc.SaveAs(filename), "must be able to save briefcase")

	loadedBriefcase, err := LoadBriefcase(filename, nil)
	assert.NoError(t, err, "must be able to reload briefcase")

	assert.False(t, loadedBriefcase.ShouldRefreshVaultToken(context.TODO()), "must not need to refresh a token with a TTL")
	assert.Equal(t, "s.eD8onDKEpvQqNCrSZDwxPLld", loadedBriefcase.AuthTokenLease.Token, "loaded token must equal saved token")
	assert.Equal(t, "8FvDM61Vc23jht83if5bFWlC", loadedBriefcase.AuthTokenLease.Accessor, "loaded accessor must equal saved accessor")
}

func TestExpiringTokenNeedsRefresh(t *testing.T) {
	bc := NewBriefcase(nil)
	token := myToken(t)

	token.Data["ttl"] = 299

	assert.NoError(t, bc.EnrollVaultToken(context.TODO(), util.NewWrappedToken(&token, true)), "must be able to enroll example token in briefcase")
	assert.True(t, bc.ShouldRefreshVaultToken(context.TODO()), "token expiring in less than 5 minutes must require a refresh")
}

func TestExpiringNonRenewableTokenNeverNeedsRefresh(t *testing.T) {
	bc := NewBriefcase(nil)
	token := myToken(t)

	token.Data["ttl"] = 1

	assert.NoError(t, bc.EnrollVaultToken(context.TODO(), util.NewWrappedToken(&token, false)), "must be able to enroll example token in briefcase")
	assert.False(t, bc.ShouldRefreshVaultToken(context.TODO()), "non renewable token must never need refreshing")
}

func TestExpiredNonRenewableTokenNeverNeedsRefresh(t *testing.T) {
	bc := NewBriefcase(nil)
	token := myToken(t)

	fakeClock := testing2.NewFakeClock(time.Now())
	clockContext := clock.Set(context.Background(), fakeClock)

	assert.NoError(t, bc.EnrollVaultToken(clockContext, util.NewWrappedToken(&token, false)), "must be able to enroll example token in briefcase")

	fakeClock.Sleep(100 * time.Hour)
	assert.False(t, bc.ShouldRefreshVaultToken(clockContext), "non renewable token must never need refreshing")
}

func TestNilTokenEnrollment(t *testing.T) {
	bc := NewBriefcase(nil)

	assert.NotPanics(t, func() {
		assert.Error(t, bc.EnrollVaultToken(context.TODO(), nil), "trying to enroll a nil token must return an error")
	}, "trying to enroll a nil token must not panic()")
}

func TestResetBriefcase(t *testing.T) {
	s := map[string]bool{
		"a": true,
		"b": true,
	}

	sversioned := map[string]int64{
		"a": 3,
		"b": 8,
	}

	aws := map[string]leasedAWSCredential{
		"foo": {},
		"bar": {},
	}

	ssh := map[string]sshCert{
		"baz": {},
	}

	mtrcs := metrics.NewMetrics()
	big := NewBriefcase(mtrcs)
	big.AWSCredentialLeases = aws
	big.SSHCertificates = ssh
	big.TokenScopedTemplates = s
	big.StaticTemplates = s
	big.TokenScopedSecrets = s
	big.StaticScopedSecrets = s
	big.TokenScopedComposites = s
	big.StaticScopedComposites = s
	big.VersionScopedSecrets = sversioned

	small := NewBriefcase(mtrcs)
	small.AWSCredentialLeases = aws
	small.SSHCertificates = ssh
	small.StaticTemplates = s
	small.StaticScopedSecrets = s
	small.StaticScopedComposites = s
	small.VersionScopedSecrets = sversioned
	resetBig := big.ResetBriefcase()

	assert.EqualValues(t, small, resetBig, "resetting a briefcase should leave non-token scoped data")
	assert.Equal(t, 1, mtrcs.Counter(metrics.BriefcaseReset))
}
