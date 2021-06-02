package briefcase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path"
	"testing"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	testing2 "k8s.io/utils/clock/testing"
)

const (
	fakeSSHKeySize = 4096
)

var (
	testTime = time.Unix(1443332960, 0)
)

func createSSHSignedPublicKey(testTime time.Time, dir string, certTTL time.Duration, t *testing.T) {
	assert := assert.New(t)
	hostKeys, err := rsa.GenerateKey(rand.Reader, fakeSSHKeySize)
	assert.NoError(err)

	clientKeys, err := rsa.GenerateKey(rand.Reader, fakeSSHKeySize)
	assert.NoError(err)
	clientPKey, err := ssh.NewPublicKey(&clientKeys.PublicKey)
	assert.NoError(err)

	signer, err := ssh.NewSignerFromKey(hostKeys)
	assert.NoError(err)

	cert := &ssh.Certificate{
		Key:         clientPKey,
		ValidBefore: uint64(testTime.Add(certTTL).Unix()),
		ValidAfter:  uint64(testTime.Unix()),
	}
	assert.NoError(cert.SignCert(rand.Reader, signer))

	fd, err := os.Create(path.Join(dir, "id_rsa-cert.pub"))
	assert.NoError(err)
	_, err = fd.Write(ssh.MarshalAuthorizedKey(cert))
	assert.NoError(err)
	fd.Close()
}

func TestSSHCredentialsExpireAndRefreshCheck(t *testing.T) {
	assert := assert.New(t)

	ctx := clock.Set(context.Background(), testing2.NewFakeClock(testTime))

	bc := NewBriefcase(nil)

	tmpDir := t.TempDir()
	createSSHSignedPublicKey(testTime, tmpDir, time.Hour, t)

	certConfig := config.SSHCertificateType{
		VaultMount: "ssh",
		VaultRole:  "user-readonly",
		OutputPath: tmpDir,
	}

	bc.EnrollSSHCertificate(ctx, certConfig, 0)

	assert.True(bc.ShouldRefreshSSHCertificate(certConfig, clock.Now(ctx).Add(3601*time.Second)), "if cert expires before next check, should return true")
	assert.False(bc.ShouldRefreshSSHCertificate(certConfig, clock.Now(ctx).Add(45*60*time.Second)), "if cert expires after next check, should return false")

	// re-enroll, now with a forced refresh time.
	bc.EnrollSSHCertificate(ctx, certConfig, 30*time.Minute)

	assert.True(bc.ShouldRefreshSSHCertificate(certConfig, clock.Now(ctx).Add(45*60*time.Second)), "if cert expires after next check, but the tokens refresh ttl expires before next check, should return true")
	assert.False(bc.ShouldRefreshSSHCertificate(certConfig, clock.Now(ctx).Add(29*time.Minute)), "if cert expires after next check, and the tokens refresh ttl expires after next check, should return false")

	// create new key with longer expiry
	createSSHSignedPublicKey(testTime, tmpDir, 3602*time.Second, t)
	bc.EnrollSSHCertificate(ctx, certConfig, 0)
	assert.False(bc.ShouldRefreshSSHCertificate(certConfig, clock.Now(ctx).Add(3601*time.Second)), "if cert expires before next check, should return true")
	bc.EnrollSSHCertificate(ctx, certConfig, 3600*time.Second)
	assert.True(bc.ShouldRefreshSSHCertificate(certConfig, clock.Now(ctx).Add(3601*time.Second)), "if cert expires before next check, should return true")

	// test some edge cases
	createSSHSignedPublicKey(testTime, tmpDir, -1*time.Second, t)
	bc.EnrollSSHCertificate(ctx, certConfig, 0)
	assert.True(bc.ShouldRefreshSSHCertificate(certConfig, clock.Now(ctx)), "if cert already expired, should refresh")

	createSSHSignedPublicKey(testTime, tmpDir, 1*time.Second, t)
	assert.Error(bc.EnrollSSHCertificate(ctx, certConfig, -1*time.Second), "negative refresh TTL values should not be allowed")
}
