package briefcase

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"
	"golang.org/x/crypto/ssh"
)

var neverExpires = time.Unix(0, 0)

func (b *Briefcase) ShouldRefreshSSHCertificate(sshCertConfig config.SSHCertificateType, expiresBefore time.Time) bool {
	entry, ok := b.SSHCertificates[sshCertConfig.OutputPath]
	if !ok {
		return true
	}

	b.log.Debug().Time("expiry", entry.Expiry).Str("outputPath", sshCertConfig.OutputPath).Msg("determined expiry of ssh certificate")

	certExpiresBefore := entry.Expiry.Before(expiresBefore) || entry.Expiry == neverExpires
	shouldRefreshBefore := entry.RefreshExpiry != nil && !entry.RefreshExpiry.IsZero() && entry.RefreshExpiry.Before(expiresBefore)

	return certExpiresBefore || shouldRefreshBefore
}

func createRefreshExpiry(ctx context.Context, forceRefreshTTL time.Duration) *time.Time {
	var refreshExpiry *time.Time
	// we only add a refresh if a ttl value was set.
	if forceRefreshTTL > 0 {
		exp := clock.Now(ctx).Add(forceRefreshTTL)
		refreshExpiry = &exp
	}
	return refreshExpiry
}

// EnrollSSHCertificate adds a managed SSH certificate to briefcase. If forceRefreshTTL is not zero, then it will associate a
// refresh expiry time with the certificate.
func (b *Briefcase) EnrollSSHCertificate(ctx context.Context, sshCertConfig config.SSHCertificateType, forceRefreshTTL time.Duration) error {
	if forceRefreshTTL < 0 {
		return fmt.Errorf("forceRefreshTTL cannot be negative: %s", forceRefreshTTL)
	}

	certificateFilename := filepath.Join(sshCertConfig.OutputPath, util.SSHCertificate)

	log := b.log.With().Str("filename", certificateFilename).Logger()

	log.Debug().Msg("enrolling ssh certificate")
	validBefore, err := b.readSSHCertificateValidBefore(certificateFilename)
	if err != nil {
		log.Debug().Err(err).Msg("failed to read ssh valid before field in certificate")
		return err
	}

	var validBeforeTime time.Time

	if validBefore == ssh.CertTimeInfinity {
		b.log.Warn().Str("sshCertificate", certificateFilename).Msg("ssh certificate never expires")
		validBeforeTime = neverExpires
	} else {
		validBeforeTime = time.Unix(int64(validBefore), 0)
	}

	log.Debug().Time("validBefore", validBeforeTime).Msg("ssh certificate validity")
	b.SSHCertificates[sshCertConfig.OutputPath] = sshCert{
		Expiry:        validBeforeTime,
		RefreshExpiry: createRefreshExpiry(ctx, forceRefreshTTL),
		Cfg:           sshCertConfig,
	}
	return nil
}

func (b *Briefcase) readSSHCertificateValidBefore(certificate string) (uint64, error) {
	certificateBytes, err := ioutil.ReadFile(certificate)
	if err != nil {
		return 0, fmt.Errorf("could not read certificate file %q: %w", certificate, err)
	}

	// ParseAuthorizedKeys parses a public key from an authorized_keys file used in OpenSSH
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certificateBytes)
	if err != nil {
		return 0, err
	}
	// pk.Marshal() Marshal returns the serialized key data in SSH wire format, with the name prefix
	// ssh.ParsePublicKey is used to unmarshal the returned data
	cert, err := ssh.ParsePublicKey(pk.Marshal())
	if err != nil {
		return 0, err
	}

	sshCert, ok := cert.(*ssh.Certificate)
	if !ok {
		return 0, fmt.Errorf("could not parse certificate %q", certificate)
	}

	return sshCert.ValidBefore, nil
}
