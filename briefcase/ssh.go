package briefcase

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"golang.org/x/crypto/ssh"
)

var neverExpires = time.Unix(0, 0)

func (b *Briefcase) ShouldRefreshSSHCertificate(sshCertConfig config.SSHCertificateType, expiresBefore time.Time) bool {
	entry, ok := b.SSHCertificates[sshCertConfig.OutputPath]
	if !ok {
		return true
	}

	b.log.Debug().Time("expiry", entry.Expiry).Str("outputPath", sshCertConfig.OutputPath).Msg("determined expiry of ssh certificate")
	return entry.Expiry.Before(expiresBefore) || entry.Expiry == neverExpires
}

func (b *Briefcase) EnrollSSHCertificate(sshCertConfig config.SSHCertificateType) error {

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
		Expiry: validBeforeTime,
		Cfg:    sshCertConfig,
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
