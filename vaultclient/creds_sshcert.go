package vaultclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hootsuite/vault-ctrl-tool/v2/util"

	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

// SSHPrivateKey is the name of the output file with the the SSH private key (think: ssh -i id_rsa ....)
const SSHPrivateKey = "id_rsa"

// SSHPublicKey is the corresponding public key, used for signing
const SSHPublicKey = "id_rsa.pub"

func (vc *wrappedVaultClient) CreateSSHCertificate(ssh config.SSHCertificateType) error {

	log := vc.log.With().Str("vaultRole", ssh.VaultRole).Logger()

	privateKeyFilename := filepath.Join(ssh.OutputPath, SSHPrivateKey)
	publicKeyFilename := filepath.Join(ssh.OutputPath, SSHPublicKey)

	// I'd use util.MustMakeDirAllForFile, but I want to set the directory permission
	if err := os.MkdirAll(ssh.OutputPath, 0700); err != nil {
		return fmt.Errorf("could not make directory path %q: %w", ssh.OutputPath, err)
	}

	log.Info().Str("privateKey", privateKeyFilename).Str("publicKey", publicKeyFilename).Msg("generating SSH keypair")

	if err := vc.generateKeyPair(privateKeyFilename, publicKeyFilename); err != nil {
		return fmt.Errorf("failed to generate SSH keys: %w", err)
	}
	if err := vc.signKey(log, ssh.OutputPath, ssh.VaultMount, ssh.VaultRole); err != nil {
		return fmt.Errorf("failed to sign SSH key: %w", err)
	}

	return nil
}

func (vc *wrappedVaultClient) generateKeyPair(privateKeyFilename, publicKeyFilename string) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("could not generate RSA key: %w", err)
	}

	// Write a SSH private key..
	privateKeyFile, err := os.OpenFile(privateKeyFilename, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("could not create private key file %q: %w", privateKeyFilename, err)
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("could not PEM encode private key %q: %w", privateKeyFilename, err)
	}

	// Write SSH public key..
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("could not create public SSH key %q: %w", publicKeyFilename, err)
	}

	err = ioutil.WriteFile(publicKeyFilename, ssh.MarshalAuthorizedKey(pub), 0600)
	if err != nil {
		return fmt.Errorf("could not write public SSH key %q: %w", publicKeyFilename, err)

	}
	return nil

}

func (vc *wrappedVaultClient) signKey(log zerolog.Logger, outputPath string, vaultMount string, vaultRole string) error {
	log.Debug().Str("outputPath", outputPath).Str("vaultMount", vaultMount).Msg("signing SSH keys")

	vaultSSH := vc.Delegate().SSHWithMountPoint(vaultMount)

	publicKeyFilename := filepath.Join(outputPath, SSHPublicKey)
	certificateFilename := filepath.Join(outputPath, util.SSHCertificate)

	publicKeyBytes, err := ioutil.ReadFile(publicKeyFilename)
	if err != nil {
		return fmt.Errorf("could not read SSH public key %q: %w", publicKeyFilename, err)
	}

	resp, err := vaultSSH.SignKey(vaultRole, map[string]interface{}{
		"public_key": string(publicKeyBytes),
	})
	if err != nil {
		return fmt.Errorf("failed to sign SSH key: %w", err)
	}

	signedKey := resp.Data["signed_key"]
	if signedKey == nil {
		return fmt.Errorf("did not receive a signed_key from Vault at %q when signing key at %q with \"%s/sign/%s\"",
			vc.Delegate().Address(), outputPath, vaultMount, vaultRole)
	}
	signedKeyString, ok := resp.Data["signed_key"].(string)
	if !ok {
		return fmt.Errorf("could not convert signed_key to string")
	}

	log.Info().Str("certificateFile", certificateFilename).Msg("writing SSH certificate")

	if err := ioutil.WriteFile(certificateFilename, []byte(signedKeyString), 0600); err != nil {
		return fmt.Errorf("could not write certificate file: %w", err)
	}

	return nil
}
