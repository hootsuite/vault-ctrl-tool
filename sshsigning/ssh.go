package sshsigning

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

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/ssh"
)

// SSHPrivateKey is the name of the output file with the the SSH private key (think: ssh -i id_rsa ....)
const SSHPrivateKey = "id_rsa"

// SSHPublicKey is the corresponding public key, used for signing
const SSHPublicKey = "id_rsa.pub"

// SSHCertificate is public key, signed by Vault.
const SSHCertificate = "id_rsa-cert.pub"

func generateKeyPair(outputPath string) error {

	privateKeyFilename := filepath.Join(outputPath, SSHPrivateKey)
	publicKeyFilename := filepath.Join(outputPath, SSHPublicKey)

	jww.INFO.Printf("Writing ssh keypair to %q and %q", privateKeyFilename, publicKeyFilename)

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return errwrap.Wrapf("could not generate RSA key: {{err}}", err)
	}

	if err := os.MkdirAll(outputPath, 0700); err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not make directory path %q: {{err}}", outputPath), err)
	}

	// Write a SSH private key..
	privateKeyFile, err := os.OpenFile(privateKeyFilename, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0600)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not create private key file %q: {{err}}", privateKeyFilename), err)
	}
	defer privateKeyFile.Close()

	scrubber.AddFile(privateKeyFilename)

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not PEM encode private key %q: {{err}}", privateKeyFilename), err)
	}

	// Write SSH public key..
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not create public SSH key %q: {{err}}", publicKeyFilename), err)
	}

	err = ioutil.WriteFile(publicKeyFilename, ssh.MarshalAuthorizedKey(pub), 0600)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not write public SSH key %q: {{err}}", publicKeyFilename), err)

	}
	scrubber.AddFile(publicKeyFilename)
	return nil

}

func WriteKeys(currentConfig cfg.Config, client *api.Client) error {

	for _, sshConfig := range currentConfig.SSH {
		if err := generateKeyPair(sshConfig.OutputPath); err != nil {
			return errwrap.Wrapf("failed to generate SSH keys: {{err}}", err)
		}
		if err := SignKey(client, sshConfig.OutputPath, sshConfig.VaultMount, sshConfig.VaultRole); err != nil {
			return errwrap.Wrapf("failed to sign SSH key: {{err}}", err)
		}
		leases.EnrollSSH(sshConfig)
	}
	return nil
}

func ReadCertificateValidBefore(certificate string) (uint64, error) {
	certificateBytes, err := ioutil.ReadFile(certificate)
	if err != nil {
		return 0, errwrap.Wrapf(fmt.Sprintf("could not read certificate file %q: {{err}}", certificate), err)
	}

	cert, err := ssh.ParsePublicKey(certificateBytes)
	if err != nil {
		return 0, errwrap.Wrapf(fmt.Sprintf("could not parse ssh certificate %q: {{err}}", certificate), err)
	}
	sshCert, ok := cert.(*ssh.Certificate)
	if !ok {
		return 0, fmt.Errorf("could not parse certificate %q", certificate)
	}

	return sshCert.ValidBefore, nil
}

func SignKey(client *api.Client, outputPath string, vaultMount string, vaultRole string) error {
	jww.DEBUG.Printf("Signing keys in %q with certificate at %q and role %q", outputPath, vaultMount, vaultRole)
	vaultSSH := client.SSHWithMountPoint(vaultMount)

	publicKeyFilename := filepath.Join(outputPath, SSHPublicKey)
	certificateFilename := filepath.Join(outputPath, SSHCertificate)

	publicKeyBytes, err := ioutil.ReadFile(publicKeyFilename)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not read SSH public key %q: {{err}}", publicKeyFilename), err)
	}

	resp, err := vaultSSH.SignKey(vaultRole, map[string]interface{}{
		"public_key": string(publicKeyBytes),
	})
	if err != nil {
		return errwrap.Wrapf("failed to sign SSH key: {{err}}", err)
	}

	signedKey := resp.Data["signed_key"]
	if signedKey == nil {
		return fmt.Errorf("did not receive a signed_key from Vault at %q when signing key at %q with \"%s/sign/%s\"",
			client.Address(), outputPath, vaultMount, vaultRole)
	}
	signedKeyString, ok := resp.Data["signed_key"].(string)
	if !ok {
		return fmt.Errorf("could not convert signed_key to string")
	}

	jww.INFO.Printf("Writing ssh certificate to %q", certificateFilename)
	if err := ioutil.WriteFile(certificateFilename, []byte(signedKeyString), 0600); err != nil {
		return errwrap.Wrapf("could not write certificate file: {{err}}", err)
	}
	scrubber.AddFile(certificateFilename)
	return nil
}
