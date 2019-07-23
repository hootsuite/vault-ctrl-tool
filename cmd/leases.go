package main

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

// Leases is a serialized file that contains all the information needed for the tool, running in sidecar mode,
// to keep all the associated leases, secrets, etc refreshed.
type Leases struct {
	AuthTokenLease      LeasedAuthToken       `json:"auth"`
	SecretLeases        []LeasedSecret        `json:"secrets"`
	SSHCertificates     []SSHType             `json:"ssh"`
	AWSCredentialLeases []LeasedAWSCredential `json:"aws"`
	ManagedFiles        []string              `json:"files"`
}

type LeasedAuthToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiry"`
	CanExpire bool      `json:"expires"`
}

type LeasedSecret struct {
	LeaseID string    `json:"lease"`
	Expiry  time.Time `json:"expiry"`
}

type LeasedAWSCredential struct {
	AWSCredential AWSType   `json:"role"`
	Expiry        time.Time `json:"expiry"`
}

// Contains all the runtime data needed for the tool to manage leases in sidecar mode.
var leases Leases

func enrollFilesInLease(files []string) {
	leases.ManagedFiles = append(leases.ManagedFiles, files...)
}

func enrollSSHInLease(sshConfig SSHType) {
	jww.DEBUG.Printf("Enrolling SSH keys in %q into lease.", sshConfig.OutputPath)
	leases.SSHCertificates = append(leases.SSHCertificates, sshConfig)
}

func enrollAWSInLease(awsCredential *api.Secret, awsConfig AWSType) {
	jww.DEBUG.Printf("Enrolling AWS credentials for %s into lease.", awsConfig.VaultRole)
	expiry := time.Now().Add(time.Second * time.Duration(awsCredential.LeaseDuration))
	leases.AWSCredentialLeases = append(leases.AWSCredentialLeases, LeasedAWSCredential{AWSCredential: awsConfig, Expiry: expiry})
}

func enrollAuthTokenInLease(authToken *api.Secret) {

	token, err := authToken.TokenID()
	if err != nil {
		jww.FATAL.Fatalf("Failed to obtain token for authentication credentials: %v", err)
	}

	renewable, err := authToken.TokenIsRenewable()
	if err != nil {
		jww.FATAL.Fatalf("Could not determine if token is renewable: %v", err)
	}
	ttl, err := authToken.TokenTTL()
	if err != nil {
		jww.FATAL.Fatalf("Could not fetch token TTL: %v", err)
	}

	jww.DEBUG.Printf("auth token renewable=%v ttl=%v", renewable, ttl)

	if !renewable && ttl != 0 {
		if *ignoreNonRenewableAuth {
			jww.WARN.Printf("Ignoring that the authentication token has a TTL of %d but is not renewable.", ttl)
			return
		}
		jww.FATAL.Fatalf("Authentication token has a non-infinity TTL (%d), but is not renewable.", ttl)
	}

	expiry := time.Now().Add(ttl)
	expires := ttl != 0
	leases.AuthTokenLease = LeasedAuthToken{Token: token, ExpiresAt: expiry, CanExpire: expires}

}

func enrollSecretInLease(secret *api.Secret) {

	metadata, err := secret.TokenMetadata()
	if err != nil {
		jww.FATAL.Fatalf("Could not fetch metadata for secret: %v", err)
	}

	jww.INFO.Printf("LeaseID: %v, LeaseDuration: %d, Renewable: %v, Metadata: %v", secret.LeaseID, secret.LeaseDuration, secret.Renewable,
		metadata)

}

func writeLeaseFile() {
	jww.DEBUG.Printf("Writing leases file %q", *leasesFile)
	bytes, err := json.Marshal(leases)

	if err != nil {
		jww.FATAL.Fatalf("Unable to serialize leases file: %v", err)
	}

	// Create interim directories to lease, just in case.

	makeDirsForFile(*leasesFile)

	err = ioutil.WriteFile(*leasesFile, bytes, 0600)
	if err != nil {
		jww.FATAL.Fatalf("Failed to write leases file %q: %v", *leasesFile, err)
	}
}

func readLeaseFile() {
	jww.INFO.Printf("Reading leases file %q", *leasesFile)
	bytes, err := ioutil.ReadFile(*leasesFile)
	if err != nil {
		jww.FATAL.Fatalf("Failed to read leases file %q: %v", *leasesFile, err)
	}

	err = json.Unmarshal(bytes, &leases)
	if err != nil {
		jww.FATAL.Fatalf("Failed to unmarshal leases file %q: %v", *leasesFile, err)
	}
}
