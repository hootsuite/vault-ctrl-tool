package leases

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/util"

	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

// Leases is a serialized file that contains all the information needed for the tool, running in sidecar mode,
// to keep all the associated leases, secrets, etc refreshed.
type Leases struct {
	AuthTokenLease      LeasedAuthToken       `json:"auth"`
	SecretLeases        []LeasedSecret        `json:"secrets"`
	SSHCertificates     []cfg.SSHType         `json:"ssh"`
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
	AWSCredential cfg.AWSType `json:"role"`
	Expiry        time.Time   `json:"expiry"`
}

// Current contains all the runtime data needed for the tool to manage leases in sidecar mode.
var Current Leases

var ignoreNonRenewableAuth bool

func EnrollFiles(files []string) {
	Current.ManagedFiles = append(Current.ManagedFiles, files...)
}

func EnrollSSH(sshConfig cfg.SSHType) {
	jww.DEBUG.Printf("Enrolling SSH keys in %q into lease.", sshConfig.OutputPath)
	Current.SSHCertificates = append(Current.SSHCertificates, sshConfig)
}

func EnrollAWS(awsCredential *api.Secret, awsConfig cfg.AWSType) {
	jww.DEBUG.Printf("Enrolling AWS credentials for %s into lease.", awsConfig.VaultRole)
	expiry := time.Now().Add(time.Second * time.Duration(awsCredential.LeaseDuration))
	Current.AWSCredentialLeases = append(Current.AWSCredentialLeases, LeasedAWSCredential{AWSCredential: awsConfig, Expiry: expiry})
}

func EnrollAuthToken(authToken *api.Secret) {

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
		if ignoreNonRenewableAuth {
			jww.WARN.Printf("Ignoring that the authentication token has a TTL of %d but is not renewable.", ttl)
			return
		}
		jww.FATAL.Fatalf("Authentication token has a non-infinity TTL (%d), but is not renewable.", ttl)
	}

	expiry := time.Now().Add(ttl)
	expires := ttl != 0
	Current.AuthTokenLease = LeasedAuthToken{Token: token, ExpiresAt: expiry, CanExpire: expires}

}

func WriteFile() {
	jww.DEBUG.Printf("Writing leases file %q", util.Flags.LeasesFile)
	bytes, err := json.Marshal(Current)

	if err != nil {
		jww.FATAL.Fatalf("Unable to serialize leases file: %v", err)
	}

	// Create interim directories to lease, just in case.

	util.MakeDirsForFile(util.Flags.LeasesFile)

	err = ioutil.WriteFile(util.Flags.LeasesFile, bytes, 0600)
	if err != nil {
		jww.FATAL.Fatalf("Failed to write leases file %q: %v", util.Flags.LeasesFile, err)
	}
}

func ReadFile() {
	jww.INFO.Printf("Reading leases file %q", util.Flags.LeasesFile)
	bytes, err := ioutil.ReadFile(util.Flags.LeasesFile)
	if err != nil {
		jww.FATAL.Fatalf("Failed to read leases file %q: %v", util.Flags.LeasesFile, err)
	}

	err = json.Unmarshal(bytes, &Current)
	if err != nil {
		jww.FATAL.Fatalf("Failed to unmarshal leases file %q: %v", util.Flags.LeasesFile, err)
	}
}

func SetIgnoreNonRenewableAuth(ignore *bool) {
	if ignore != nil {
		ignoreNonRenewableAuth = *ignore
	} else {
		ignoreNonRenewableAuth = false
	}
}
