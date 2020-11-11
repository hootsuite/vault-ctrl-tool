package e2e

import (
	"context"
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/api"
	mtrics "github.com/hootsuite/vault-ctrl-tool/v2/metrics"
	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	testing2 "k8s.io/utils/clock/testing"
	"os"
	"path"
	"testing"
	"time"
)

// TestSyncWithPinnedVersion ensures that when requesting a specific version of a secret in a config file cascades
// that request to Vault.
func TestSyncWithPinnedVersion(t *testing.T) {

	fixture := setupSync(t, `
---
version: 3
secrets:
 - key: example
   path: path/in/vault
   missingOk: false
   mode: 0700
   pinnedVersion: 3
   output: example-output
   lifetime: static
`, []string{
		"--init",
		"--vault-token", "unit-test-token"})

	vaultToken := Secret(vaultTokenJSON)
	fixture.vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(vaultToken, nil).AnyTimes()
	fixture.vaultClient.EXPECT().ServiceSecretPrefix(gomock.Any()).Return("/prefix/")
	fixture.vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	fixture.vaultClient.EXPECT().ReadWithData(gomock.Any(), gomock.Any()).DoAndReturn(
		func(path string, data map[string][]string) (*api.Secret, error) {

			// Expect a request for the absolute secret path of version 3.
			assert.Equal(t, "/prefix/path/in/vault", path)
			assert.Len(t, data, 1)
			assert.Equal(t, []string{"3"}, data["version"])
			response := Secret(exampleSecretJSON)
			return response, nil
		}).Times(1)

	fakeClock := testing2.NewFakeClock(time.Now())
	ctx := clock.Set(context.Background(), fakeClock)
	err := fixture.syncer.PerformSync(ctx, fakeClock.Now().AddDate(1, 0, 0), *fixture.cliFlags)

	assert.NoError(t, err)
	assert.FileExists(t, path.Join(fixture.workDir, "example-output"))
	assert.Equal(t, 1, fixture.metrics.Counter(mtrics.SecretUpdates))
	assert.Equal(t, 0, fixture.metrics.Counter(mtrics.VaultTokenWritten))
}

// TestSyncVersionScope - when a KVv2 secret gets a new version and it is at least 30 seconds old, the
// field associated with the secret must be updated.
func TestSyncVersionScope(t *testing.T) {

	const configBody = `---
version: 3
secrets:
 - key: example
   path: path/in/vault
   missingOk: false
   mode: 0700
   lifetime: version
   fields:
    - name: foo
      output: foo
`

	sharedDir := t.TempDir()

	fixture1 := setupSyncWithDir(t, configBody, []string{"--init",
		"--vault-token", "unit-test-token"}, sharedDir)

	vaultToken := Secret(vaultTokenJSON)
	fixture1.vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(vaultToken, nil).AnyTimes()
	fixture1.vaultClient.EXPECT().ServiceSecretPrefix(gomock.Any()).Return("/prefix/")
	fixture1.vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	fixture1.vaultClient.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(path string) (*api.Secret, error) {
			assert.Equal(t, "/prefix/path/in/vault", path)
			response := Secret(exampleSecretJSON)
			return response, nil
		}).Times(1)

	fakeClock := testing2.NewFakeClock(time.Now())
	ctx := clock.Set(context.Background(), fakeClock)
	err := fixture1.syncer.PerformSync(ctx, fakeClock.Now().AddDate(1, 0, 0), *fixture1.cliFlags)

	assert.NoError(t, err)
	assert.FileExists(t, path.Join(fixture1.workDir, "foo"))

	foobytes, _ := ioutil.ReadFile(path.Join(fixture1.workDir, "foo"))
	assert.Equal(t, "aaaa", string(foobytes))

	assert.Equal(t, 1, fixture1.metrics.Counter(mtrics.SecretUpdates))
	assert.Equal(t, 0, fixture1.metrics.Counter(mtrics.VaultTokenWritten))

	// Now, do this again, except with a new version of the secret

	fixture2 := setupSyncWithDir(t, configBody, []string{"--sidecar", "--one-shot", "--vault-token", "unit-test-token"}, sharedDir)

	fixture2.vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(vaultToken, nil).AnyTimes()
	fixture2.vaultClient.EXPECT().ServiceSecretPrefix(gomock.Any()).Return("/prefix/")
	fixture2.vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	fixture2.vaultClient.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(path string) (*api.Secret, error) {
			assert.Equal(t, "/prefix/path/in/vault", path)
			// return "v4" of the secret
			response := Secret(exampleSecretV4JSON)
			return response, nil
		}).Times(1)

	err = fixture2.syncer.PerformSync(ctx, fakeClock.Now().AddDate(1, 0, 0), *fixture1.cliFlags)

	assert.NoError(t, err)
	assert.FileExists(t, path.Join(fixture2.workDir, "foo"))

	foobytes, _ = ioutil.ReadFile(path.Join(fixture2.workDir, "foo"))

	// Since the secret is quite old, expect the field to be updated.
	assert.Equal(t, "aaaa2", string(foobytes))
	assert.Equal(t, 1, fixture1.metrics.Counter(mtrics.SecretUpdates))
	assert.Equal(t, 0, fixture1.metrics.Counter(mtrics.VaultTokenWritten))

}

// TestSyncVersionScope - when a KVv2 secret gets a new version and it is not 30 seconds old, nothing
// should be updated.
func TestSyncVersionScopeWithFreshSecret(t *testing.T) {

	const configBody = `---
version: 3
secrets:
 - key: example
   path: path/in/vault
   missingOk: false
   mode: 0700
   lifetime: version
   touchfile: test-touchfile
   fields:
    - name: foo
      output: foo
`

	// Step 1: There is nothing in the briefcase, so the field will be written.
	sharedDir := t.TempDir()

	fixture1 := setupSyncWithDir(t, configBody, []string{"--init",
		"--vault-token", "unit-test-token"}, sharedDir)

	vaultToken := Secret(vaultTokenJSON)
	fixture1.vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(vaultToken, nil).AnyTimes()
	fixture1.vaultClient.EXPECT().ServiceSecretPrefix(gomock.Any()).Return("/prefix/")
	fixture1.vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	fixture1.vaultClient.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(path string) (*api.Secret, error) {
			assert.Equal(t, "/prefix/path/in/vault", path)
			response := Secret(exampleSecretJSON)
			return response, nil
		}).Times(1)

	// This is 10 seconds after the time in exampleSecretFreshV4JSON
	fakeClock := testing2.NewFakeClock(time.Date(2019, 10, 2, 22, 52, 20, 0, time.UTC))

	ctx := clock.Set(context.Background(), fakeClock)
	err := fixture1.syncer.PerformSync(ctx, fakeClock.Now().AddDate(1, 0, 0), *fixture1.cliFlags)

	assert.NoError(t, err)
	assert.FileExists(t, path.Join(fixture1.workDir, "foo"))

	foobytes, _ := ioutil.ReadFile(path.Join(fixture1.workDir, "foo"))
	assert.Equal(t, "aaaa", string(foobytes))

	assert.Equal(t, 1, fixture1.metrics.Counter(mtrics.SecretUpdates))
	assert.Equal(t, 0, fixture1.metrics.Counter(mtrics.VaultTokenWritten))

	// Expect the "touchfile" to exist since the fields were written.
	assert.FileExists(t, path.Join(fixture1.workDir, "test-touchfile"))
	assert.NoError(t, os.Remove(path.Join(fixture1.workDir, "test-touchfile")))

	// Now, do this again, except with a new version of the secret in Vault

	fixture2 := setupSyncWithDir(t, configBody, []string{"--sidecar", "--one-shot", "--vault-token", "unit-test-token"}, sharedDir)

	fixture2.vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(vaultToken, nil).AnyTimes()
	fixture2.vaultClient.EXPECT().ServiceSecretPrefix(gomock.Any()).Return("/prefix/")
	fixture2.vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	fixture2.vaultClient.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(path string) (*api.Secret, error) {
			assert.Equal(t, "/prefix/path/in/vault", path)
			// return "v4" of the secret, but with a created_timestamp that isn't old enough.
			response := Secret(exampleSecretFreshV4JSON)
			return response, nil
		}).Times(1)

	err = fixture2.syncer.PerformSync(ctx, fakeClock.Now().AddDate(1, 0, 0), *fixture1.cliFlags)

	assert.NoError(t, err)

	// Expect the touchfile to _not_ exist, since the fields were not updated.
	assert.NoFileExists(t, path.Join(fixture2.workDir, "test-touchfile"))

	assert.FileExists(t, path.Join(fixture2.workDir, "foo"))

	foobytes, _ = ioutil.ReadFile(path.Join(fixture2.workDir, "foo"))
	assert.Equal(t, "aaaa", string(foobytes))

	assert.Equal(t, 0, fixture2.metrics.Counter(mtrics.SecretUpdates))
	assert.Equal(t, 0, fixture2.metrics.Counter(mtrics.VaultTokenWritten))
}

// TestSyncWithEmptyConfig ensures that when a configuration file is empty, the service still runs, but doesn't
// actually do anything.
func TestSyncWithEmptyConfig(t *testing.T) {

	fixture := setupSync(t, `
---
version: 3
`, []string{"--vault-token", "unit-test-token",
		"--init"})

	fixture.vaultClient.EXPECT().Address().Return("unit-tests").AnyTimes()

	var secret api.Secret
	if err := json.Unmarshal([]byte(vaultTokenJSON), &secret); err != nil {
		t.Fatal(err)
	}

	fixture.vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(&secret, nil).AnyTimes()
	fixture.vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	fakeClock := testing2.NewFakeClock(time.Now())
	ctx := clock.Set(context.Background(), fakeClock)
	err := fixture.syncer.PerformSync(ctx, fakeClock.Now().AddDate(1, 0, 0), *fixture.cliFlags)

	assert.NoError(t, err)
	assert.Equal(t, 1, fixture.metrics.Counter(mtrics.BriefcaseReset))
	assert.Equal(t, 0, fixture.metrics.Counter(mtrics.VaultTokenWritten))
	assert.Equal(t, 0, fixture.metrics.Counter(mtrics.VaultTokenRefreshed))
	assert.Equal(t, 0, fixture.metrics.Counter(mtrics.SecretUpdates))
}

// TestBase64Field
func TestBase64Field(t *testing.T) {

	fixture := setupSync(t, `
---
version: 3
secrets:
 - key: example
   path: path/in/vault
   missingOk: false
   mode: 0700
   lifetime: static
   fields:
     - name: foo64
       output: foo-output.txt
       encoding: base64
`, []string{"--vault-token", "unit-test-token",
		"--init"})

	fixture.vaultClient.EXPECT().Address().Return("unit-tests").AnyTimes()

	var secret api.Secret
	if err := json.Unmarshal([]byte(vaultTokenJSON), &secret); err != nil {
		t.Fatal(err)
	}

	fixture.vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(&secret, nil).AnyTimes()
	fixture.vaultClient.EXPECT().ServiceSecretPrefix(gomock.Any()).Return("/prefix/")
	fixture.vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	fixture.vaultClient.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(path string) (*api.Secret, error) {
			assert.Equal(t, "/prefix/path/in/vault", path)
			response := Secret(exampleBase64SecretJSON)
			return response, nil
		}).Times(1)

	fakeClock := testing2.NewFakeClock(time.Now())
	ctx := clock.Set(context.Background(), fakeClock)
	err := fixture.syncer.PerformSync(ctx, fakeClock.Now().AddDate(1, 0, 0), *fixture.cliFlags)

	assert.NoError(t, err)

	outputFile := path.Join(fixture.workDir, "foo-output.txt")
	assert.FileExists(t, outputFile)

	foo64Bytes, err := ioutil.ReadFile(outputFile)
	assert.Equal(t, "Hello Hootsuite", string(foo64Bytes))

	assert.Equal(t, 1, fixture.metrics.Counter(mtrics.BriefcaseReset))
	assert.Equal(t, 1, fixture.metrics.Counter(mtrics.SecretUpdates))
	assert.Equal(t, 0, fixture.metrics.Counter(mtrics.VaultTokenWritten))
	assert.Equal(t, 0, fixture.metrics.Counter(mtrics.VaultTokenRefreshed))
}
