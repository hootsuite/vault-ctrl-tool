package e2e

import (
	"encoding/json"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	mtrics "github.com/hootsuite/vault-ctrl-tool/v2/metrics"
	"github.com/hootsuite/vault-ctrl-tool/v2/syncer"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	mock_vaultclient "github.com/hootsuite/vault-ctrl-tool/v2/vaultclient/mocks"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"os"
	"path"
	"testing"
)

func Secret(secretJSON string) *api.Secret {
	var secret api.Secret
	if err := json.Unmarshal([]byte(secretJSON), &secret); err != nil {
		panic(fmt.Sprintf("could not parse JSON. JSON=%q Error=%v", secretJSON, err))
	}
	return &secret
}

// vaultTokenJSON has a valid token that is not going to expire any time soon. It includes an accessor, id, and username
// that must not change.
// language=JSON
const vaultTokenJSON = `{
  "request_id": "7dbcff81-3182-c523-8c50-3be49a578d25",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "unit-test-accessor",
    "creation_time": 1604433628,
    "creation_ttl": 32400,
    "display_name": "unit-test-token",
    "entity_id": "07ef9c85-9f14-1272-eb56-92b7bfd21500",
    "expire_time": "2040-11-03T21:00:28.797810827-08:00",
    "explicit_max_ttl": 0,
    "id": "unit-test-token",
    "issue_time": "2020-11-03T12:00:28.797823501-08:00",
    "meta": {
      "username": "unit.tests"
    },
    "num_uses": 0,
    "orphan": true,
    "path": "auth/fake",
    "policies": [
      "default"
    ],
    "renewable": true,
    "ttl": 32387,
    "type": "service"
  },
  "warnings": null
}`

// exampleSecretJSON is a non-destroyed secret with two bits of data, and a version of 3.
// language=JSON
const exampleSecretJSON = `{
  "request_id": "8c472fc1-f389-d0c8-fec0-83d9a9930a40",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "bar": "bbbb",
      "foo": "aaaa"
    },
    "metadata": {
      "created_time": "2019-10-02T22:42:10.724886003Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 3
    }
  },
  "warnings": null
}`

// exampleSecretFreshV4JSON is just like exampleSecretV4JSON, except the created_time is a specific
// value to test against.
// language=JSON
const exampleSecretFreshV4JSON = `{
  "request_id": "8c472fc1-f389-d0c8-fec0-83d9a9930a40",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "bar": "bbbb2",
      "foo": "aaaa2"
    },
    "metadata": {
      "created_time": "2019-10-02T22:52:10.724886003Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 4
    }
  },
  "warnings": null
}`

// exampleSecretV4JSON is just like exampleSecretJSON except the version has been incremented
// and the values of the secrets are different. The created_time is 31s later than exampleSecretJSON.
// language=JSON
const exampleSecretV4JSON = `{
  "request_id": "8c472fc1-f389-d0c8-fec0-83d9a9930a40",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "bar": "bbbb2",
      "foo": "aaaa2"
    },
    "metadata": {
      "created_time": "2019-10-02T22:42:41.724886003Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 4
    }
  },
  "warnings": null
}`

// exampleBase64SecretJSON returns a secret with a field "foo64" whose value was written into
// vaule already base64 encoded.
const exampleBase64SecretJSON = `{
  "request_id": "8c472fc1-f389-d0c8-fec0-83d9a9930a40",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "foo64": "SGVsbG8gSG9vdHN1aXRl"
    },
    "metadata": {
      "created_time": "2019-10-02T22:42:41.724886003Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 4
    }
  },
  "warnings": null
}`

type SyncFixture struct {
	log         zerolog.Logger
	workDir     string
	ctrl        *gomock.Controller
	vaultClient *mock_vaultclient.MockVaultClient
	cfg         *config.ControlToolConfig
	metrics     *mtrics.Metrics
	cliFlags    *util.CliFlags
	bcase       *briefcase.Briefcase
	syncer      *syncer.Syncer
}

func setupSync(t *testing.T, configBody string, cliArgs []string) *SyncFixture {
	return setupSyncWithDir(t, configBody, cliArgs, t.TempDir())
}

// setupSyncWithDir lets you share the briefcase from one run with another run,
// good for doing an --init run, then a --sidecar --one-shot run.
func setupSyncWithDir(t *testing.T, configBody string, cliArgs []string, workDir string) *SyncFixture {

	ctrl := gomock.NewController(t)

	log := zlog.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.DebugLevel)

	cfg, err := config.ReadConfig(log, []byte(configBody), workDir, workDir)

	if err != nil {
		t.Fatal(err)
	}

	vaultClient := mock_vaultclient.NewMockVaultClient(ctrl)
	vaultClient.EXPECT().Address().Return("unit-tests").AnyTimes()

	metrics := mtrics.NewMetrics()

	var bcase *briefcase.Briefcase

	bcase, err = briefcase.LoadBriefcase(path.Join(workDir, "briefcase"), metrics)
	if err != nil {
		bcase = briefcase.NewBriefcase(metrics)
	}

	var args []string

	args = append(args, cliArgs...)
	args = append(args, "--output-prefix", workDir,
		"--input-prefix", workDir,
		"--leases-file", path.Join(workDir, "briefcase"))

	cliFlags, err := util.ProcessFlags(args)

	if err != nil {
		t.Fatal(err)
	}

	s := syncer.NewSyncer(log, cfg, vaultClient, bcase, metrics)

	return &SyncFixture{
		log:         log,
		workDir:     workDir,
		ctrl:        ctrl,
		vaultClient: vaultClient,
		cfg:         cfg,
		metrics:     metrics,
		cliFlags:    cliFlags,
		bcase:       bcase,
		syncer:      s,
	}
}
