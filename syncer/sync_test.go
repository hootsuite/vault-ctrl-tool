package syncer

import (
	"context"
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	mock_vaultclient "github.com/hootsuite/vault-ctrl-tool/v2/vaultclient/mocks"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
	"time"
)

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
    "expire_time": "2020-11-03T21:00:28.797810827-08:00",
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

func TestSyncWithEmptyConfig(t *testing.T) {

	ctrl := gomock.NewController(t)

	cfg := &config.ControlToolConfig{}
	vaultClient := mock_vaultclient.NewMockVaultClient(ctrl)
	vaultClient.EXPECT().Address().Return("unit-tests").AnyTimes()

	var secret api.Secret
	if err := json.Unmarshal([]byte(vaultTokenJSON), &secret); err != nil {
		t.Fatal(err)
	}

	vaultClient.EXPECT().VerifyVaultToken(gomock.Any()).Return(&secret, nil).AnyTimes()
	vaultClient.EXPECT().SetToken(gomock.Any()).AnyTimes()

	bcase := briefcase.NewBriefcase()

	workDir := t.TempDir()
	cliFlags, err := util.ProcessFlags([]string{
		"--init",
		"--output-prefix", workDir,
		"--input-prefix", workDir,
		"--vault-token", "unit-test-token",
		"--leases-file", path.Join(workDir, "briefcase"),
	})

	if err != nil {
		t.Fatal(err)
	}

	s := NewSyncer(log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.DebugLevel),
		cfg, vaultClient, bcase)

	err = s.PerformSync(context.TODO(), time.Now().AddDate(1, 0, 0), *cliFlags)

	assert.NoError(t, err)
}
