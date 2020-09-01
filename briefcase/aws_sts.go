package briefcase

import (
	"context"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
)

// STS credentials have a maximum lifetime enforced by AWS. The current expiry is kept in the briefcase
// and checked to determine if it needs to be refreshed. Services using STS credentials are expected to handle
// credentials expiring underneath them at any time.

func (b *Briefcase) AWSCredentialExpiresBefore(awsConfig config.AWSType, expiresBefore time.Time) bool {
	entry, ok := b.AWSCredentialLeases[awsConfig.OutputPath]
	if !ok {
		return true
	}

	return !entry.Expiry.After(expiresBefore)
}

func (b *Briefcase) EnrollAWSCredential(ctx context.Context, awsCreds *api.Secret, awsConfig config.AWSType) {
	expiry := clock.Now(ctx).Add(time.Second * time.Duration(awsCreds.LeaseDuration))

	b.log.Info().Time("expiry", expiry).Str("outputPath", awsConfig.OutputPath).
		Msg("enrolling AWS credential")
	b.AWSCredentialLeases[awsConfig.OutputPath] = leasedAWSCredential{
		AWSCredential: awsConfig,
		Expiry:        expiry,
	}
}
