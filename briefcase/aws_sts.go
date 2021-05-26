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

// AWSCredentialsShouldRefresh checks if a set of AWS credentials should be refreshed.
func (b *Briefcase) AWSCredentialShouldRefreshBefore(awsConfig config.AWSType, refreshBefore time.Time) bool {
	entry, ok := b.AWSCredentialLeases[awsConfig.OutputPath]
	if !ok {
		return true
	}

	return entry.RefreshExpiry != nil && !entry.RefreshExpiry.IsZero() && refreshBefore.After(*entry.RefreshExpiry)
}

// EnrollAWSCredenntial adds or replaces a managed AWS credential to briefcase. IF forceRefreshTTL is not zero then it will associate
// refresh expirty time with the certificate.
func (b *Briefcase) EnrollAWSCredential(ctx context.Context, awsCreds *api.Secret, awsConfig config.AWSType, forceRefreshTTL time.Duration) {
	expiry := clock.Now(ctx).Add(time.Second * time.Duration(awsCreds.LeaseDuration))

	var refreshExpiry *time.Time

	// we only add a refresh if a ttl value was set.
	if forceRefreshTTL > 0 {
		exp := clock.Now(ctx).Add(forceRefreshTTL)
		refreshExpiry = &exp
		if refreshExpiry.After(expiry) {
			b.log.Warn().Msgf("forceRefreshTTL is longer than the expiry of aws credentials")
		}
		b.log.Info().Time("expiry", expiry).Time("refreshTime", exp).Int("TTL", int(forceRefreshTTL.Minutes())).Str("outputPath", awsConfig.OutputPath).
			Msg("enrolling AWS credential")
	} else {
		b.log.Info().Time("expiry", expiry).Str("outputPath", awsConfig.OutputPath).
			Msg("enrolling AWS credential")
		refreshExpiry = nil
	}

	b.AWSCredentialLeases[awsConfig.OutputPath] = leasedAWSCredential{
		AWSCredential: awsConfig,
		Expiry:        expiry,
		RefreshExpiry: refreshExpiry,
	}
}
