package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"os"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// These locators come only from trusted deployment environment, independently
// installed beside the actual original v1 file before controller activation.
// No request/task/projection chooses the file, digest or issuer. The metadata
// signature supplies oldGrantSHA; the original core supplies its trusted key.
const originalForwardFileEnvironment = "SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_FILE"
const originalForwardSHAEnvironment = "SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_SHA256"

// For callers without a retained view. Original task/native checks remain the
// caller's responsibility. A same-view caller must use the method below.
func (s *DeploymentService) checkOriginalForwardConfiguration(ctx context.Context, oldGrantSHA, oldConfigSHA string, currentVersion uint64, currentSHA string) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Gate.Authority.DB == nil {
		return c.ErrExecutionAuthority
	}
	view, err := s.Runtime.Owner.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return c.ErrExecutionAuthority
	}
	defer view.Rollback()
	if s.checkOriginalForwardConfigurationInView(ctx, view, oldGrantSHA, oldConfigSHA, currentVersion, currentSHA) != nil || view.Rollback() != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}

func (s *DeploymentService) checkOriginalForwardConfigurationInView(ctx context.Context, view reg.SQLReadView, oldGrantSHA, oldConfigSHA string, currentVersion uint64, currentSHA string) error {
	if s == nil || ctx == nil || ctx.Err() != nil || view == nil || !s.ForwardEnabled || s.Forward == nil || !formalCandidateDigest(oldGrantSHA) || !formalCandidateDigest(oldConfigSHA) || !formalCandidateDigest(currentSHA) || s.publicationBinding() != nil {
		return c.ErrExecutionAuthority
	}
	currentIdentity := s.Forward
	public, err := base64.StdEncoding.Strict().DecodeString(s.Config.ForwardGrant.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || currentIdentity.CheckDeploymentInViewWithIssuer(ctx, view, ed25519.PublicKey(public)) != nil {
		return c.ErrExecutionAuthority
	}
	current := currentIdentity.DeploymentBinding()
	if current.ConfigVersion != currentVersion || current.ConfigSHA256 != currentSHA {
		return c.ErrExecutionAuthority
	}
	file, selectedSHA := os.Getenv(originalForwardFileEnvironment), os.Getenv(originalForwardSHAEnvironment)
	if file == "" || selectedSHA != oldGrantSHA {
		return c.ErrExecutionAuthority
	}
	if _, err := pinnedDeploymentFile(file, oldGrantSHA, 65536); err != nil {
		return c.ErrExecutionAuthority
	}
	original, err := c.NewPinnedExecutionIdentity(file, oldGrantSHA, s.Config.KeyDirectory, ed25519.PublicKey(public))
	if err != nil || original.CheckDeploymentInViewWithIssuer(ctx, view, ed25519.PublicKey(public)) != nil {
		return c.ErrExecutionAuthority
	}
	old := original.DeploymentBinding()
	if old.ConfigSHA256 != oldConfigSHA {
		return c.ErrExecutionAuthority
	}
	if oldGrantSHA == currentIdentity.GrantSHA256() {
		if !reflect.DeepEqual(old, current) || oldConfigSHA != currentSHA {
			return c.ErrExecutionAuthority
		}
	} else {
		if old.ConfigVersion != 1 || currentVersion != 2 || oldConfigSHA == currentSHA {
			return c.ErrExecutionAuthority
		}
		expected := old
		expected.ConfigVersion, expected.ConfigSHA256 = currentVersion, currentSHA
		if !reflect.DeepEqual(expected, current) {
			return c.ErrExecutionAuthority
		}
		proof, err := sec.ReadOriginalEnabledOnlyLineage(ctx, view, s.Config.InstallationID, oldConfigSHA, currentVersion, currentSHA)
		if err != nil || !proof.Matches(s.Config.InstallationID, oldConfigSHA, currentVersion, currentSHA) {
			return c.ErrExecutionAuthority
		}
		authorizedSHA, err := proof.AuthorizationConfigSHA256(ctx, view)
		if err != nil || authorizedSHA != oldConfigSHA {
			return c.ErrExecutionAuthority
		}
	}
	// Repeat original/current file/key/time checks after the actual SQL proof;
	// do not retain a lineage or transfer it to another context/transaction.
	if s.Forward != currentIdentity || s.publicationBinding() != nil || original.CheckDeploymentInViewWithIssuer(ctx, view, ed25519.PublicKey(public)) != nil || currentIdentity.CheckDeploymentInViewWithIssuer(ctx, view, ed25519.PublicKey(public)) != nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}
