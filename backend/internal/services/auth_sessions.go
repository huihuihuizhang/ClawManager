package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/repository"
	"clawreef/internal/systembackupsecurity"
)

// WithSystemBackupSessions is enabled only by an explicitly configured runtime.
// A recorder failure prevents tokens from being returned to the caller.
func WithSystemBackupSessions(recorder systembackupsecurity.LoginSessionRecorder) AuthServiceOption {
	return func(s *authService) { s.backupSessions = recorder }
}

func loginState(user *models.User) repository.LoginState {
	var external *string
	if user.ExternalID != nil {
		v := *user.ExternalID
		external = &v
	}
	return repository.LoginState{UserID: user.ID, PasswordHash: user.PasswordHash, AuthProvider: user.AuthProvider, ExpectedRole: user.Role, Role: user.Role, ExternalID: external, At: time.Now()}
}

func (s *authService) updateLoginState(user *models.User, state repository.LoginState) error {
	state.Role = user.Role
	if repo, ok := s.userRepo.(repository.LoginStateRepository); ok {
		return repo.UpdateLoginState(state)
	}
	// Legacy embedders retain their old behavior only while the session hook is
	// disabled. A hook may not attest a full-row write of a stale user snapshot.
	if s.backupSessions != nil {
		return systembackupsecurity.ErrLoginSessionUnavailable
	}
	return s.userRepo.Update(user)
}

func (s *authService) issueSessionTokens(ctx context.Context, user *models.User, previousRefresh string) (*TokenPair, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pair, err := s.generateTokens(user.ID)
	if err != nil {
		return nil, errors.New("token generation unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.backupSessions != nil {
		digest := sha256.Sum256([]byte(user.PasswordHash))
		recordCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err = s.backupSessions.RecordPair(recordCtx, systembackupsecurity.LoginSessionPair{UserID: int64(user.ID), CredentialSHA256: hex.EncodeToString(digest[:]), AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken, PreviousRefreshToken: previousRefresh})
		if err != nil {
			if errors.Is(err, systembackupsecurity.ErrLoginSessionRejected) {
				return nil, systembackupsecurity.ErrLoginSessionRejected
			}
			return nil, systembackupsecurity.ErrLoginSessionUnavailable
		}
		if recordCtx.Err() != nil {
			return nil, systembackupsecurity.ErrLoginSessionUnavailable
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return pair, nil
}
