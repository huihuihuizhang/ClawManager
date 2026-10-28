package services

import (
	"clawreef/internal/systembackup/mutation"
	"context"
	"errors"
)

// Set before Start. Each permit spans all child goroutines and external writes;
// failure to release leaves durable evidence that blocks capture admission.
type BackupMutationGate interface {
	Enter(context.Context, string) (func() error, error)
}

func enterBackupMutation(ctx context.Context, g BackupMutationGate, name string) (func() error, error) {
	if g == nil {
		return mutation.Enter(ctx, name)
	}
	release, err := g.Enter(ctx, name)
	if err == nil && release == nil {
		return nil, errors.New("backup mutation release capability missing")
	}
	return release, err
}
