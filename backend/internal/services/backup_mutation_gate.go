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

// Keep the permit's cancellation signal attached to detached worker children.
// Release remains the worker's responsibility after its cleanup has joined.
func enterBackupMutationContext(ctx context.Context, g BackupMutationGate, name string) (context.Context, func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		return ctx, nil, context.Canceled
	}
	if g == nil {
		return mutation.EnterContext(ctx, name)
	}
	if contextual, ok := g.(mutation.ContextGate); ok {
		child, release, err := contextual.EnterContext(ctx, name)
		if err == nil && (child == nil || release == nil) {
			capabilityErr := errors.New("backup mutation context capability missing")
			if release != nil {
				capabilityErr = errors.Join(capabilityErr, release())
			}
			return ctx, nil, capabilityErr
		}
		return child, release, err
	}
	release, err := enterBackupMutation(ctx, g, name)
	return ctx, release, err
}
