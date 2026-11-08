//go:build !linux

package main

import (
	"clawreef/internal/systembackup/quiesce"
	"context"
)

func keepLonghornAttachment(context.Context, string) error { return quiesce.ErrNodeObservation }
