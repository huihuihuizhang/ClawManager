//go:build !linux

package main

import (
	"clawreef/internal/systembackup/quiesce"
	"context"
)

func configureLonghornMaterials(context.Context, *quiesce.SharedRuntimeNodeHandler, string, string) error {
	return quiesce.ErrNodeObservation
}
