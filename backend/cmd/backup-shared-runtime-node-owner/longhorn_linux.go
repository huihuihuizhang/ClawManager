//go:build linux

package main

import (
	"context"
	"time"

	"clawreef/internal/systembackup/quiesce"
)

func configureLonghornMaterials(ctx context.Context, h *quiesce.SharedRuntimeNodeHandler, file, digest string) error {
	if file == "" && digest == "" {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return h.ConfigureLonghornExt4Materials(bounded, file, digest)
}
