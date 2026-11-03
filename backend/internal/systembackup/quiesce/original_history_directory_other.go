//go:build !linux

package quiesce

import (
	"context"
	"os"
)

func openOriginalHistoryDirectoryNative(context.Context, observedPath, string) (*os.File, os.FileInfo, error) {
	return nil, nil, ErrNodeObservation
}
func checkOriginalHistoryDirectoryNative(context.Context, *os.File, os.FileInfo, observedPath, string) error {
	return ErrNodeObservation
}
