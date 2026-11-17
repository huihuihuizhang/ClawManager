//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

func runLonghornPreColdHelper(context.Context, []byte, []byte, string, io.Writer) ([]byte, error) {
	return nil, errors.New("Longhorn native continuation requires Linux")
}
