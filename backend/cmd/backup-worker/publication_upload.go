package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"runtime"

	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupexecution"
)

func runPublicationUpload(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("publish-upload-only", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := flags.String("request", "", "immutable public publication request")
	requestSHA := flags.String("request-sha256", "", "original Job spec request byte hash")
	ca := flags.String("ca", "", "pinned target CA")
	credential := flags.String("credential", "", "separate upload-only credential")
	input := flags.String("input", "", "read-only encrypted input root")
	result := flags.String("result", "", "original Job result root")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *request == "" || len(*requestSHA) != 64 || *ca == "" || *credential == "" || *input == "" || *result == "" {
		return worker.ErrRequest
	}
	if runtime.GOOS != "linux" {
		return worker.ErrNotReady
	}
	raw, err := readPublicationUploadRequest(*request, *requestSHA)
	if err != nil {
		return err
	}
	source, err := os.OpenRoot(*input)
	if err != nil {
		return worker.ErrRequest
	}
	defer source.Close()
	destination, err := os.OpenRoot(*result)
	if err != nil {
		return worker.ErrRequest
	}
	defer destination.Close()
	observed, err := systembackupexecution.RunPublicationUploadOnly(ctx, raw, *ca, *credential, source, destination)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(observed)
}

func readPublicationUploadRequest(path, pin string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, worker.ErrRequest
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return nil, worker.ErrRequest
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != pin {
		return nil, worker.ErrRequest
	}
	return raw, nil
}
