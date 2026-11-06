package main

import (
	"context"
	"encoding/json"
	"io"

	"clawreef/internal/systembackupexecution"
)

func verifyPublicationV2(ctx context.Context, path, origin, backup string, maxBytes int64, out io.Writer) error {
	var inputs systembackupexecution.PublicationReadbackInputs
	if err := decodeFile(path, &inputs); err != nil {
		return err
	}
	result, err := systembackupexecution.VerifyPublicationReadback(ctx, inputs, origin, backup, maxBytes)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
