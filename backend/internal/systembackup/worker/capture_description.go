package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	cd "clawreef/internal/systembackupcapturedescription"
)

const CaptureDescriptionPullPath = "/capture-description"

func descriptionMatchesCarrier(description cd.Description, i Invocation) bool {
	if i.ProviderKey == nil || i.FormalCapture == nil || len(description.AdministrativeInvocations) != 3 {
		return false
	}
	scope, key := description.Scope, i.ProviderKey.Request.Context
	sha, err := i.Hash()
	return err == nil && scope.InstallationID == key.InstallationID && scope.TaskPublicID == key.BackupPublicID && scope.CaptureContextSHA256 == key.CaptureContextHash && scope.ConfigSHA256 == i.FormalCapture.SourceConfigSHA256 && strconv.FormatUint(scope.AttemptNo, 10) == key.AttemptNo && key.AttemptNo == i.Request.Binding.Attempt && description.AdministrativeInvocations[0].SHA256 == sha
}

func captureDescriptionOperation(operation string) bool { return operation == cd.Operation }

func validCaptureDescriptionRequest(r Request) bool {
	return r.Version == Version && r.Operation == cd.Operation && !r.Deadline.IsZero() && r.CaptureDescription != nil && r.CaptureDescription.Validate() == nil && r.Binding.Path == cd.Part && r.ArtifactName == cd.LogicalCipherName && r.MaxArchiveBytes == r.CaptureDescription.MaxPlaintextBytes && r.MaxCompressedBytes == r.CaptureDescription.MaxPlaintextBytes && r.MaxFiles == 0 && r.MaxFileBytes == 0 && r.PolicyVersion == "" && len(r.Files) == 0 && r.ControlEvidence == nil && r.SourceRedis == nil && r.SkillObjects == nil && r.SkillWorkspace == nil && r.Teams == nil && r.Resources == nil && r.Database == nil && r.RuntimePolicy == nil && r.WorkBuddyIdentity == nil && r.TeamWorkspace == nil
}

// ConfigureCaptureDescription uses only this ORIGINAL Job's existing control
// client and reserved key window. No source DB credential or new permission is
// delivered; the endpoint reads the same task's already observed B records.
func ConfigureCaptureDescription(ctx context.Context, i Invocation, j *CaptureKeyJob, env *FormalCaptureEnvironment) error {
	if env == nil || j == nil || j.original == nil || j.original.client == nil || !validCaptureDescriptionRequest(i.Request) || !validFormalInvocation(i) || j.Recheck(ctx) != nil {
		return ErrNotReady
	}
	sha, err := i.Hash()
	if err != nil || sha != j.original.lease.Identity.InvocationSHA256 {
		return ErrNotReady
	}
	env.SourceValidUntil = j.until
	// The formal runner independently calls Recheck before/after use and
	// recheckDuringUse inside WithDEK. Do not recursively acquire its mutex.
	env.SourceAuthorize = func(ctx context.Context, actual Invocation) error {
		got, err := actual.Hash()
		if ctx == nil || ctx.Err() != nil || err != nil || got != sha || j.original.failed || !time.Now().Before(j.until) {
			return ErrNotReady
		}
		return nil
	}
	env.CaptureDescription = func(ctx context.Context, actual Invocation) ([]byte, error) {
		got, err := actual.Hash()
		if err != nil || got != sha {
			return nil, ErrNotReady
		}
		return j.captureDescriptionSource(ctx)
	}
	return nil
}

func (j *CaptureKeyJob) captureDescriptionSource(ctx context.Context) (result []byte, resultErr error) {
	defer func() {
		if resultErr != nil && j != nil && j.original != nil {
			j.original.failed = true
		}
	}()
	if j == nil || j.original == nil || j.original.client == nil || !validCaptureDescriptionRequest(j.original.invocation.Request) || j.recheckDuringUse(ctx) != nil {
		return nil, ErrNotReady
	}
	a := j.original
	client := a.client
	request := ControlRequest{Invocation: a.invocation, InvocationSHA256: a.lease.Identity.InvocationSHA256, Action: "key-check", Point: a.lease.Nonce}
	if !ValidateControl(request) || client.http == nil || client.tokenFile == "" {
		return nil, ErrNotReady
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, ErrExecution
	}
	defer clear(body)
	endpoint, err := url.Parse(client.endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, ErrExecution
	}
	endpoint.Path, endpoint.RawPath = CaptureDescriptionPullPath, ""
	bounded, cancel := context.WithDeadline(ctx, j.until)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(bounded, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrExecution
	}
	token, err := os.ReadFile(client.tokenFile)
	defer clear(token)
	if err != nil || len(token) < 16 || len(token) > 16384 || strings.ContainsAny(string(token), "\r\n\x00") {
		return nil, ErrExecution
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(token))
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(httpRequest)
	if err != nil {
		return nil, ErrExecution
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || response.Uncompressed {
		return nil, ErrExecution
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, a.invocation.Request.MaxArchiveBytes+1))
	keep := false
	defer func() {
		if !keep {
			clear(raw)
		}
	}()
	if err != nil || int64(len(raw)) > a.invocation.Request.MaxArchiveBytes {
		return nil, ErrExecution
	}
	description, err := cd.Decode(raw, *a.invocation.Request.CaptureDescription)
	if err != nil {
		return nil, ErrExecution
	}
	defer description.Clear()
	if !descriptionMatchesCarrier(description, a.invocation) || j.recheckDuringUse(bounded) != nil || bounded.Err() != nil || !time.Now().Before(j.until) {
		return nil, ErrExecution
	}
	keep = true
	return raw, nil
}

func captureDescription(ctx context.Context, i Invocation, source func(context.Context, Invocation) ([]byte, error), dst io.Writer, check func() error) error {
	if ctx == nil || ctx.Err() != nil || source == nil || dst == nil || check == nil || !validCaptureDescriptionRequest(i.Request) || check() != nil {
		return ErrNotReady
	}
	raw, err := source(ctx, i)
	defer clear(raw)
	if err != nil || int64(len(raw)) > i.Request.MaxArchiveBytes {
		return ErrExecution
	}
	description, err := cd.Decode(raw, *i.Request.CaptureDescription)
	if err != nil {
		return ErrExecution
	}
	defer description.Clear()
	if !descriptionMatchesCarrier(description, i) {
		return ErrExecution
	}
	for offset := 0; offset < len(raw); {
		if ctx.Err() != nil || check() != nil {
			return ErrNotReady
		}
		end := offset + (64 << 10)
		if end > len(raw) {
			end = len(raw)
		}
		n, err := dst.Write(raw[offset:end])
		if err != nil {
			return err
		}
		if n != end-offset {
			return io.ErrShortWrite
		}
		offset = end
	}
	if ctx.Err() != nil || check() != nil {
		return ErrNotReady
	}
	return nil
}
