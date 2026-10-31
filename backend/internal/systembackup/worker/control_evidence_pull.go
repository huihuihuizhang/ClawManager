package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// ControlEvidenceSource is synchronous inside this ORIGINAL Generate/using
// callback. The locator comes only from the frozen original invocation; no
// caller supplies a replacement ref/scope/nonce or plaintext. It writes no
// files and returns in-memory canonical input to the two original C streams.
func (j *CaptureKeyJob) ControlEvidenceSource(ctx context.Context) (source ce.PreparedSource, resultErr error) {
	defer func() {
		if resultErr != nil && j != nil && j.original != nil {
			j.original.failed = true
		}
	}()
	if j == nil || j.original == nil || j.original.client == nil || j.original.invocation.Request.Operation != ce.Operation || j.recheckDuringUse(ctx) != nil {
		return source, ErrExecution
	}
	a := j.original
	client := a.client
	if client.http == nil || client.tokenFile == "" {
		return source, ErrExecution
	}
	raw, err := json.Marshal(a.invocation.Request)
	if err != nil {
		return source, ErrExecution
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return source, ErrExecution
	}
	var locator ce.CaptureLocator
	decoder := json.NewDecoder(bytes.NewReader(fields["control_evidence"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&locator) != nil || decoder.Decode(new(any)) != io.EOF || locator.Validate() != nil {
		return source, ErrExecution
	}
	control := ControlRequest{Invocation: a.invocation, InvocationSHA256: a.lease.Identity.InvocationSHA256, Action: "key-check", Point: a.lease.Nonce}
	if !ValidateControl(control) {
		return source, ErrExecution
	}
	body, err := json.Marshal(control)
	if err != nil {
		return source, ErrExecution
	}
	defer clear(body)
	endpoint, err := url.Parse(client.endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return source, ErrExecution
	}
	endpoint.Path = "/control-evidence"
	endpoint.RawPath = ""
	bounded, cancel := context.WithDeadline(ctx, j.until)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return source, ErrExecution
	}
	request.Header.Set("Content-Type", "application/json")
	token, err := os.ReadFile(client.tokenFile)
	defer clear(token)
	if err != nil || len(token) < 16 || len(token) > 16384 || strings.ContainsAny(string(token), "\r\n\x00") {
		return source, ErrExecution
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	response, err := client.http.Do(request)
	if err != nil {
		return source, ErrExecution
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || response.Uncompressed {
		return source, ErrExecution
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, ce.MaxProofBytes+1))
	if err != nil || len(payload) > ce.MaxProofBytes {
		return source, ErrExecution
	}
	defer clear(payload)
	var reply ce.SourceResponse
	decoder = json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reply) != nil || decoder.Decode(new(any)) != io.EOF || reply.Version != "system-backup-control-evidence-source-response.v1" || reply.InvocationSHA256 != control.InvocationSHA256 || reply.KeyUseNonce != control.Point || reply.AuthoritySHA256 != a.lease.AuthoritySHA256 || !reply.Until.Equal(a.lease.Until) || !time.Now().Before(j.until) {
		return source, ErrExecution
	}
	source, err = ce.Rebuild(bounded, locator, reply.Evidence)
	if err != nil {
		return ce.PreparedSource{}, err
	}
	if j.recheckDuringUse(bounded) != nil || bounded.Err() != nil || !time.Now().Before(j.until) {
		clear(source.SidecarJSON)
		clear(source.ProofsJSON)
		return ce.PreparedSource{}, ErrExecution
	}
	return source, nil
}
