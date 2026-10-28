package quiesce

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/flow"
)

var criID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// CRIInspect must query the actual runtime on the recorded node. Missing
// containers are inconclusive (including after GC); absence is never success.
type CRIInspect interface {
	Inspect(context.Context, string) ([]byte, error)
}
type CRIProver struct {
	Node      string
	Inspector CRIInspect
}

func (p CRIProver) Confirm(ctx context.Context, pods []PodIdentity) error {
	if _, ok := ctx.Deadline(); !ok || p.Node == "" || p.Inspector == nil || len(pods) == 0 || len(pods) > 1000 {
		return flow.ErrQuiesce
	}
	seen := map[string]bool{}
	for _, pod := range pods {
		if pod.Node != p.Node || pod.UID == "" || len(pod.Containers) == 0 {
			return flow.ErrQuiesce
		}
		for _, address := range pod.Containers {
			parts := strings.Split(address, "://")
			if len(parts) != 2 || (parts[0] != "containerd" && parts[0] != "cri-o") || !criID.MatchString(parts[1]) || seen[address] {
				return flow.ErrQuiesce
			}
			seen[address] = true
			b, e := p.Inspector.Inspect(ctx, parts[1])
			if e != nil || len(b) > 1<<20 {
				return flow.ErrQuiesce
			}
			var result struct {
				Status struct {
					ID         string            `json:"id"`
					State      json.RawMessage   `json:"state"`
					FinishedAt json.RawMessage   `json:"finishedAt"`
					Labels     map[string]string `json:"labels"`
				} `json:"status"`
			}
			decoder := json.NewDecoder(bytes.NewReader(b))
			if decoder.Decode(&result) != nil {
				return flow.ErrQuiesce
			}
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				return flow.ErrQuiesce
			}
			status := result.Status
			// crictl uses protobuf JSON: the enum may be its symbolic name or numeric
			// value; int64 timestamps may be decimal strings. Both must prove EXITED.
			state := strings.Trim(string(status.State), "\"")
			finished := strings.Trim(string(status.FinishedAt), "\"")
			if status.ID != parts[1] || status.Labels["io.kubernetes.pod.uid"] != pod.UID || (state != "CONTAINER_EXITED" && state != "2") || !positiveTimestamp(finished) {
				return flow.ErrQuiesce
			}
		}
	}
	return ctx.Err()
}
func positiveTimestamp(s string) bool {
	if len(s) == 0 || len(s) > 19 || s[0] < '1' || s[0] > '9' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0
}

// CRICommand is a Linux node-side read-only adapter. Binary/endpoint are pinned
// deployment configuration, never request parameters. The controller must run
// it on the observed node using a restricted proof worker, not in an API Pod.
type CRICommand struct{ Binary, Endpoint string }

func (c CRICommand) Inspect(ctx context.Context, id string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok || runtime.GOOS != "linux" || !filepath.IsAbs(c.Binary) || !strings.HasPrefix(c.Endpoint, "unix:///") || strings.ContainsAny(c.Endpoint, "\x00\r\n") || !criID.MatchString(id) {
		return nil, flow.ErrQuiesce
	}
	command := exec.CommandContext(ctx, c.Binary, "--runtime-endpoint", c.Endpoint, "inspect", "--output", "json", id)
	output := &boundedOutput{remaining: 1 << 20}
	command.Stdout = output
	command.Stderr = io.Discard
	if command.Run() != nil {
		return nil, flow.ErrQuiesce
	}
	return output.Bytes(), nil
}

type boundedOutput struct {
	bytes.Buffer
	remaining int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.remaining {
		return 0, errors.New("proof output exceeds limit")
	}
	b.remaining -= len(p)
	return b.Buffer.Write(p)
}
