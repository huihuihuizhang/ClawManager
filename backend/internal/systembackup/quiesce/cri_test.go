package quiesce

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type inspectFunc func(context.Context, string) ([]byte, error)

func (f inspectFunc) Inspect(ctx context.Context, id string) ([]byte, error) { return f(ctx, id) }
func TestCRIProofRejectsMissingRunningAndForeignContainers(t *testing.T) {
	id := strings.Repeat("a", 64)
	pods := []PodIdentity{{Name: "agent", UID: "pod-1", Node: "node-a", Containers: []string{"containerd://" + id}}}
	for _, mode := range []string{"exited", "numeric", "running", "missing", "foreign-pod", "foreign-container", "zero-finished", "wrong-node", "extra-json"} {
		t.Run(mode, func(t *testing.T) {
			state, uid, container, finished := "\"CONTAINER_EXITED\"", "pod-1", id, "\"123456789\""
			switch mode {
			case "numeric":
				state = "2"
				finished = "123456789"
			case "running":
				state = "\"CONTAINER_RUNNING\""
			case "foreign-pod":
				uid = "pod-other"
			case "foreign-container":
				container = strings.Repeat("b", 64)
			case "zero-finished":
				finished = "\"0\""
			}
			proof := CRIProver{Node: "node-a", Inspector: inspectFunc(func(context.Context, string) ([]byte, error) {
				if mode == "missing" {
					return nil, errors.New("not found")
				}
				s := fmt.Sprintf(`{"status":{"id":%q,"state":%s,"finishedAt":%s,"labels":{"io.kubernetes.pod.uid":%q}}}`, container, state, finished, uid)
				if mode == "extra-json" {
					s += "{}"
				}
				return []byte(s), nil
			})}
			if mode == "wrong-node" {
				proof.Node = "node-b"
			}
			e := proof.Confirm(testDeadline(t), pods)
			if (mode == "exited" || mode == "numeric") != (e == nil) {
				t.Fatal(mode, e)
			}
		})
	}
}
