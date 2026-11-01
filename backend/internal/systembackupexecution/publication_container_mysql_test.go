package systembackupexecution

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
)

// Same actual task/10 workers/full C/single external certificate Sign, then the
// real production writer reads private original copies into six local files.
// Inspect's named LOCAL file-version DATA below is structural readback only;
// it is not a native artifact object version, Job upload or DR acceptance.
func TestAOriginalSixPartContainerAssemblyMySQL(t *testing.T) {
	runAOriginalSixPartCertificatePublication(t, "current", func(ctx context.Context, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		limits, err := f.service.publicationContainerLimits(ctx, *claim, capture.Input.CaptureAttemptNo)
		if err != nil {
			t.Fatal(err)
		}
		var total int64
		members := 0
		for _, requested := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
			var facts pc.Facts
			receipt, err := staging.WriteUnpublishedFile(ctx, root, "container-"+requested+".enc", func(dst io.Writer) error {
				var err error
				facts, err = f.service.writeOriginalPublicationContainer(ctx, claim, capture.Input.CaptureAttemptNo, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}, capture, requested, dst)
				return err
			})
			if err != nil || receipt.SHA256 != facts.SHA256 || receipt.Size != facts.Size || facts.Size > limits.MaxArtifactBytes-total {
				t.Fatal("actual original C container file", requested, err)
			}
			total += facts.Size
			members += len(facts.Header.Members)
			file, err := staging.OpenFile(ctx, root, receipt)
			if err != nil {
				t.Fatal(err)
			}
			checkpoints := map[string]string{}
			for _, part := range capture.Parts {
				if part.RequestedPart == requested {
					sum, err := pcCheckpointSHA(part.Checkpoint)
					if err != nil {
						t.Fatal(err)
					}
					checkpoints[part.Part] = sum
				}
			}
			read, err := pc.Inspect(ctx, pc.FixedObject{Reader: file, Version: "named-LOCAL-file-structural-DATA", SHA256: receipt.SHA256, Size: receipt.Size}, facts.Header.Scope, checkpoints, limits.MaxArtifactBytes, limits.MaxIndexBytes)
			closeErr := file.Close()
			if err != nil || closeErr != nil || read.SHA256 != facts.SHA256 || read.Size != facts.Size || len(read.Header.Members) != len(facts.Header.Members) {
				t.Fatal("independent complete local container parser", requested, err, closeErr)
			}
		}
		if members != 8 {
			t.Fatal("business original C omitted/duplicated", members)
		}
		t.Log("actual original private C into six local physical containers; not remote/Job acceptance", f.publicID, members, total)
	})
}
