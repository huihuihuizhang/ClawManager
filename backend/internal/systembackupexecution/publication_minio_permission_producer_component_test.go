package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func checkMinIOProducerCommittedSources(t *testing.T, ctx context.Context, f *minioProducerComponent) ([]byte, []byte) {
	t.Helper()
	public := ed25519.PrivateKey(f.key).Public().(ed25519.PublicKey)
	var records [][]byte
	for _, v := range []struct {
		name, domain string
		immutable    bool
	}{{f.definition.GrantName, minioPermissionOwnerDomain, true}, {f.definition.HeadName, minioPermissionHeadDomain, false}} {
		cm, err := f.kube.CoreV1().ConfigMaps(f.definition.Grant.Namespace).Get(ctx, v.name, metav1.GetOptions{})
		if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.Immutable == nil || *cm.Immutable != v.immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 1 {
			t.Fatal("actual committed original resource", err)
		}
		raw := []byte(cm.Data["record.json"])
		if !ed25519.Verify(public, append([]byte(v.domain), raw...), cm.BinaryData["signature"]) || ed25519.Verify(public, raw, cm.BinaryData["signature"]) {
			t.Fatal("actual original domain-separated signature missing")
		}
		records = append(records, raw)
	}
	var grant minioPermissionGrant
	var head minioPermissionHead
	want, _ := ce.Canonical(f.definition.Grant)
	if decodePublicationCanonical(records[0], &grant) != nil || decodePublicationCanonical(records[1], &head) != nil || !bytes.Equal(want, records[0]) || grant.Epoch != 1 || head.Epoch != 1 || head.GrantSHA256 != hash(records[0]) || !grant.NotBefore.Equal(f.definition.Grant.NotBefore) || !grant.Until.Equal(f.definition.Grant.Until) || !head.NotBefore.Equal(grant.NotBefore) || !head.Until.Equal(grant.Until) {
		t.Fatal("producer changed original scope/epoch/windows")
	}
	if f.created.Load() != 3 || f.model.executions.Load() != 0 || f.model.openTx.Load() != 0 {
		t.Fatal("wrong enrollment/resource writes or leaked SQL transaction")
	}
	return records[0], records[1]
}

// Component test of the COMPLETE producer. No helper replaces its owner
// authentication, native observations, commits, exporter or final consumer.
// Local protocol models are not native MinIO/MySQL/field installation proof.
func TestMinIOPermissionProducerCompleteStartupAndActualConsumerComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newMinIOProducerComponent(t, ctx, "positive")
	beforeQueries := f.model.queries.Load()
	receipt, err := ProduceOriginalMinIOPermissionSource(ctx, f.installer, f.kube, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile, f.directory)
	if err != nil || receipt.File != f.output || receipt.Epoch != 1 || receipt.DefinitionSHA256 != f.definitionSHA || f.model.queries.Load() <= beforeQueries {
		t.Fatal("actual complete producer", err)
	}
	grantRaw, headRaw := checkMinIOProducerCommittedSources(t, ctx, f)
	raw, err := os.ReadFile(receipt.File)
	if err != nil || receipt.SHA256 != hash(raw) || receipt.GrantSHA256 != hash(grantRaw) || receipt.HeadSHA256 != hash(headRaw) {
		t.Fatal("receipt did not bind actual written bytes", err)
	}
	var config minioEffectivePermissionConfiguration
	if decodePublicationCanonical(raw, &config) != nil || config.Version != "minio-publication-effective-permission-source.v2" || !bytes.Equal(config.Issuer, ed25519.PrivateKey(f.key).Public().(ed25519.PublicKey)) || config.MinimumEpoch != 1 || config.Grant.UID != receipt.GrantUID || config.Head.UID != receipt.HeadUID || config.GrantSHA256 != receipt.GrantSHA256 || config.ObserverCredentialSHA256 != f.definition.ObserverCredentialSHA256 {
		t.Fatal("actual startup source fields")
	}
	if info, err := os.Stat(receipt.File); err != nil || !info.Mode().IsRegular() || runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		t.Fatal("startup file not created", err)
	}
	if f.preNative.Load() != 58 || f.postNative.Load() != 58 || f.selfReads.Load() != 24 || f.helpReads.Load() != 24 || f.postBucketPasses.Load() != 2 {
		t.Fatal("complete producer did not execute BOTH complete six-account native observations", f.preNative.Load(), f.postNative.Load(), f.selfReads.Load(), f.helpReads.Load())
	}
	// Independently invoke the actual startup consumer on the producer's file
	// and receipt pin, then read current signed owner resources. This is local
	// consumer loading, not whole DeploymentService/publication readiness.
	reader, err := NewMinIOEffectivePublicationPermissionV2Reader(MinIOPublicationPermissionInput{File: receipt.File, SHA256: receipt.SHA256})
	if err != nil {
		t.Fatal("actual startup consumer constructor", err)
	}
	state, err := reader.effectiveOwnerV2(ctx, f.kube, time.Now())
	actualGrant, _ := ce.Canonical(state.grant)
	if err != nil || !bytes.Equal(actualGrant, grantRaw) || state.stamp == "" || state.grant.ConfigSHA256 != f.definition.ConfigSHA256 {
		t.Fatal("actual consumer current owner read", err)
	}
	if _, err = NewMinIOEffectivePublicationPermissionReader(MinIOPublicationPermissionInput{File: receipt.File, SHA256: receipt.SHA256}); err == nil {
		t.Fatal("v1 consumer silently accepted v2 source")
	}
	// A repeat must not overwrite signed resources or output. This initial
	// installer deliberately refuses existing resources rather than re-issue.
	second, err := ProduceOriginalMinIOPermissionSource(ctx, f.installer, f.kube, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile, f.directory)
	after, readErr := os.ReadFile(receipt.File)
	if err == nil || second != (MinIOPermissionProductionReceipt{}) || readErr != nil || !bytes.Equal(raw, after) || f.created.Load() != 3 {
		t.Fatal("repeat overwrote/re-signed original startup/resources", err, readErr)
	}
	if err := os.WriteFile(receipt.File, append(append([]byte(nil), raw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewMinIOEffectivePublicationPermissionV2Reader(MinIOPublicationPermissionInput{File: receipt.File, SHA256: receipt.SHA256}); err == nil {
		t.Fatal("consumer accepted drift in actual startup bytes")
	}
}

func TestMinIOPermissionProducerRejectsPostCommitNativeAndOwnerTailsComponent(t *testing.T) {
	for _, scenario := range []string{"post-commit-native-generation", "post-commit-original-sql-window", "post-output-current-owner-head-revoked"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := newMinIOProducerComponent(t, ctx, scenario)
			receipt, err := ProduceOriginalMinIOPermissionSource(ctx, f.installer, f.kube, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile, f.directory)
			if !errors.Is(err, install.ErrCommitUnknown) || receipt != (MinIOPermissionProductionReceipt{}) || !f.headCreated.Load() || f.preNative.Load() != 58 || f.postNative.Load() != 58 || f.postBucketPasses.Load() != 2 {
				t.Fatal("did not reach/refuse actual full post-commit native/owner tail", err, f.preNative.Load(), f.postNative.Load())
			}
			grantRaw, headRaw := checkMinIOProducerCommittedSources(t, ctx, f)
			raw, readErr := os.ReadFile(f.output)
			if scenario == "post-output-current-owner-head-revoked" {
				// The file really exists BEFORE original current-head revocation.
				// The full producer's final consumer detects it, not a receipt hook.
				if readErr != nil || len(raw) == 0 || !f.ownerTailReached.Load() {
					t.Fatal("never reached actual post-output owner readback", readErr)
				}
				var head minioPermissionHead
				if json.Unmarshal(headRaw, &head) != nil || head.State != "revoked" {
					t.Fatal("original signed head was not actually revoked")
				}
				reader, e := NewMinIOEffectivePublicationPermissionV2Reader(MinIOPublicationPermissionInput{File: f.output, SHA256: hash(raw)})
				if e != nil {
					t.Fatal("startup itself should still be intact", e)
				}
				if _, e = reader.effectiveOwnerV2(ctx, f.kube, time.Now()); e == nil {
					t.Fatal("actual consumer accepted the revoked original current head")
				}
			} else {
				if !os.IsNotExist(readErr) {
					t.Fatal("startup exported despite failed pre-export tail", readErr)
				}
				if scenario == "post-commit-original-sql-window" && (!f.ownerTailReached.Load() || !f.model.clockBeyondOriginalWindow.Load()) {
					t.Fatal("actual original SQL window tail was not reached")
				}
			}
			// Preserve partial/unknown original resources, never auto-delete them
			// or invent a fresh epoch on retry. Recheck their exact signed bytes.
			if retry, e := ProduceOriginalMinIOPermissionSource(ctx, f.installer, f.kube, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile, f.directory); e == nil || retry != (MinIOPermissionProductionReceipt{}) {
				t.Fatal("unknown commit was silently renewed", e)
			}
			g2, h2 := checkMinIOProducerCommittedSources(t, ctx, f)
			if !bytes.Equal(g2, grantRaw) || !bytes.Equal(h2, headRaw) {
				t.Fatal("failed tail/retry changed original signed resources")
			}
			definition, readErr := os.ReadFile(f.definitionFile)
			if readErr != nil || hash(definition) != f.definitionSHA {
				t.Fatal("failure changed original selected definition", readErr)
			}
			if scenario == "post-output-current-owner-head-revoked" {
				after, e := os.ReadFile(f.output)
				if e != nil || !bytes.Equal(after, raw) {
					t.Fatal("unknown commit deleted/changed actual output", e)
				}
			}
		})
	}
}
