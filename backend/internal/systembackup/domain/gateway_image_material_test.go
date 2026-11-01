package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
)

func materialTestObject(size int) capturedImageObject {
	return capturedImageObject{Ref: GatewayImageObjectRef{ArtifactID: "img_" + strings.Repeat("a", 32), Bucket: "owned-source", Key: "gateway-images/img_" + strings.Repeat("a", 32), Version: "owned-v1", SHA256: strings.Repeat("a", 64), Size: int64(size)}, Ciphertext: bytes.Repeat([]byte{7}, size)}
}
func materialTestJSON(t *testing.T, objects ...capturedImageObject) []byte {
	t.Helper()
	raw, e := json.Marshal(capturedImageObjects{Version: "gateway-image-objects.074.v1", SourceSQLSHA256: strings.Repeat("a", 64), Objects: objects})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestGatewayImageMaterialPreallocationLimits(t *testing.T) {
	ctx := context.Background()
	limits := imageMaterialLimits{64, 8, 12}
	if e := preflightImageMaterial(ctx, materialTestJSON(t, materialTestObject(8), materialTestObject(4)), true, limits); e != nil {
		t.Fatal("exact small budgets", e)
	}
	for _, tc := range []struct {
		name    string
		objects []capturedImageObject
	}{
		{"single", []capturedImageObject{materialTestObject(9)}},
		{"total", []capturedImageObject{materialTestObject(8), materialTestObject(5)}},
		{"count", make([]capturedImageObject, 65)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "count" {
				for i := range tc.objects {
					tc.objects[i] = materialTestObject(1)
				}
			}
			if !errors.Is(preflightImageMaterial(ctx, materialTestJSON(t, tc.objects...), true, limits), ErrCapacity) {
				t.Fatal("budget was not rejected before typed decode")
			}
		})
	}
	// The real production item ceiling is rejected using a declared size only;
	// no large base64 string, decoded buffer or memory-pressure test is needed.
	o := materialTestObject(1)
	o.Ref.Size = imageCiphertextLimit + 1
	var out capturedImageObjects
	if !errors.Is(decodeImageMaterial(ctx, materialTestJSON(t, o), &out), ErrCapacity) || len(out.Objects) != 0 {
		t.Fatal("actual item ceiling allocated a typed object")
	}
	for _, count := range []int{64, 65} {
		data := imageReceiptData{}
		for i := 0; i < count; i++ {
			data.Objects = append(data.Objects, restoredImageObject{Source: materialTestObject(1).Ref, TargetVersion: "target-v1", PlaintextSHA256: strings.Repeat("a", 64)})
		}
		raw, e := json.Marshal(data)
		if e != nil {
			t.Fatal(e)
		}
		e = preflightImageMaterial(ctx, raw, false, imageMaterialLimits{64, 8, 128})
		if count == 64 && e != nil || count == 65 && !errors.Is(e, ErrCapacity) {
			t.Fatal("receipt count bound", count, e)
		}
	}
	t.Log("pre-typed-decode count64, real item maximum, exact tiny item/total boundaries and independent receipt count checked without large allocations")
}

type imageMaterialObservingContext struct {
	context.Context
	out               *capturedImageObjects
	retained          []byte
	cancelAfterDecode bool
}

func (c *imageMaterialObservingContext) Err() error {
	if len(c.out.Objects) > 0 && len(c.out.Objects[0].Ciphertext) > 0 {
		c.retained = c.out.Objects[0].Ciphertext
		if c.cancelAfterDecode {
			return context.Canceled
		}
	}
	return c.Context.Err()
}
func TestGatewayImageMaterialFailureAndCancellationClear(t *testing.T) {
	valid := materialTestJSON(t, materialTestObject(1))
	for _, mode := range []string{"missing-ref", "duplicate", "unknown", "trailing", "partial-decode", "canonical", "cancel-before", "cancel-after"} {
		t.Run(mode, func(t *testing.T) {
			raw := append([]byte(nil), valid...)
			var out capturedImageObjects
			observed := &imageMaterialObservingContext{Context: context.Background(), out: &out}
			var ctx context.Context = observed
			switch mode {
			case "missing-ref":
				raw = bytes.Replace(raw, []byte(`"Ref":{`), []byte(`"MissingRef":{`), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"Objects":`), []byte(`"Version":"duplicate","Objects":`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"Objects":`), []byte(`"Unknown":null,"Objects":`), 1)
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			case "partial-decode":
				raw = materialTestJSON(t, materialTestObject(1), materialTestObject(1))
				// Malformed later material must never leave retained typed values,
				// regardless of how much the standard decoder completed.
				idx := bytes.LastIndex(raw, []byte(`"Bucket":"owned-source"`))
				raw = append(append(append([]byte(nil), raw[:idx]...), []byte(`"Bucket":"\q"`)...), raw[idx+len(`"Bucket":"owned-source"`):]...)
			case "canonical":
				raw = bytes.Replace(raw, []byte(`"Ciphertext":"Bw=="`), []byte(`"Ciphertext":"Bx=="`), 1)
			case "cancel-before":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "cancel-after":
				observed.cancelAfterDecode = true
			}
			if e := decodeImageMaterial(ctx, raw, &out); e == nil || len(out.Objects) != 0 || out.Version != "" {
				t.Fatal("failed decode retained typed material", e)
			}
			for _, v := range observed.retained {
				if v != 0 {
					t.Fatal("ciphertext backing buffer was not cleared")
				}
			}
			if (mode == "canonical" || mode == "cancel-after") && len(observed.retained) == 0 {
				t.Fatal("counterexample never reached a populated typed buffer")
			}
		})
	}
}

func TestGatewayImageMaterialEncryptedOpenKeepsEnvelopeChecks(t *testing.T) {
	ctx := context.Background()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	key := bytes.Repeat([]byte{92}, 32)
	binding, _, _ := imageObjectBindings()
	objects := make([]capturedImageObject, 65)
	for i := range objects {
		objects[i] = materialTestObject(1)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want bool
	}{{"valid", materialTestJSON(t, materialTestObject(1)), true}, {"count65", materialTestJSON(t, objects...), false}} {
		receipt, e := staging.SealFile(ctx, root, tc.name+".enc", key, binding, func(w io.Writer) error { _, e := w.Write(tc.raw); return e })
		if e != nil {
			t.Fatal(e)
		}
		var out capturedImageObjects
		e = openImageMaterial(ctx, root, receipt, key, binding, &out)
		if (e == nil) != tc.want {
			t.Fatal(tc.name, e)
		}
		clearImageMaterial(&out)
		if tc.want {
			if e = root.Chmod(receipt.Name, 0600); e != nil {
				t.Fatal("make owned sealed fixture writable for explicit corruption", e)
			}
			file, e := root.OpenFile(receipt.Name, os.O_RDWR, 0)
			if e != nil {
				t.Fatal(e)
			}
			if e = file.Truncate(receipt.Size - 1); e != nil {
				t.Fatal(e)
			}
			file.Close()
			// Recompute the outer file receipt: final-frame AEAD authentication
			// still rejects it, rather than relying only on the outer hash.
			encoded, e := root.ReadFile(receipt.Name)
			if e != nil {
				t.Fatal(e)
			}
			receipt.Size = int64(len(encoded))
			receipt.SHA256 = imageHash(encoded)
			clear(encoded)
			if e = openImageMaterial(ctx, root, receipt, key, binding, &out); e == nil || len(out.Objects) != 0 {
				t.Fatal("truncated final frame bypassed envelope validation")
			}
		}
	}
}
