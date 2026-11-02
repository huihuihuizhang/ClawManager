package systembackupexecution

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
)

func TestOriginalCaptureMappingRejectsWorkerInvalidIndependentSourceGrantWindowsComponent(t *testing.T) {
	for _, name := range []string{"capture-database", "capture-team-objects"} {
		for _, fault := range []string{"zero-not-before", "twenty-five-hour-window"} {
			t.Run(name+"/"+fault, func(t *testing.T) {
				s, d := completeMappingComponentsFixture(t)
				operation := s.materials.Operations[name]
				if _, err := s.mappingComponents(name, operation, d); err != nil {
					t.Fatal("same original valid signed source must pass before window mutation", err)
				}
				mount := &d.DatabaseSource
				if name == "capture-team-objects" {
					mount = d.TeamsSource
				}
				raw, err := install.ReadSourceMaterialFile(mount.GrantFile)
				var signed worker.SignedFormalSourceGrant
				var grant worker.FormalSourceGrant
				if err != nil || decodeMetadataCanonical(raw, &signed) != nil || decodeMetadataCanonical(signed.Record, &grant) != nil {
					t.Fatal("actual original source grant unavailable", err)
				}
				if fault == "zero-not-before" {
					grant.NotBefore = time.Time{}
				} else {
					grant.Until = grant.NotBefore.Add(25 * time.Hour)
				}
				key, err := install.ReadPrivateFile(s.privateFile, ed25519.PrivateKeySize)
				if err != nil || len(key) != ed25519.PrivateKeySize {
					clear(key)
					t.Fatal("same enrolled signing key unavailable", err)
				}
				defer clear(key)
				signed.Record, err = json.Marshal(grant)
				if err != nil {
					t.Fatal(err)
				}
				signed.Signature = ed25519.Sign(ed25519.PrivateKey(key), append([]byte(worker.FormalSourceGrantDomain), signed.Record...))
				raw, err = json.Marshal(signed)
				if err != nil || !ed25519.Verify(mount.Issuer, append([]byte(worker.FormalSourceGrantDomain), signed.Record...), signed.Signature) {
					t.Fatal("window fault must retain a valid original-key signature", err)
				}
				if err := os.WriteFile(mount.GrantFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
				mount.GrantSHA256 = hash(raw)
				found := false
				for index, file := range d.Files {
					if file.WorkerPath == mount.GrantFile {
						d.Files[index].SHA256 = mount.GrantSHA256
						found = true
					}
				}
				if !found {
					t.Fatal("original projected grant pin missing")
				}
				// Hash, original signer, scope and original-window coverage are
				// still valid. Only the worker's structural time guard refuses.
				if grant.NotBefore.After(s.definition.NotBefore) || grant.Until.Before(s.definition.Until) {
					t.Fatal("fault accidentally targeted original-window coverage")
				}
				if _, err := s.mappingComponents(name, operation, d); err == nil {
					t.Fatal("mapper accepted a source window rejected by the actual worker")
				}
			})
		}
	}
}
