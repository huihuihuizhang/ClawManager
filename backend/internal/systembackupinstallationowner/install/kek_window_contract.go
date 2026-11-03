package install

import (
	"crypto/ed25519"
	"encoding/json"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	kek "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const BootstrapKEKWindowVersion = "system-backup-original-window-kek-resource.v1"
const BootstrapKEKWindowDomain = BootstrapKEKWindowVersion + "\x00"
const BootstrapKEKWindowSnapshotProfile = "system-backup-kek-window-snapshot-facts.go-json.v1"

// Explicit ORIGINAL association for reference:kek, not a provider capability,
// completed scan, PreparedAdmission or a replacement for the independent KEK
// owner. Its distinct issuer action binds the complete original selection to
// actual independently authenticated KEK source facts and deployment pins.
type BootstrapKEKWindowRecord struct {
	SchemaVersion, PlanSHA256, CaptureRecordSHA256, PreparationSHA256 string
	Target                                                            owner.Target
	Actor                                                             owner.Actor
	Enrollment                                                        EnrollmentPin
	NotBefore, Until                                                  time.Time
	Selection                                                         pd.BootstrapConsumptionRequest
	Reference                                                         sec.BootstrapSecretRef
	MappingSource                                                     reg.SourceRecord
	SourceRevision, BindingSHA256, SnapshotFactsSHA256                string
	SnapshotFactsProfile                                              string
}
type BootstrapKEKWindowFiles struct{ RecordFile, RecordSHA256, SignatureFile string }

func kekWindowPreparation(p *kek.SQLBootstrapKEKPreparation) (kek.SQLBootstrapKEKConfig, string, error) {
	cfg, err := p.OriginalConfiguration()
	if err != nil {
		return cfg, "", ErrInstall
	}
	raw, err := canonical(cfg)
	if err != nil {
		return cfg, "", ErrInstall
	}
	return cfg, hash(raw), nil
}
func kekWindowSnapshotSHA(snapshot reg.Snapshot) (string, error) {
	// SameSnapshotFacts deliberately excludes ONLY this SQL sample timestamp.
	// All epoch, binding, reference and complete four-partition facts remain.
	snapshot.ObservedAt = time.Time{}
	// Preserve uint64 SQL counters exactly; JCS/IEEE-754 aliases adjacent
	// values above 2^53. The explicit profile fixes this Go-JSON wire.
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", ErrInstall
	}
	return hash(append([]byte(BootstrapKEKWindowSnapshotProfile+"\x00"), raw...)), nil
}
func kekWindowBindingSHA(binding reg.Binding) (string, error) {
	// Reuse the existing original mapping Source.ContentSHA256 profile.
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}
func kekWindowReference(c sec.BootstrapConfig) (sec.BootstrapSecretRef, error) {
	var out sec.BootstrapSecretRef
	n := 0
	for _, ref := range c.References() {
		if ref.Purpose == "kek" {
			n++
			out = ref
		}
	}
	if n != 1 {
		return out, ErrInstall
	}
	return out, nil
}
func validateKEKWindow(r BootstrapKEKWindowRecord) error {
	if r.SnapshotFactsProfile != BootstrapKEKWindowSnapshotProfile || r.BindingSHA256 != r.MappingSource.ContentSHA256 || r.Actor.UserID < 1 || r.Actor.UserID > 9007199254740991 || !text(r.Actor.Username) || !text(r.Actor.OwnerSubject) {
		return ErrInstall
	}
	if r.SchemaVersion != BootstrapKEKWindowVersion || r.Reference.Purpose != "kek" || !digestPattern.MatchString(r.Reference.IdentityHash) || r.Reference.Version == "" || r.SourceRevision == "" || r.NotBefore.IsZero() || !r.NotBefore.Before(r.Until) || r.Until.Sub(r.NotBefore) > 24*time.Hour || bootstrapKEKSelectionHash(r.Selection) == "" || r.Selection.Scope != (pd.Scope{Installation: pd.Installation(r.Target.InstallationID), ServerUUID: pd.ServerUUID(r.Target.ServerUUID), Database: pd.Database(r.Target.Database)}) {
		return ErrInstall
	}
	for _, sum := range []string{r.PlanSHA256, r.CaptureRecordSHA256, r.PreparationSHA256, r.BindingSHA256, r.SnapshotFactsSHA256, r.MappingSource.ContentSHA256} {
		if !digestPattern.MatchString(sum) {
			return ErrInstall
		}
	}
	if r.MappingSource.SourceID == "" || r.MappingSource.RecordID == "" || r.MappingSource.RecordVersion == "" {
		return ErrInstall
	}
	return nil
}
func bootstrapKEKSelectionHash(selection pd.BootstrapConsumptionRequest) string {
	h, err := pd.BootstrapConsumptionHash(selection)
	if err != nil {
		return ""
	}
	return string(h)
}
func verifyKEKWindow(raw, signature, public []byte) (BootstrapKEKWindowRecord, error) {
	var r BootstrapKEKWindowRecord
	if len(raw) == 0 || len(raw) > 262144 || len(signature) != 64 || len(public) != 32 || !ed25519.Verify(public, append([]byte(BootstrapKEKWindowDomain), raw...), signature) || decodeExact(raw, &r) != nil || validateKEKWindow(r) != nil {
		return r, ErrInstall
	}
	return r, nil
}
