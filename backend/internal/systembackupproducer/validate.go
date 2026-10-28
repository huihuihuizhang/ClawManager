package systembackupproducer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

var (
	hashPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern           = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	evidencePattern     = regexp.MustCompile(`^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidPattern         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	installationPattern = regexp.MustCompile(`^installation_[A-Za-z0-9_-]{1,115}$`)
	refPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	requestPattern      = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)
)
var providerSlots = map[Role][]string{
	"artifact": {"conditional_create", "checksum_bound_request", "scoped_upload_credential", "scoped_read_credential", "scoped_delete_credential", "multipart_resume", "object_checksum", "version_listing", "delete_marker_listing", "strong_read_after_write", "tls_verified"},
	"catalog":  {"conditional_create", "checksum_bound_request", "scoped_read_credential", "scoped_append_credential", "strong_read_after_write", "provider_snapshot_listing", "inventory_manifest_listing", "versioned_absence_proof", "tls_verified"},
	"evidence": {"conditional_create", "checksum_bound_request", "scoped_read_credential", "scoped_write_credential", "scoped_delete_credential", "object_checksum", "strong_read_after_write", "versioned_absence_proof", "tls_verified"},
}
var dependencySlots = []string{"artifact_credential", "ca", "kek", "signing", "catalog", "evidence", "attestation"}
var dependencyReasons = []string{"none", "provider_unavailable", "credential_unavailable", "ca_unavailable", "kek_unavailable", "signing_key_unavailable", "signature_invalid", "key_compromised", "acceptance_invalid", "catalog_unavailable", "evidence_unavailable", "attestation_invalid", "attestation_expired", "artifact_corrupt", "catalog_tombstoned", "delete_failed", "cleanup_residual_data", "finalization_pending", "verification_inconclusive"}

func in(s string, choices ...string) bool { return slices.Contains(choices, s) }
func bounded(s string, chars, bytes int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) >= 1 && utf8.RuneCountInString(s) <= chars && len(s) <= bytes
}
func provider(role Role) bool { _, ok := providerSlots[role]; return ok }
func purpose(role Role, p Purpose) bool {
	if provider(role) {
		return p == "capability_probe"
	}
	return p == "dependency_check"
}

func validateTyped(v reflect.Value) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return validateTyped(v.Elem())
	}
	switch v.Kind() {
	case reflect.Bool:
		return nil
	case reflect.String:
		s := v.String()
		if !utf8.ValidString(s) {
			return ErrInvalid
		}
		valid := true
		switch value := v.Interface().(type) {
		case Hash:
			valid = hashPattern.MatchString(s)
		case ID:
			valid = idPattern.MatchString(s)
		case EvidenceID:
			valid = evidencePattern.MatchString(s)
		case Installation:
			valid = installationPattern.MatchString(s)
		case ServerUUID:
			valid = uuidPattern.MatchString(s)
		case Database:
			valid = bounded(s, 64, 256)
		case Text:
			valid = bounded(s, 256, 1024)
		case ProviderVersion:
			valid = bounded(s, 128, 512)
		case RefVersion:
			valid = refPattern.MatchString(s)
		case RequestKey:
			valid = requestPattern.MatchString(s)
		case RelativeKey:
			valid = bounded(s, 1024, 4096)
		case Counter:
			_, e := value.Uint64()
			valid = e == nil
		case ZeroCounter:
			_, e := value.Uint64()
			valid = e == nil
		case Timestamp:
			_, e := value.Time()
			valid = e == nil
		case Role:
			valid = in(s, "artifact", "catalog", "evidence", "kms", "secret", "signing")
		case Purpose:
			valid = in(s, "capability_probe", "dependency_check")
		case Owner:
			valid = in(s, "A", "C")
		}
		if !valid {
			return ErrInvalid
		}
		return nil
	case reflect.Slice:
		if v.IsNil() || v.Len() < 1 || v.Len() > 32 {
			return ErrInvalid
		}
		for i := 0; i < v.Len(); i++ {
			if e := validateTyped(v.Index(i)); e != nil {
				return e
			}
		}
		return nil
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if e := validateTyped(v.Field(i)); e != nil {
				return e
			}
		}
	default:
		return ErrInvalid
	}
	valid := true
	switch r := v.Interface().(type) {
	case UnconfiguredAdmission:
		valid = r.Scenario == "unconfigured"
	case ConfiguredAdmission:
		valid = in(r.Scenario, "disabled", "enabled")
	case Admission:
		valid = (r.Unconfigured == nil) != (r.Configured == nil)
	case ServiceHost:
		valid = r.Kind == "service"
	case JobHost:
		valid = r.Kind == "job"
	case Host:
		valid = (r.Service == nil) != (r.Job == nil)
	case Target:
		want := providerSlots[r.Role]
		got := make([]string, len(r.ResultSlots))
		for i, s := range r.ResultSlots {
			got[i] = string(s)
			if i > 0 && got[i-1] >= got[i] {
				valid = false
			}
		}
		if provider(r.Role) {
			want = slices.Clone(want)
			slices.Sort(want)
			valid = valid && r.EvaluatorOwner == "C" && slices.Equal(got, want)
		} else {
			valid = valid && r.EvaluatorOwner == "A"
			for _, s := range got {
				valid = valid && slices.Contains(dependencySlots, s)
			}
			if r.Role == "kms" {
				valid = valid && slices.Equal(got, []string{"kek"})
			}
			if r.Role == "signing" {
				valid = valid && slices.Equal(got, []string{"signing"})
			}
		}
	case EvidenceBinding:
		valid = r.OwnerType == "system" && r.EvidenceType == "capability_snapshot" && in(r.Classification, "public", "internal", "confidential", "sensitive")
	case ProviderObservation:
		switch r.Status {
		case "supported":
			valid = r.Reason == "none"
		case "unsupported":
			valid = r.Reason == "unsupported_api"
		case "degraded":
			valid = in(r.Reason, "probe_failed", "provider_unavailable", "credential_unavailable", "permission_denied", "response_invalid", "version_drift", "internal")
		default:
			valid = false
		}
	case DependencyObservation:
		valid = slices.Contains(dependencySlots, r.Slot) && in(r.Status, "healthy", "degraded", "unknown") && slices.Contains(dependencyReasons, r.Reason) && (r.Status == "healthy") == (r.Reason == "none") && (r.ObservedVersion == nil) == (r.ObservedChecksum == nil)
	case ProviderResults:
		valid = r.Kind == "provider"
	case DependencyResults:
		valid = r.Kind == "dependency"
	case Results:
		valid = (r.Provider == nil) != (r.Dependency == nil)
	case ResultRequest:
		valid = r.SchemaVersion == "system-backup-producer-result.c1" && purpose(r.Target.Role, r.Purpose) && r.Evidence.OwnerID == r.Scope.Installation && r.Evidence.ImmutableVersion != nil && *r.Evidence.ImmutableVersion != "null" && r.ObservedAt < r.ObservationExpiresAt
		got := []string{}
		if provider(r.Target.Role) {
			valid = valid && r.Results.Provider != nil
			if r.Results.Provider != nil {
				for _, o := range r.Results.Provider.Observations {
					got = append(got, string(o.Slot))
				}
			}
		} else {
			valid = valid && r.Results.Dependency != nil
			if r.Results.Dependency != nil {
				for _, o := range r.Results.Dependency.Observations {
					got = append(got, o.Slot)
				}
			}
		}
		want := make([]string, len(r.Target.ResultSlots))
		for i, s := range r.Target.ResultSlots {
			want[i] = string(s)
		}
		valid = valid && slices.Equal(got, want) && withinCanonical(r, 65536)
	case CommandRequest:
		valid = r.SchemaVersion == "system-backup-producer-command.c1" && in(r.Command, "acquire", "renew", "revoke", "takeover")
		valid = valid && (r.Command == "acquire") == (r.Expected == nil) && in(r.Command, "acquire", "takeover") == (r.Next != nil) && (r.Command == "revoke") == (r.LeaseExpiresAt == nil)
		if r.Command != "takeover" {
			valid = valid && r.TerminationDecisionHash == nil
		}
		if r.Expected != nil {
			valid = valid && string(r.Expected.TargetGeneration) == string(r.ExpectedTargetGeneration)
		}
		if r.Next != nil {
			valid = valid && r.LeaseExpiresAt != nil && purpose(r.Target.Role, r.Next.Purpose) && r.Next.SubjectIdentityHash == r.ActorIdentityHash
			if r.LeaseExpiresAt != nil {
				valid = valid && *r.LeaseExpiresAt <= r.Next.AuthorizationExpiresAt && r.Next.OwnerWriteExpiresAt <= r.Next.AuthorizationExpiresAt
			}
		}
		if r.Command == "takeover" {
			if r.Expected == nil || r.Next == nil {
				valid = false
			} else {
				old, _ := r.Expected.GrantGeneration.Uint64()
				next, _ := r.Next.GrantGeneration.Uint64()
				valid = valid && r.Next.GrantID != r.Expected.GrantID && r.Next.RunID != r.Expected.RunID && next > old
			}
		}
		valid = valid && withinCanonical(r, 32768)
	case DomainRecord:
		valid = in(r.State, "open", "closed", "revoked")
	case GrantRecord:
		valid = in(r.State, "active", "revoked", "superseded") && purpose(r.Target.Role, r.Purpose) && r.CreatedAt < r.LeaseExpiresAt && r.LeaseExpiresAt <= r.AuthorizationExpiresAt
	case RunRecord:
		valid = in(r.State, "acquired", "pending", "published", "committed", "superseded")
		if r.ObservedAt == nil && r.ObservationExpiresAt == nil {
			valid = valid && in(r.State, "acquired", "superseded")
		} else {
			valid = valid && r.ObservedAt != nil && r.ObservationExpiresAt != nil
			if valid {
				valid = *r.ObservedAt < *r.ObservationExpiresAt
			}
		}
	case TargetRecord:
		h, e := targetDigest(r.Target)
		valid = e == nil && h == r.TargetHash
	case HistoricalBindingRecord:
		h := sha256.Sum256([]byte(r.RelativeKey))
		valid = r.Evidence.OwnerID == r.Scope.Installation && r.Evidence.ImmutableVersion == nil && r.ObservedAt < r.ObservationExpiresAt && r.RetentionExpiresAt >= r.OwnerWriteExpiresAt && string(r.Evidence.RelativeKeyHash) == hex.EncodeToString(h[:]) && !strings.HasPrefix(string(r.RelativeKey), "/") && !strings.Contains(string(r.RelativeKey), "\\")
		for _, p := range strings.Split(string(r.RelativeKey), "/") {
			valid = valid && p != "" && p != "." && p != ".."
		}
	case ReceiptRecord:
		h, e := resultHashesUnchecked(r.Request)
		old, _ := r.Request.ExpectedResultVersion.Uint64()
		next, _ := r.ResultVersion.Uint64()
		valid = e == nil && r.Scope == r.Request.Scope && r.ReceiptKeyHash == h.Key && r.RequestHash == h.Request && r.CommittedAt < r.RetentionExpiresAt && old < ^uint64(0) && next == old+1
	case CommandReceiptRecord:
		h, e := commandHashesUnchecked(r.Request)
		valid = e == nil && r.Scope == r.Request.Scope && r.ReceiptKeyHash == h.Key && r.RequestHash == h.Request && r.CommittedAt < r.RetentionExpiresAt
		if r.Request.Next != nil {
			n := r.Request.Next
			valid = valid && r.Outcome.GrantID == n.GrantID && r.Outcome.GrantGeneration == n.GrantGeneration && r.Outcome.RunID == n.RunID
		} else if r.Request.Expected != nil {
			n := r.Request.Expected
			valid = valid && r.Outcome.GrantID == n.GrantID && r.Outcome.GrantGeneration == n.GrantGeneration && r.Outcome.RunID == n.RunID
		} else {
			valid = false
		}
		prior, _ := r.Request.ExpectedTargetGeneration.Uint64()
		next, _ := r.Outcome.TargetGeneration.Uint64()
		if in(r.Request.Command, "acquire", "takeover") {
			valid = valid && prior < ^uint64(0)
			prior++
		}
		valid = valid && next == prior
	case ReferenceRecord:
		valid = in(r.ReferenceKind, "producer_result", "producer_receipt", "bootstrap_candidate", "hold")
	}
	if !valid {
		return ErrInvalid
	}
	return nil
}
func withinCanonical(v any, max int) bool {
	raw, e := json.Marshal(v)
	if e != nil {
		return false
	}
	encoded, e := CanonicalJSON(raw)
	return e == nil && len(encoded) <= max
}
