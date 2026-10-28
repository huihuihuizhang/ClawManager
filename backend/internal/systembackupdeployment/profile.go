// Package systembackupdeployment holds the wire profile shared by HTTP admission
// and the production execution owner. It has no dependency on either adapter.
package systembackupdeployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"slices"
)

type ProfileError struct{ Code string }

func (e *ProfileError) Error() string { return "execution profile " + e.Code }

var profileToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var profileHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var installationToken = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)

func digestJSON(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func decodeProfile(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil || dec.Decode(new(any)) != io.EOF {
		return &ProfileError{"validation_failed"}
	}
	return nil
}

type ExecutionProfile struct {
	InstallationID    string   `json:"installation_id"`
	Revision          string   `json:"revision"`
	Orchestrator      string   `json:"source_orchestrator"`
	Profile           string   `json:"source_profile"`
	TargetClass       string   `json:"target_class"`
	TargetRisks       []string `json:"target_risks"`
	FailureDomain     string   `json:"target_failure_domain_id"`
	RestoreTargetRef  string   `json:"restore_target_ref"`
	RestoreTargetHash string   `json:"restore_target_sha256"`
}

func (p ExecutionProfile) CanonicalIdentity() ([]byte, string, error) {
	if !installationToken.MatchString(p.InstallationID) || !profileToken.MatchString(p.Revision) ||
		!slices.Contains([]string{"kubernetes", "k3s"}, p.Orchestrator) || !slices.Contains([]string{"cluster", "single-node"}, p.Profile) ||
		!slices.Contains([]string{"dr-ready-external", "same-cluster-copy"}, p.TargetClass) || !profileToken.MatchString(p.FailureDomain) ||
		!profileToken.MatchString(p.RestoreTargetRef) || !profileHash.MatchString(p.RestoreTargetHash) {
		return nil, "", &ProfileError{"validation_failed"}
	}
	allowed := []string{"source_overlap", "same_failure_domain", "artifact_credential_source_dependent", "kek_source_dependent", "signing_key_source_dependent", "catalog_source_dependent", "attestation_missing", "attestation_expired", "conditional_commit_unavailable", "transport_unverified", "broad_egress", "provider_capability_degraded"}
	p.TargetRisks = append([]string{}, p.TargetRisks...)
	slices.Sort(p.TargetRisks)
	for i, r := range p.TargetRisks {
		if !slices.Contains(allowed, r) || i > 0 && p.TargetRisks[i-1] == r {
			return nil, "", &ProfileError{"validation_failed"}
		}
	}
	raw, err := json.Marshal(p)
	return raw, digestJSON(raw), err
}

func LoadExecutionProfile(path string) (ExecutionProfile, error) {
	var p ExecutionProfile
	f, err := os.Open(path)
	if err != nil {
		return p, &ProfileError{"not_ready"}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return p, &ProfileError{"not_ready"}
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || decodeProfile(raw, &p) != nil {
		return p, &ProfileError{"not_ready"}
	}
	_, _, err = p.CanonicalIdentity()
	return p, err
}
