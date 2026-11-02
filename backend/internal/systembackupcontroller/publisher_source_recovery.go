package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/quiesce"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

type PublisherSourceRecoveryFacts struct {
	Scope                                                                              ce.Scope
	Root                                                                               ce.EvidenceRef
	SourceSHA256, PlanSHA256, CaptureResultSHA256, FrozenControlSHA256, RegistrySHA256 string
	CaptureEpoch                                                                       uint64
	WriterCount                                                                        int
	ObservedAt                                                                         time.Time
}

// PublisherSourceRecovery is issued only after the current publisher's typed
// capture reader and complete original recovery history have been consumed.
// It is immutable data, not execution/Unwrap/Ready authority.
type PublisherSourceRecovery struct {
	access   *security.SQLPublisherCaptureAuthority
	record   PublisherCaptureRecord
	prepared *PreparedSourceRecovery
	facts    PublisherSourceRecoveryFacts
}

func (h *PublisherSourceRecovery) Facts() PublisherSourceRecoveryFacts {
	if h == nil {
		return PublisherSourceRecoveryFacts{}
	}
	return h.facts
}

// OpenPublisherSourceRecovery performs record-key/AEAD work OUTSIDE the caller's
// publication transaction. Historical claim fields are pure parser inputs only;
// this function never invokes the old execution/recovery grant or source I/O.
func (s SQLExecutionRecords) OpenPublisherSourceRecovery(ctx context.Context, access *security.SQLPublisherCaptureAuthority, record PublisherCaptureRecord) (*PublisherSourceRecovery, error) {
	if record.receipt == nil || record.receipt.access != access || publisherCaptureRecordHash(record) != record.receipt.recordSHA {
		return nil, ErrExecutionAuthority
	}
	identity, ok := s.Keys.(*PinnedExecutionIdentity)
	originalIdentity, sameIdentity := record.receipt.records.Keys.(*PinnedExecutionIdentity)
	if !ok || identity == nil || !sameIdentity || identity != originalIdentity || s.Authority.DB != record.receipt.records.Authority.DB {
		return nil, ErrExecutionAuthority
	}
	check := func() error {
		tx, err := s.Authority.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return err
		}
		defer tx.Rollback()
		return record.RecheckTx(ctx, tx, access)
	}
	if err := check(); err != nil {
		return nil, err
	}
	var candidate publisherStoredCandidate
	if publisherDecodeClosed(record.CandidateJSON, &candidate) != nil {
		return nil, ErrExecutionRecord
	}
	original := d.Input{Authority: candidate.Authority, ConfigSnapshot: bytes.Clone(record.Input.ConfigSnapshot), ProfileID: record.Input.ProfileID, ProfileRevision: record.Input.ProfileRevision, Backup: &record.Input.Backup}
	desc, err := describeExecutionPlan(original, record.Plan)
	if err != nil || desc.SourceSHA256 != record.Input.SourceSHA256 || !bytes.Equal(desc.Source, record.Input.SourceSnapshot) {
		return nil, ErrExecutionRecord
	}
	snapshot := record.receipt.snapshot
	key, err := publisherReadRecordKey(identity, snapshot.Result.Ref)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	raw, err := publisherOpenRecord(ctx, snapshot.Result.Cipher, key, publisherRecordBinding(snapshot.Coordinates, "capture_result", snapshot.Result.Digest), 8<<20)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if recordHash(raw) != record.CaptureResultSHA256 {
		return nil, ErrExecutionRecord
	}
	parts, err := sourceRecoveryParsedParts(original, record.Plan, desc, raw)
	if err != nil {
		return nil, err
	}
	h := &PublisherSourceRecovery{access: access, record: record, prepared: &PreparedSourceRecovery{a: original.Authority, desc: desc, parts: parts}}
	tx, err := s.Authority.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = h.readTx(ctx, tx, true); err != nil {
		return nil, err
	}
	return h, nil
}

// RecheckTx does only bounded SQL history reads under this SAME concrete current
// publisher authority. No key-file, network, AEAD, current runtime observation,
// mutation lease acquisition or old capture/recovery authorization is performed.
func (h *PublisherSourceRecovery) RecheckTx(ctx context.Context, tx *sql.Tx, access *security.SQLPublisherCaptureAuthority) error {
	if h == nil || h.access != access || h.prepared == nil {
		return ErrExecutionAuthority
	}
	return h.readTx(ctx, tx, false)
}

func (h *PublisherSourceRecovery) readTx(ctx context.Context, tx *sql.Tx, first bool) error {
	if err := h.record.RecheckTx(ctx, tx, h.access); err != nil {
		return err
	}
	p, input, capture := h.prepared, h.record.Input, h.record.receipt.snapshot
	scope := ce.Scope{Installation: input.InstallationID, Backup: input.TaskPublicID, Attempt: input.CaptureAttemptNo}
	root, err := sourceRecoveryReadEntry(ctx, tx, scope, "")
	if err != nil {
		return ErrSourceRecoveryProofRequired
	}
	var saved sourceRecoveryRoot
	if json.Unmarshal(root.Payload, &saved) != nil {
		return ErrSourceRecoveryProofRequired
	}
	writers, _ := json.Marshal(p.desc.Writers)
	var application, registry string
	var actualWriters []byte
	var epoch uint64
	if tx.QueryRowContext(ctx, `SELECT application_scope,gate_generation,registry_sha256,writers_json FROM system_backup_v2_runtime_captures WHERE task_public_id=? FOR SHARE`, scope.Backup).Scan(&application, &epoch, &registry, &actualWriters) != nil || !bytes.Equal(writers, actualWriters) || registry != recordHash(writers) || epoch != input.CaptureEpoch {
		return ErrSourceRecoveryProofRequired
	}
	p.gate.Authority.ApplicationScope = application
	p.root = saved
	frozen, err := p.frozenControlTx(ctx, tx)
	if err != nil || saved.Version != "original-source-recovery.v1" || saved.Scope != scope || saved.ConfigVersion != input.ConfigVersion || saved.ConfigSHA256 != input.ConfigSHA256 || saved.PlanSHA256 != h.record.Plan.SHA256 || saved.SourceSHA256 != input.SourceSHA256 || saved.RegistrySHA256 != registry || saved.Epoch != epoch || saved.CaptureResultSHA256 != h.record.CaptureResultSHA256 || saved.CaptureResultCipherSHA256 != recordHash(capture.Result.Cipher) || saved.CaptureResultKeyRef != capture.Result.Ref || saved.FrozenControlSHA256 != frozen || !saved.CollectorsStoppedAt.Equal(capture.Facts.CollectorsStoppedAt) || !saved.SourceResumedAt.Equal(capture.Facts.SourceResumedAt) || saved.ObservedAt.Before(saved.SourceResumedAt) {
		return ErrSourceRecoveryProofRequired
	}
	entries := []ce.RegisteredEvidence{root}
	for _, writer := range sourceRecoverySorted(p.desc.Writers) {
		entry, e := sourceRecoveryReadEntry(ctx, tx, scope, writer.ID)
		if e != nil {
			return ErrSourceRecoveryProofRequired
		}
		entries = append(entries, entry)
	}
	if count, e := sourceRecoveryFamilyCountTx(ctx, tx, scope); e != nil || count != len(entries) {
		return ErrSourceRecoveryProofRequired
	}
	if !first {
		if len(p.entries) != len(entries) {
			return ErrSourceRecoveryProofRequired
		}
		for i := range entries {
			if !bytes.Equal(entries[i].Payload, p.entries[i].Payload) || entries[i].SHA256 != p.entries[i].SHA256 {
				return ErrSourceRecoveryProofRequired
			}
		}
	}
	p.entries = entries
	if p.validateEntries() != nil || p.validateProducerLeaves() != nil || p.historicalReferencesTx(ctx, tx) != nil {
		return ErrSourceRecoveryProofRequired
	}
	facts := PublisherSourceRecoveryFacts{Scope: scope, Root: ce.EvidenceRef{PublicID: root.PublicID, SHA256: root.SHA256}, SourceSHA256: saved.SourceSHA256, PlanSHA256: saved.PlanSHA256, CaptureResultSHA256: saved.CaptureResultSHA256, FrozenControlSHA256: saved.FrozenControlSHA256, RegistrySHA256: saved.RegistrySHA256, CaptureEpoch: saved.Epoch, WriterCount: saved.WriterCount, ObservedAt: saved.ObservedAt}
	if !first && facts != h.facts {
		return ErrSourceRecoveryProofRequired
	}
	h.facts = facts
	return h.record.RecheckTx(ctx, tx, h.access)
}

func (p *PreparedSourceRecovery) historicalReferencesTx(ctx context.Context, tx *sql.Tx) error {
	for i, writer := range sourceRecoverySorted(p.desc.Writers) {
		var leaf sourceRecoveryLeaf
		if json.Unmarshal(p.entries[i+1].Payload, &leaf) != nil {
			return ErrSourceRecoveryProofRequired
		}
		var physical struct {
			Kind    string
			Runtime *SourceRecoveryRuntime
		}
		if json.Unmarshal(leaf.Facts, &physical) != nil {
			return ErrSourceRecoveryProofRequired
		}
		for _, ref := range leaf.References {
			var raw []byte
			var digest string
			switch ref.Kind {
			case "lease_epoch":
				var err error
				raw, err = p.gate.sourceRecoveryLeaseFactsTx(ctx, tx, p.a)
				if err != nil {
					return err
				}
				digest = recordHash(raw)
			case "runtime_control", "runtime_source", "gateway_binding":
				if physical.Runtime == nil || ref.Identity != writer.ID {
					return ErrSourceRecoveryProofRequired
				}
				switch ref.Kind {
				case "runtime_control":
					raw = physical.Runtime.ControlRow
				case "runtime_source":
					raw = physical.Runtime.SourceRow
				case "gateway_binding":
					raw = physical.Runtime.BindingRow
				}
				if len(raw) < 2 {
					return ErrSourceRecoveryProofRequired
				}
				digest = recordHash(raw)
			case "runtime_stop":
				if tx.QueryRowContext(ctx, "SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=? FOR SHARE", p.a.TaskPublicID, ref.Identity).Scan(&raw, &digest) != nil {
					return ErrSourceRecoveryProofRequired
				}
				var witness quiesce.ExitWitness
				var cp struct {
					Namespace string
					Process   quiesce.PodIdentity
					Pods      []quiesce.PodIdentity
				}
				if json.Unmarshal(raw, &witness) != nil || json.Unmarshal([]byte(writer.Original.Checkpoint), &cp) != nil {
					return ErrSourceRecoveryProofRequired
				}
				pods := cp.Pods
				if cp.Process.UID != "" {
					pods = []quiesce.PodIdentity{cp.Process}
				}
				found := false
				for _, pod := range pods {
					if pod.UID != ref.Identity {
						continue
					}
					found = true
					if witness.Namespace != cp.Namespace || witness.PodName != pod.Name || witness.PodUID != pod.UID || witness.Node != pod.Node || witness.NodeUID == "" || witness.ResourceVersion == "" || len(witness.Containers) != len(pod.Containers) {
						return ErrSourceRecoveryProofRequired
					}
					for _, id := range pod.Containers {
						if witness.Containers[id].IsZero() {
							return ErrSourceRecoveryProofRequired
						}
					}
				}
				if !found {
					return ErrSourceRecoveryProofRequired
				}
			case "gateway_stopped", "gateway_resumed":
				if physical.Runtime == nil || physical.Runtime.GatewayRequest == nil {
					return ErrSourceRecoveryProofRequired
				}
				req, err := gatewayBackupRequest(p.a, physical.Runtime.Spec)
				if err != nil || req != *physical.Runtime.GatewayRequest || gatewayRequestHash(req) != ref.RequestSHA256 {
					return ErrSourceRecoveryProofRequired
				}
				proof, err := readGatewayProof(ctx, tx, p.a, writer.ID, req, ref.Kind[len("gateway_"):])
				if err != nil || !services.ValidateRuntimeBackupReceipt(req, proof.Receipt) || proof.Receipt.ConfirmedAt.After(p.root.ObservedAt) {
					return ErrSourceRecoveryProofRequired
				}
				if ref.Kind == "gateway_resumed" && (proof.Receipt.PID != physical.Runtime.GatewayPID || recordHash(proof.Raw) != physical.Runtime.GatewayStateSHA256) {
					return ErrSourceRecoveryProofRequired
				}
				raw, digest = proof.Raw, recordHash(proof.Raw)
			default:
				return ErrSourceRecoveryProofRequired
			}
			if digest != ref.SHA256 || recordHash(raw) != digest {
				return ErrSourceRecoveryProofRequired
			}
		}
	}
	return nil
}
