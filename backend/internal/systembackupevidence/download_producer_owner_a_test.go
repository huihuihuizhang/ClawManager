package systembackupevidence

import (
	"context"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Call only before admission. Reverify the SAME signed header at the sampled
// SQL time so the strict transport oracle expects the new acceptance time.
// Signed auth_time/expiry and all original material limits remain unchanged.
func sampleAAdmissionProofTime(f *admissionTxFixture, now time.Time) error {
	f.db.now, f.env.cfg.Now = now, now
	proof, err := VerifySensitiveDownloadRequestHeader(f.env.actor, f.initial.Manifest, f.request.Header, f.env.Issuer(), f.env.cfg)
	if err != nil {
		return err
	}
	f.db.proof, f.db.m.f.Proof = proof, proof
	return nil
}

// Mutate well-formed, rehashed original producer facts after a successful
// admission. A syntactically valid replacement must not keep authorizing the
// committed request, or release its claim through an independent result write.
func TestAProducerDownloadChangedOriginalAfterCommit(t *testing.T) {
	for _, mode := range []string{"unchanged", "receipt_manifest", "receipt_version", "receipt_grant", "owner_deadline"} {
		t.Run(mode, func(t *testing.T) {
			f, authority, owners, model := producerDownloadFixture(t)
			receipt := producerDownloadReceipt(t, model)
			model.store(t, &receipt)
			var err error
			f.service, err = NewDownloadAdmissionService(owners.Registry(), f.secret, &producerOwnerTestEnvironment{f.env, owners})
			if err != nil {
				t.Fatal(err)
			}
			// Sample the synthetic SQL clock at each new transaction, while
			// freezing all original proof/material/claim limits at admission.
			// This test targets changed bindings, rather than a short lease.
			clock := func() { f.db.now = time.Now().UTC().Truncate(time.Microsecond) }
			clock()
			if err = sampleAAdmissionProofTime(f, f.db.now); err != nil {
				t.Fatal("resample original signed proof", err)
			}
			// The expected nonce row uses this acceptance sample too, while the
			// signed auth_time/expiry and all original limits remain unchanged.
			f.db.proof, err = VerifySensitiveDownloadRequestHeader(f.env.actor, f.initial.Manifest, f.request.Header, f.env.Issuer(), f.env.cfg)
			if err != nil {
				t.Fatal("sampled original proof", err)
			}
			f.db.m.f.Proof = f.db.proof
			f.env.reservationUntil = f.db.now.Add(20 * time.Second)
			committed, err := f.service.Admit(f.request)
			if err != nil {
				t.Fatal("original admission", err)
			}
			ctx := bindCommittedFixture(t, authority, committed)
			clock()
			if err = authority.CheckCommittedDownload(ctx, committed); err != nil {
				t.Fatal("original committed authorization", err)
			}
			switch mode {
			case "receipt_manifest":
				receipt.Request.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
			case "receipt_version":
				version := pd.Text("replacement-version")
				receipt.Request.Evidence.ImmutableVersion = &version
			case "receipt_grant":
				receipt.Request.GrantGeneration = "99"
			case "owner_deadline":
				model.history.OwnerWriteExpiresAt = systemExecutionStamp(f.initial.OwnerDeadline.Add(-time.Microsecond))
				model.run.OwnerWriteExpiresAt = model.history.OwnerWriteExpiresAt
				model.store(t, &model.history)
				model.store(t, &model.run)
			}
			digests, err := pd.ResultHashes(receipt.Request)
			if err != nil {
				t.Fatal("replacement is not a valid producer request", err)
			}
			receipt.ReceiptKeyHash, receipt.RequestHash = digests.Key, digests.Request
			model.store(t, &receipt)
			clock()
			err = authority.CheckCommittedDownload(ctx, committed)
			if (err == nil) != (mode == "unchanged") {
				t.Fatal("committed authority ignored original binding", mode, err)
			}
			results := resultFixture(t, f)
			results.c.Registry, results.c.Owners = owners.Registry(), owners
			f.db.sessionRevoked, f.db.userActive = true, false
			// Successful SQL authorization also commits its read transaction.
			// Count only this independent result's additional commit.
			beforeResultCommits := f.db.commits
			clock()
			err = results.Finish(context.Background(), committed, DownloadResultObservation{Outcome: "interrupted"})
			if mode == "unchanged" {
				if err != nil || f.db.commits != beforeResultCommits+1 || f.db.resultInserts != 1 || f.db.record.Claim != "" {
					t.Fatal("unchanged result after revocation", err)
				}
			} else if err == nil || f.db.commits != beforeResultCommits || f.db.resultInserts != 0 || f.db.record.Claim != committed.record.Claim {
				t.Fatal("changed owner allowed result commit or claim release", mode, err)
			}
		})
	}
}
