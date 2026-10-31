package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Actual current publisher, original 104 DDL/FKs/CHECKs and private owner key.
// This tests only inert candidate INTENT creation, with zero provider/Job IO;
// it is not six-domain preparation, provider permission or publication success.
func TestPublicationCandidateUsesOriginal104BeforeOwnerKeyMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"exact-retry", "creating-ack-lost", "owner-key-lost", "request-drift", "root-alias", "released-claim", "owner-hmac-drift"} {
		t.Run(mode, func(t *testing.T) {
			boundary := &aStageCommitBoundary{}
			store, state := newANativePublicationStore(t, time.Minute)
			defer store.Close()
			store.config.RemoteStagingRoot = "remote-staging/installation_test/"
			x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{FullService: true, PublicationTarget: &store.config, WrapControlConnector: func(inner driver.Connector) driver.Connector {
				return aStageBoundaryConnector{Connector: inner, boundary: boundary}
			}})
			aStartPublisherVerifierSamePod(t, x)
			aUseActualPublicationDDL(t, x, store.config)
			h, ctx := x.history, context.Background()
			h.service.staging = h.owner.Staging
			indexSHA := hash([]byte("candidate intent index DATA"))
			p := PublicationUploadRequest{Version: publicationUploadVersion, Installation: h.original.InstallationID, Backup: h.original.TaskPublicID, Attempt: h.original.AttemptNo, Endpoint: store.config.Endpoint, Region: store.config.Region, Bucket: store.config.Bucket, ArtifactRoot: store.config.Root, RemoteStagingRoot: store.config.RemoteStagingRoot, CAHash: store.config.CASHA256, CredentialHash: strings.Repeat("f", 64), Deadline: h.original.DeadlineAt.Add(-time.Second), Objects: []PublicationUploadInput{{Path: "parts/original.enc", SHA256: hash([]byte("inert original C locator")), Bytes: 24}, {Path: "artifact-index.json", SHA256: indexSHA, Bytes: 27}}}
			p.ManifestInput = []byte(`{"schema_version":"system-backup.v1","origin_installation_id":"` + p.Installation + `","backup_public_id":"` + p.Backup + `","attempt_no":` + strconv.FormatUint(p.Attempt, 10) + `,"artifact_index":{"path":"artifact-index.json","checksum":"` + indexSHA + `"}}`)
			countRows := func() int {
				t.Helper()
				var count int
				if e := h.admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_staging_resources WHERE backup_public_id=? AND phase='publish'", p.Backup).Scan(&count); e != nil {
					t.Fatal(e)
				}
				return count
			}
			if mode == "root-alias" {
				p.RemoteStagingRoot = p.ArtifactRoot
			}
			if mode == "released-claim" {
				if _, e := (c.ClaimCoordinator{Executor: h.admin, InstallationID: p.Installation}).Release(ctx, h.token, time.Second); e != nil {
					t.Fatal(e)
				}
				var owner sql.NullString
				var version uint64
				if h.admin.QueryRow("SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?", p.Backup).Scan(&owner, &version) != nil || owner.Valid || version <= h.token.RowVersion {
					t.Fatal("actual claim release did not occur")
				}
			}
			if mode == "creating-ack-lost" {
				boundary.arm("creating", func() error {
					var keyVersion, lifecycle string
					if e := h.admin.QueryRow("SELECT owner_marker_key_version,lifecycle FROM system_backup_v2_staging_resources WHERE backup_public_id=? AND phase='publish'", p.Backup).Scan(&keyVersion, &lifecycle); e != nil || lifecycle != "creating" {
						t.Fatal("original 104 did not actually commit", lifecycle, e)
					}
					keys, e := stageKeyRoot(h.owner.Staging, false)
					if e != nil {
						t.Fatal(e)
					}
					defer keys.Close()
					if _, e = keys.Lstat(keyVersion + ".key"); !errors.Is(e, os.ErrNotExist) {
						t.Fatal("candidate key preceded acknowledged creating intent", e)
					}
					return errAPublicationACKLost
				})
			}
			aRefreshPublicationPayloadCapacity(t, x)
			first, err := h.service.beginPublicationCandidate(ctx, h.token, p.Attempt, store.config, p)
			if mode == "root-alias" || mode == "released-claim" {
				if err == nil || countRows() != 0 {
					t.Fatal("unowned/aliased candidate intent accepted", err)
				}
				return
			}
			if mode == "creating-ack-lost" {
				if !errors.Is(err, c.ErrExecutionCommitUnknown) || countRows() != 1 {
					t.Fatal("actual committed candidate ACK was not lost", err)
				}
				boundary.arm("", nil)
				if _, e := h.service.beginPublicationCandidate(ctx, h.token, p.Attempt, store.config, p); e == nil {
					t.Fatal("unknown creating commit regenerated key/adopted resource")
				}
			} else {
				if err != nil || first.Lifecycle != "creating" || first.RowVersion != 1 || countRows() != 1 {
					t.Fatal("original candidate creating intent", first, err)
				}
				if mode == "owner-key-lost" {
					keys, e := stageKeyRoot(h.owner.Staging, false)
					if e != nil {
						t.Fatal(e)
					}
					e = keys.Remove(first.owner.KeyVersion + ".key")
					keys.Close()
					if e != nil {
						t.Fatal(e)
					}
				}
				if mode == "request-drift" {
					p.Deadline = p.Deadline.Add(-time.Second)
				}
				p.CandidateOwnerHMAC = first.MAC
				if mode == "owner-hmac-drift" {
					p.CandidateOwnerHMAC = strings.Repeat("e", 64)
				}
				second, e := h.service.beginPublicationCandidate(ctx, h.token, p.Attempt, store.config, p)
				if mode == "exact-retry" {
					if e != nil || first != second {
						t.Fatal("exact original candidate readback", e)
					}
				} else if e == nil {
					t.Fatal("candidate owner/request substitution admitted")
				}
				var lifecycle string
				var version uint64
				if h.admin.QueryRow("SELECT lifecycle,row_version FROM system_backup_v2_staging_resources WHERE public_id=?", first.owner.Resource).Scan(&lifecycle, &version) != nil || lifecycle != "creating" || version != 1 {
					t.Fatal("intent retry altered original 104 lifecycle")
				}
			}
			state.mu.Lock()
			puts, gets, heads := state.puts, state.gets, state.heads
			state.mu.Unlock()
			if puts != 0 || gets != 0 || heads != 0 {
				t.Fatal("metadata intent sent provider IO", puts, gets, heads)
			}
		})
	}
}
