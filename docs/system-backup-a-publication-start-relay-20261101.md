# Original publication start and authenticated result reception

This work follows material commit `05040bee78f3f36e514111287d153833de4e1f64`.
The first-forward assembly files remain separate WIP. No formal six-domain
manifest, final publication, cleanup, acceptance, catalog or terminal outcome is
provided by this start/result transport alone.

Fresh original 121 creation stays suspended. The original immutable Secret is
bound to the actual Job UID before original 107 reception is registered. The
107 identity reference names that actual Secret and UID; its version is the
actual leaf certificate DER hash, with the original fixed material deadline.
An immutable original evidence intent records the Job's original UID, spec,
resourceVersion and before/after generation. The intent and 107 row commit in
one transaction with the original publish attempt's preparing-to-running CAS,
before a single JSON patch tests UID, resourceVersion,
generation and suspend=true, then replaces suspend with false. No original
owner generation, request/grant/private bytes or deadline is rewritten.
Current running status and its original start timestamp remain required on
reopen/reception; an independently failed publish attempt cannot be reused.
The two new metadata costs reserve capacity separately, each within the
unchanged 8 KiB inline bound and existing physical-report freshness rules.

Unknown SQL or native patch ACK permits GET only. A still-suspended Job stays
unknown without another patch. A started Job must match the original activation
and original 107 generation exactly. An unjournaled generation change, UID or
namespace replacement, spec drift or resuspension fails. Native I/O occurs
outside SQL transactions; current authority is checked around those operations.
The full original 121 coordinates and activation/107 are reread after Job GET.

The production Job projects request, target CA, finite upload grants and mTLS
identity from the same immutable original Secret. It creates no second request
ConfigMap. An explicit audience-limited bound Pod token is projected while
automatic token mounting stays disabled. Only original individual ciphertext
files are mounted read-only. No source grant, DEK, KMS material or artifact
signer is passed to the worker. The generated controller RBAC/readiness adds
only jobs patch in the dedicated namespace when publication is configured.

The dedicated `/publication-result` endpoint uses the existing TLS listener but
the separately configured upload SA. Every message requires real verified mTLS,
fresh TokenReview/SA/Pod identity, the original Secret leaf, original 121/107,
the actual active Job generation and Pod owner/template. Original immutable
evidence supplies the actual claim receipt; message fields never manufacture a
current owner/row-version token. Capture runtime_resources and the 107 command
slot are not used for publish.

One bounded canonical message carries one original object/candidate key, hash,
length and opaque immutable version. Empty/null/latest versions, wrong keys,
hashes, sizes, requests, sequence gaps and conflicting duplicates are refused.
Original evidence and the original 107 cursor/progress advance atomically;
exact duplicates preserve the existing row version and evidence. A lost actual
receipt commit ACK returns unavailable and is reconciled by an exact duplicate.
These are lookup hints, not independent provider readback or artifact acceptance.

The native SQL fixture preserves all 21 existing capture observation fields
when installing the actual original 107 DDL, with binary/null-safe readback of
every field. Capture UID, generation, timestamps and cursor are not rewritten.
Original FKs/CHECKs remain enabled for all operation/receipt assertions.

Validation records (shared parent `.tools`):

- `a-publication-start-relay-packages-v2.log`: full execution/worker CLI/kube
  packages PASS 9.293/4.423/2.812s, with SQL fixture variables cleared. Includes
  actual loopback mTLS result sending plus generation/version/RBAC/Job tests.
  This earlier snapshot preceded the final attempt-status CAS.
- `a-publication-start-relay-combined-v9-attempt-cas.log`: complete final
  standalone start/reception matrix PASS 195.890s on baseline b4be078c: ten
  original SQL/native start cases 63.52s, a separate OS-process started-Job
  reopen 11.55s, and fourteen actual mTLS/TokenReview/cursor cases 117.55s.
  Includes mutable-version rejection, exact duplicates, actual Release,
  failed-attempt refusal, real old expiry and actual SQL receipt commit ACK loss.
  The new owned instance is 127.0.0.1:65298, UUID
  `9679c9da-d595-11f1-b25e-745d22085e06`, with separate credentials; no old
  instance identity pin was changed.
- `a-publication-start-relay-and-material-regression-278ee6c5.log`: PASS
  336.550s after syncing 278ee6c5. Includes the final ten-start/fourteen-receipt
  matrix and started-Job child, plus original ten suspended-121 cases 39.54s,
  two material OS-child reopens 17.42s, twelve material/ownership faults 77.35s
  and post-commit creation refusal 3.02s. All original expiry and one-send
  assertions remain enabled.
- `a-publication-start-relay-b705b86e-current-authority.log`: after syncing
  b705b86e, five targeted native SQL cases PASS 38.475s: healthy start and
  ordered reception, actual Release refusal, and failed-attempt refusal at
  both reopen and reception. This is a targeted integration check, not another
  full matrix run.
- `a-publication-start-relay-packages-final-b705b86e.log`: final full execution,
  worker CLI, kube and controller packages PASS 8.521/4.351/4.214/10.684s with
  SQL fixture variables cleared.
- Independent supervisor frozen review: complete start/OS-child/fourteen-
  receipt/version/generation combination PASS 205.753s, with full execution,
  kube and worker CLI packages PASS 8.405/4.155/4.385s. Supervisor compared all
  15 Go files with the frozen SHA256 inventory and reported exact matches.
  Logs: `supervisor-a-start-relay-native-frozen.log` and
  `supervisor-a-start-relay-full-packages.log`.
- `a-publication-start-and-relay-current.log`: the attempted original SQL run
  failed during initial production DDL/seed after a connection timeout; later
  cases failed the existing server UUID read guard. Their native start, child
  reopen and authenticated cursor assertions were not reached. The independent
  mTLS sender and part/candidate version checks in that run passed.
- Ordinary process visibility and an approved native mysql.exe read-only probe
  could not reach 59355. This does not prove UUID drift. The UUID file read by A
  was the old workspace `.tools/mysql-local/data/auto.cnf`, not the Temp runtime
  datadir. A did not restart, initialize, copy an identity file or change pins.
  The supervisor subsequently retrieved the original server-session exit:
  missing InnoDB redo files and failed redo creation caused a fatal exit. A
  separate persistent fixture is being prepared with its own actual identity;
  this is not recovery or replacement of the old instance's identity.

The expiry case first requires a real
healthy receipt/cursor on the same TLS connection, waits the original deadline,
then requires actual HTTP403 with unchanged cursor/evidence. Any connection
error fails that test; infrastructure failures cannot stand in for expiry.

Formal first-forward dispatch, full six-domain manifest/index construction,
independent fixed-version provider readback and finalization remain separate
work. In particular, a formal asynchronous caller must retain its actual claim
while receiving; returning and releasing immediately after Job start would
invalidate the original receipt. No current claim is synthesized from SQL.
