package systembackupexecution

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	sec "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

const minioTerminalInputFileName = "minio-bootstrap-terminal.input.json"

// ReadMinIOBootstrapTerminalInput reads independently pinned ORIGINAL operator
// data. It accepts no HTTP/task/publisher-verifier input or serialized checks.
// Its return type is exactly the MinIO field in the enrolled v3 composition.
// It does not establish current SQL state or actual provider qualifications.
func ReadMinIOBootstrapTerminalInput(file, sha string) (MinIOBootstrapTerminalInput, error) {
	var input MinIOBootstrapTerminalInput
	raw, e := install.ReadPrivateFile(file, 262144)
	if e != nil || !formalCandidateDigest(sha) || hash(raw) != sha || decodePublicationCanonical(raw, &input) != nil {
		return MinIOBootstrapTerminalInput{}, sec.ErrRegistrationUnavailable
	}
	return input, nil
}

func readMinioTerminalInstall(ctx context.Context, kube kubernetes.Interface, file, sha string) (*MinIOBootstrapTerminalResource, []byte, sec.OfflineBootstrapGrant, sec.BootstrapConfig, error) {
	bad := func() (*MinIOBootstrapTerminalResource, []byte, sec.OfflineBootstrapGrant, sec.BootstrapConfig, error) {
		return nil, nil, sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}, sec.ErrRegistrationUnavailable
	}
	if ctx == nil || ctx.Err() != nil {
		return bad()
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return bad()
	}
	input, e := ReadMinIOBootstrapTerminalInput(file, sha)
	if e != nil {
		return bad()
	}
	resource, e := NewMinIOBootstrapTerminalResource(kube, input)
	if e != nil {
		return bad()
	}
	bundle, e := pinnedDeploymentFile(input.BundleFile, input.BundleSHA256, 1<<20)
	if e != nil {
		return bad()
	}
	grant, _, _, e := sec.ReadBootstrapGrantFile(input.GrantFile, input.GrantSHA256)
	if e != nil {
		return bad()
	}
	raw, e := pinnedDeploymentFile(input.DefinitionFile, input.DefinitionSHA256, 262144)
	if e != nil {
		return bad()
	}
	definition, e := install.DecodeMinIOPermissionDefinition(raw, input.DefinitionSHA256)
	if e != nil {
		return bad()
	}
	raw, e = pinnedDeploymentFile(definition.ConfigFile, definition.ConfigSHA256, 262144)
	if e != nil {
		return bad()
	}
	config, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		return bad()
	}
	return resource, bundle, grant, config, nil
}

func (r *MinIOBootstrapTerminalResource) qualifyInstallation(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (*minioBootstrapTerminalCheck, time.Time, error) {
	check, e := r.PrepareTerminalResource(ctx, grant, config)
	if e != nil {
		return nil, time.Time{}, sec.ErrRegistrationUnavailable
	}
	actual, ok := check.(*minioBootstrapTerminalCheck)
	if !ok || actual.origin != actual || actual.DependencyDeadline() == nil {
		return nil, time.Time{}, sec.ErrRegistrationUnavailable
	}
	until, e := actual.DependencyDeadline().Time()
	if e != nil || !time.Now().Before(until) {
		return nil, time.Time{}, sec.ErrRegistrationUnavailable
	}
	return actual, until, nil
}

// ImportOriginalMinIOTerminalAuthority performs REAL taskless native protocol
// qualification outside locks, then calls the existing original seven-row
// installer. The ORIGINAL private observation deadline bounds the entire SQL
// operation; signing/permission creation/future tasks are not hidden here.
// Result is metadata only. Runtime candidate Prepare/L2 remain mandatory.
func ImportOriginalMinIOTerminalAuthority(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, file, sha string) (install.MinIOSQLReceipt, error) {
	zero := install.MinIOSQLReceipt{}
	if owner == nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	resource, bundle, grant, config, e := readMinioTerminalInstall(ctx, kube, file, sha)
	if e != nil {
		return zero, e
	}
	if e = owner.AuthorizeMinIOSQLInstallation(ctx, password, enrollment, resource.input.Pin, bundle, resource.input.BundleSHA256); e != nil {
		return zero, e
	}
	_, until, e := resource.qualifyInstallation(ctx, grant, config)
	if e != nil {
		return zero, e
	}
	active, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if _, e = ReadMinIOBootstrapTerminalInput(file, sha); e != nil {
		return zero, e
	}
	receipt, e := owner.ImportMinIOSQLAuthority(active, password, enrollment, resource.input.Pin, bundle, resource.input.BundleSHA256)
	if e != nil {
		return zero, e
	}
	if receipt.State != ma.StateActive || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	// Independent actual current tuple after the commit. Never issue/sign again
	// on uncertainty: retain the same bundle for the metadata-only resolve CLI.
	again, e := owner.ResolveMinIOSQLAuthority(active, password, enrollment, resource.input.Pin, bundle, resource.input.BundleSHA256)
	if e != nil || again.State != ma.StateActive || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	return receipt, nil
}

// This receipt inventories inert source bytes and actual reserved probe
// coordinates. It is NOT a candidate admission or a reusable physical proof.
type MinIOBootstrapTerminalExport struct {
	Version, File, SHA256, BindingSHA256 string
	Metadata                             install.MinIOSQLReceipt
	ProbeInventory                       []MinIOBootstrapProbeObject
}

// ExportOriginalMinIOTerminalInput requires the original authenticated current
// seven-row SQL tuple, actual fresh permission/protocol probes and current SQL
// tails. Every bootstrap use must still instantiate the SAME concrete owner,
// prepare a NEW private observation and check current revocation in its own
// original candidate transaction. No active configuration is needed here.
func ExportOriginalMinIOTerminalInput(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, file, sha, directory string) (MinIOBootstrapTerminalExport, error) {
	zero := MinIOBootstrapTerminalExport{}
	if owner == nil || minioTerminalOutputDirectory(directory) != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	resource, bundle, grant, config, e := readMinioTerminalInstall(ctx, kube, file, sha)
	if e != nil {
		return zero, e
	}
	if _, e = owner.ResolveMinIOSQLAuthority(ctx, password, enrollment, resource.input.Pin, bundle, resource.input.BundleSHA256); e != nil {
		return zero, e
	}
	check, until, e := resource.qualifyInstallation(ctx, grant, config)
	if e != nil {
		return zero, e
	}
	active, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	receipt, e := owner.ResolveMinIOSQLAuthority(active, password, enrollment, resource.input.Pin, bundle, resource.input.BundleSHA256)
	if e != nil || receipt.State != ma.StateActive || active.Err() != nil || !time.Now().Before(until) {
		return zero, sec.ErrRegistrationUnavailable
	}
	if _, e = ReadMinIOBootstrapTerminalInput(file, sha); e != nil {
		return zero, e
	}
	raw, e := ce.Canonical(resource.input)
	if e != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	if e = writeMinioTerminalInput(directory, raw); e != nil {
		return zero, e
	}
	// A source may have been written when a tail/acknowledgement is lost. Do
	// not claim success or overwrite it; inspect the retained exact source and
	// current original tuple independently. Runtime L2 always rereads SQL.
	receipt, e = owner.ResolveMinIOSQLAuthority(active, password, enrollment, resource.input.Pin, bundle, resource.input.BundleSHA256)
	if e != nil || receipt.State != ma.StateActive || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	path := filepath.Join(directory, minioTerminalInputFileName)
	exported, e := ReadMinIOBootstrapTerminalInput(path, hash(raw))
	if e != nil {
		return zero, install.ErrCommitUnknown
	}
	binding, e := resource.BindingSHA256()
	if e != nil || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	loaded, e := NewMinIOBootstrapTerminalResource(kube, exported)
	if e != nil {
		return zero, install.ErrCommitUnknown
	}
	loadedBinding, e := loaded.BindingSHA256()
	if e != nil || loadedBinding != binding || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	return MinIOBootstrapTerminalExport{Version: "original-minio-terminal-input-export.v1", File: path, SHA256: hash(raw), BindingSHA256: binding, Metadata: receipt, ProbeInventory: check.ProbeInventory()}, nil
}

func minioTerminalOutputDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return sec.ErrRegistrationUnavailable
	}
	st, e := os.Lstat(directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return sec.ErrRegistrationUnavailable
	}
	if _, e = os.Lstat(filepath.Join(directory, minioTerminalInputFileName)); !os.IsNotExist(e) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

func writeMinioTerminalInput(directory string, raw []byte) error {
	if minioTerminalOutputDirectory(directory) != nil {
		return sec.ErrRegistrationUnavailable
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return sec.ErrRegistrationUnavailable
	}
	defer root.Close()
	f, e := root.OpenFile(minioTerminalInputFileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return sec.ErrRegistrationUnavailable
	}
	original, e := f.Stat()
	if e != nil {
		_ = f.Close()
		return sec.ErrRegistrationUnavailable
	}
	complete := false
	defer func() {
		if !complete {
			if current, e := root.Lstat(minioTerminalInputFileName); e == nil && os.SameFile(original, current) {
				_ = root.Remove(minioTerminalInputFileName)
			}
		}
	}()
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = sec.ErrRegistrationUnavailable
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil || closed != nil {
		return sec.ErrRegistrationUnavailable
	}
	complete = true
	return nil
}
