package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

type CatalogInitialInventoryLocation struct {
	Version, EnvelopeFile, EnvelopeSHA256, DefinitionSHA256, Bucket, Key, VersionID string
}
type CatalogInitialInventoryOutput struct{ File, SHA256 string }

// This finite parser admits only a complete EMPTY version inventory. Deleted
// versions, delete markers, prefixes, pagination, duplicate/unknown fields and
// encoding/delimiter alternatives cannot masquerade as an empty scope.
func catalogInitialEmptyVersionList(raw []byte, bucket, prefix string) bool {
	if len(raw) == 0 || len(raw) > 16384 {
		return false
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	fields := map[string]string{}
	opened, closed := false, false
	for {
		token, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return false
		}
		switch v := token.(type) {
		case xml.StartElement:
			if closed {
				return false
			}
			if !opened {
				if v.Name.Local != "ListVersionsResult" || v.Name.Space != "" && v.Name.Space != "http://s3.amazonaws.com/doc/2006-03-01/" {
					return false
				}
				for _, a := range v.Attr {
					if a.Name.Local != "xmlns" || a.Value != "http://s3.amazonaws.com/doc/2006-03-01/" {
						return false
					}
				}
				opened = true
				continue
			}
			switch v.Name.Local {
			case "Name", "Prefix", "KeyMarker", "VersionIdMarker", "NextKeyMarker", "NextVersionIdMarker", "MaxKeys", "IsTruncated":
			default:
				return false
			}
			if len(v.Attr) != 0 || v.Name.Space != "" && v.Name.Space != "http://s3.amazonaws.com/doc/2006-03-01/" {
				return false
			}
			if _, ok := fields[v.Name.Local]; ok {
				return false
			}
			var value string
			for {
				t, e := d.Token()
				if e != nil {
					return false
				}
				switch x := t.(type) {
				case xml.CharData:
					value += string(x)
				case xml.EndElement:
					if x.Name != v.Name {
						return false
					}
					fields[v.Name.Local] = value
					goto next
				default:
					return false
				}
			}
		case xml.EndElement:
			if !opened || closed || v.Name.Local != "ListVersionsResult" {
				return false
			}
			closed = true
		case xml.CharData:
			if strings.TrimSpace(string(v)) != "" {
				return false
			}
		case xml.ProcInst:
			if opened || v.Target != "xml" {
				return false
			}
		default:
			return false
		}
	next:
	}
	return opened && closed && fields["Name"] == bucket && fields["Prefix"] == prefix && fields["MaxKeys"] == "1" && fields["IsTruncated"] == "false" && fields["KeyMarker"] == "" && fields["VersionIdMarker"] == "" && fields["NextKeyMarker"] == "" && fields["NextVersionIdMarker"] == ""
}

func catalogInitialReference(p *minioPermissionProductionInputs) (sec.BootstrapSecretRef, error) {
	raw, e := pinnedDeploymentFile(p.definition.ConfigFile, p.definition.ConfigSHA256, 262144)
	if e != nil {
		return sec.BootstrapSecretRef{}, e
	}
	config, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		return sec.BootstrapSecretRef{}, e
	}
	for _, ref := range config.References() {
		if ref.Purpose == "catalog_snapshot" {
			return ref, nil
		}
	}
	return sec.BootstrapSecretRef{}, install.ErrInstall
}
func catalogInitialProviderSHA(p *minioPermissionProductionInputs) string {
	raw, _ := ce.Canonical(struct {
		Provider     minioPermissionProvider
		Bucket, Root string
	}{p.grant.Provider, p.catalog.Bucket, p.catalog.Root})
	return hash(raw)
}

// Capture runs after native six-account installation and BEFORE permission
// source issuance. Original admin is used ONLY here for two bounded exact
// version lists. Its secret never enters the checkpoint/runtime descriptor.
func CaptureOriginalCatalogInitialInventory(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, definitionFile, definitionSHA string, admin MinIONativeAdminFiles, issuerPrivate []byte, directory string) (CatalogInitialInventoryOutput, error) {
	zero := CatalogInitialInventoryOutput{}
	if ctx == nil || ctx.Err() != nil || owner == nil || kube == nil || nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	issuer, e := owner.PrepareMinIOPermissionIssue(ctx, password, enrollment, definitionFile, definitionSHA)
	if e != nil {
		return zero, e
	}
	p, e := readMinIOPermissionProductionInputs(definitionFile, definitionSHA)
	if e != nil {
		return zero, e
	}
	defer p.clear()
	ctx, cancel := context.WithDeadline(ctx, p.window.until)
	defer cancel()
	ref, e := catalogInitialReference(p)
	if e != nil {
		return zero, e
	}
	if p.catalog.Root != p.grant.Installation+"/catalog/" || minioPermissionKubernetesCheck(ctx, kube, p) != nil {
		return zero, install.ErrInstall
	}
	native, e := nativeInstallAdmin(p.grant.Provider, ctx, admin)
	if e != nil {
		return zero, e
	}
	defer native.close()
	if _, e = native.collectNativeInstallServer(ctx, p.grant.Profile); e != nil {
		return zero, e
	}
	if _, e = native.bucket(ctx, p.catalog.Bucket); e != nil {
		return zero, e
	}
	// Entire original catalog root, not just known registrations. Any prior
	// version, delete marker, probe or unknown key refuses initial emptiness.
	prefix := p.catalog.Root
	var scans [2]string
	var scanBodies [2][]byte
	for i := range scans {
		raw, status, e := native.get(ctx, "/"+p.catalog.Bucket, url.Values{"versions": {""}, "prefix": {prefix}, "max-keys": {"1"}})
		if e != nil || status != 200 || !catalogInitialEmptyVersionList(raw, p.catalog.Bucket, prefix) {
			return zero, install.ErrInstall
		}
		scans[i] = hash(raw)
		scanBodies[i] = append([]byte(nil), raw...)
		if i == 0 {
			if _, e = ObserveOriginalMinIOPermissions(ctx, kube, definitionFile, definitionSHA); e != nil {
				return zero, e
			}
		}
	}
	capturedAt := time.Now().UTC().Truncate(time.Microsecond)
	if scans[0] != scans[1] || issuer.Recheck(ctx) != nil {
		return zero, install.ErrInstall
	}
	// Retain the complete native replies for original-source review. These are
	// exact empty-scope XML bodies, never MinIO admin credentials or policy data.
	if _, _, e = nativeInstallSave(directory, "catalog-initial-empty-scans.json", struct {
		Version, Endpoint, Region, Bucket, Prefix string
		Replies                                   [2][]byte
	}{"original-catalog-empty-version-list-source.v1", p.grant.Provider.Endpoint, p.grant.Provider.Region, p.catalog.Bucket, prefix, scanBodies}); e != nil {
		return zero, e
	}
	record := install.CatalogInitialInventory{Version: install.CatalogInitialInventoryVersion, Mode: "inventory_manifest_initial_checkpoint", DefinitionSHA256: definitionSHA, ConfigSHA256: p.definition.ConfigSHA256, Installation: p.grant.Installation, NamespaceUID: p.grant.NamespaceUID, Reference: ref, ProviderSHA256: catalogInitialProviderSHA(p), Bucket: p.catalog.Bucket, Root: p.catalog.Root, CoveragePrefix: prefix, Key: install.CatalogInitialInventoryKey(definitionSHA, ref, p.catalog.Root), ScanSHA256: scans[1], Count: 0, CapturedAt: capturedAt, NotBefore: p.grant.NotBefore, Until: p.window.until}
	signed, e := issuer.SignCatalogInitialInventory(ctx, record, issuerPrivate)
	if e != nil {
		return zero, e
	}
	file, sha, e := nativeInstallSave(directory, "catalog-initial-inventory.envelope.json", signed)
	return CatalogInitialInventoryOutput{file, sha}, e
}

// Publish preserves the exact previously captured/signed bytes on EVERY retry.
// It uses the original independent catalog append and read identities. A
// conflicting same key/version is never overwritten, re-signed or deleted.
func PublishOriginalCatalogInitialInventory(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, definitionFile, definitionSHA, envelopeFile, envelopeSHA string, public []byte, directory string) (CatalogInitialInventoryOutput, error) {
	zero := CatalogInitialInventoryOutput{}
	if ctx == nil || ctx.Err() != nil || owner == nil || kube == nil || nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	issuer, e := owner.PrepareMinIOPermissionIssue(ctx, password, enrollment, definitionFile, definitionSHA)
	if e != nil {
		return zero, e
	}
	p, e := readMinIOPermissionProductionInputs(definitionFile, definitionSHA)
	if e != nil {
		return zero, e
	}
	defer p.clear()
	ctx, cancel := context.WithDeadline(ctx, p.window.until)
	defer cancel()
	raw, e := pinnedDeploymentFile(envelopeFile, envelopeSHA, 4096)
	var signed install.SignedCatalogInitialInventory
	if e != nil || decodePublicationCanonical(raw, &signed) != nil {
		return zero, install.ErrInstall
	}
	record, e := install.InspectCatalogInitialInventory(signed, public)
	ref, re := catalogInitialReference(p)
	if e != nil || re != nil || record.Reference != ref || !catalogInitialMatches(record, p, definitionSHA) || !time.Now().Before(record.Until) || minioPermissionKubernetesCheck(ctx, kube, p) != nil {
		return zero, install.ErrInstall
	}
	readers := map[string]*minioPermissionHTTP{}
	defer func() {
		for _, n := range readers {
			n.close()
		}
	}()
	for _, u := range p.uses {
		if u.principal.Purpose == "catalog_read" || u.principal.Purpose == "catalog_append" {
			n, e := newMinioPermissionHTTP(p.grant.Provider, u.credential)
			if e != nil {
				return zero, e
			}
			readers[u.principal.Purpose] = n
		}
	}
	reader, writer := readers["catalog_read"], readers["catalog_append"]
	if reader == nil || writer == nil {
		return zero, install.ErrInstall
	}
	current, e := minioTerminalProbeRequest(ctx, reader, record.Bucket, record.Key, "", http.MethodGet, nil, false, "")
	if e != nil {
		return zero, e
	}
	if minioTerminalError(current, 404, "NoSuchKey", record.Key, p.grant.Provider.Region) {
		reply, e := minioTerminalProbeRequest(ctx, writer, record.Bucket, record.Key, "", http.MethodPut, raw, false, "")
		if e != nil {
			return zero, install.ErrCommitUnknown
		}
		if reply.status != 200 && reply.status != 201 && !minioTerminalError(reply, 412, "PreconditionFailed", record.Key, p.grant.Provider.Region) {
			return zero, install.ErrCommitUnknown
		}
		current, e = minioTerminalProbeRequest(ctx, reader, record.Bucket, record.Key, "", http.MethodGet, nil, false, "")
	}
	version := current.header.Get("X-Amz-Version-Id")
	if e != nil || current.status != 200 || !minioTerminalVersion(version) || !bytes.Equal(current.body, raw) {
		return zero, install.ErrCommitUnknown
	}
	for _, v := range []string{version, ""} {
		back, e := minioTerminalProbeRequest(ctx, reader, record.Bucket, record.Key, v, http.MethodGet, nil, false, "")
		if e != nil || back.status != 200 || back.header.Get("X-Amz-Version-Id") != version || !bytes.Equal(back.body, raw) {
			return zero, install.ErrCommitUnknown
		}
	}
	if issuer.Recheck(ctx) != nil {
		return zero, install.ErrCommitUnknown
	}
	if _, e = ObserveOriginalMinIOPermissions(ctx, kube, definitionFile, definitionSHA); e != nil {
		return zero, install.ErrCommitUnknown
	}
	location := CatalogInitialInventoryLocation{"original-catalog-initial-inventory-location.v1", envelopeFile, envelopeSHA, definitionSHA, record.Bucket, record.Key, version}
	file, sha, e := nativeInstallSave(directory, "catalog-initial-inventory.location.json", location)
	if e != nil {
		return zero, install.ErrCommitUnknown
	}
	return CatalogInitialInventoryOutput{file, sha}, nil
}
func catalogInitialMatches(r install.CatalogInitialInventory, p *minioPermissionProductionInputs, definitionSHA string) bool {
	return r.DefinitionSHA256 == definitionSHA && r.ConfigSHA256 == p.definition.ConfigSHA256 && r.Installation == p.grant.Installation && r.NamespaceUID == p.grant.NamespaceUID && r.ProviderSHA256 == catalogInitialProviderSHA(p) && r.Bucket == p.catalog.Bucket && r.Root == p.catalog.Root && r.NotBefore.Equal(p.grant.NotBefore) && !r.Until.After(p.window.until)
}
