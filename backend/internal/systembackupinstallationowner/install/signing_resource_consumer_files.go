package install

import (
	"context"
	"path/filepath"

	owner "clawreef/internal/systembackupinstallationowner"
)

const SigningResourceConsumerVersion = "original-signing-resource-consumer-files.v1"
const SigningResourceSQLFilesVersion = "original-signing-resource-sql-files.v1"
const SigningResourceConsumerAssetsVersion = "original-signing-resource-consumer-assets.v1"

// Closed offline file locators, not approvals, a task or publisher DTO.
// The installer independently authenticates every pin against its plan/owner.
type SigningResourceSQLFiles struct {
	Version string
	Items   []SigningResourceSQLFile
}
type SigningResourceSQLFile struct {
	PinFile, PinSHA256, BundleFile, BundleSHA256 string
}
type SigningResourceConsumerAsset struct {
	Purpose                      string
	Material                     owner.SigningResourceMaterial
	ObserverFile, ObserverSHA256 string
}
type SigningResourceConsumerAssets struct {
	Version string
	Items   []SigningResourceConsumerAsset
}
type SigningResourceConsumerItem struct {
	PinFile, PinSHA256, RecordFile, SignatureFile string
	Asset                                         SigningResourceConsumerAsset
}
type SigningResourceConsumerFiles struct {
	Version                                string
	PlanFile, PlanSHA256                   string
	IssuerPublicFile, IssuerPublicSHA256   string
	EnrollmentPinFile, EnrollmentPinSHA256 string
	KubeconfigFile, KubeconfigSHA256       string
	Items                                  []SigningResourceConsumerItem
}

func signingResourcePinnedJSON(file, sha string, out any) error {
	raw, err := ReadPrivateFile(file, 262144)
	if err != nil || !digestPattern.MatchString(sha) || hash(raw) != sha || decodeExact(raw, out) != nil {
		return ErrInstall
	}
	return nil
}

// LoadSigningResourceSQLInputs loads inert original signed transport only.
// It cannot authenticate an administrator/enrollment or mutate SQL authority.
func LoadSigningResourceSQLInputs(file, sha string) ([]SigningResourceSQLInput, error) {
	var document SigningResourceSQLFiles
	if signingResourcePinnedJSON(file, sha, &document) != nil || document.Version != SigningResourceSQLFilesVersion || len(document.Items) < 1 || len(document.Items) > 2 {
		return nil, ErrInstall
	}
	inputs := make([]SigningResourceSQLInput, 0, len(document.Items))
	seen := map[string]bool{}
	for _, item := range document.Items {
		var pin owner.SigningResourceTrustPin
		if signingResourcePinnedJSON(item.PinFile, item.PinSHA256, &pin) != nil || seen[pin.Purpose] {
			return nil, ErrInstall
		}
		seen[pin.Purpose] = true
		raw, err := ReadPrivateFile(item.BundleFile, 262144)
		if err != nil {
			return nil, ErrInstall
		}
		if _, err := DecodeSigningResourceBundle(raw, item.BundleSHA256, pin); err != nil {
			return nil, ErrInstall
		}
		inputs = append(inputs, SigningResourceSQLInput{Pin: pin, Bundle: raw, SHA256: item.BundleSHA256})
	}
	return inputs, nil
}

func LoadSigningResourceConsumerAssets(file, sha string) ([]SigningResourceConsumerAsset, error) {
	var document SigningResourceConsumerAssets
	if signingResourcePinnedJSON(file, sha, &document) != nil || document.Version != SigningResourceConsumerAssetsVersion || len(document.Items) != 2 {
		return nil, ErrInstall
	}
	for n, item := range document.Items {
		if item.Purpose != owner.SigningResourcePurposes()[n] || !digestPattern.MatchString(item.ObserverSHA256) {
			return nil, ErrInstall
		}
	}
	return document.Items, nil
}

// Preflight the exact fixed export names before authentication/provider work.
// It reserves no permission and never creates/overwrites any file.
func CheckNewSigningResourceConsumerDirectory(directory string) error {
	if privateDirectory(directory) != nil {
		return ErrInstall
	}
	root, err := openSigningResourceOutput(directory)
	if err != nil {
		return err
	}
	return root.Close()
}

// readSigningResourceAsset performs only pinned local reads and the existing
// public signing-material signature/mapping check; no provider request.
func readSigningResourceAsset(ctx context.Context, asset SigningResourceConsumerAsset, grant owner.SigningResourceGrant) (observerDocument, error) {
	var doc observerDocument
	if asset.Purpose != grant.Binding.Purpose || signingResourcePinnedJSON(asset.ObserverFile, asset.ObserverSHA256, &doc) != nil || owner.CheckSigningResourceMaterial(ctx, asset.Material, grant) != nil {
		return doc, ErrInstall
	}
	ca, err := ReadPrivateFile(doc.CAFile, 65536)
	if err != nil || hash(ca) != doc.CASHA256 || doc.Endpoint != grant.Binding.Endpoint || doc.CASHA256 != grant.Binding.CASHA256 {
		return doc, ErrInstall
	}
	for _, path := range []string{asset.Material.Files.RecordFile, asset.Material.Files.SignatureFile, doc.RuntimeJWTFile, doc.ObserverTokenFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return doc, ErrInstall
		}
	}
	return doc, nil
}
