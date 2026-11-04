package install

// Content-authenticated comparison inputs. No receipt boolean, image tag,
// observed Pod DTO or caller declaration can mint an original runtime peer.
import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type OriginalRuntimeStartupImageInput struct {
	BaseManifest, BaseConfig, Manifest, Config, Layer BootstrapSourceFilePin
}
type OriginalRuntimeStartupImageInputs struct {
	Version string
	Images  []OriginalRuntimeStartupImageInput
}
type originalRuntimeStartupImage struct {
	runtime, manifest, config, source string
	defaults                          map[string]string
	entrypoint, command               []string
}

func (*originalRuntimeStartupImage) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalRuntimeStartupImage) String() string               { return "OriginalRuntimeStartupImage" }
func (*originalRuntimeStartupImage) GoString() string             { return "OriginalRuntimeStartupImage" }

const originalOpenclawSelectedManifest = "730758ed3025b5a1c7fd91b14214eea1d5a50950ef3fd56012a5efb48f345769"
const originalOpenclawBaseConfig = "c9798a575acf6d1c832a268fa53a057c3d1bb42ce7bdb06f887cddf7d00fb90a"
const originalHermesSelectedManifest = "5fe79507129002540c2fbc25fc49bbd10326cb65dbc752885cfc845b2860731d"
const originalHermesBaseConfig = "4a36a2cda56406be6c4183eca5c58ac91dcceb36cb3342b7520b315c564a6c92"
const originalOpenclawGatedServiceSHA = "3649b6362025304a52897c042a3d6dc73361ee85929982d496176ce2fb424abb"
const originalOpenclawGatedManifest = "749f578ff4799789aa301e2a11e1b5bf93639121031172231c823ef5c82646e7"
const originalOpenclawSharedNativeTLSManifest = "5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140"

func originalRuntimeJSON(pin BootstrapSourceFilePin) (map[string]any, []byte, error) {
	raw, e := readBootstrapSourcePin(pin, 262144)
	if e != nil {
		return nil, nil, e
	}
	var value map[string]any
	canonical, e := jsonCanonicalOriginalRuntime(raw)
	if e != nil {
		return nil, nil, ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.UseNumber()
	if d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF {
		return nil, nil, ErrInstall
	}
	return value, raw, nil
}
func jsonCanonicalOriginalRuntime(raw []byte) ([]byte, error) {
	// Reuse the original duplicate-rejecting material DATA decoder. Unknown OCI
	// fields are retained in the map and must compare exactly to the pinned base.
	var value json.RawMessage
	if decodeOriginalWriterMaterialData(raw, &value) != nil {
		return nil, ErrInstall
	}
	return value, nil
}
func originalRuntimeMap(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil, ErrInstall
	}
	return m, nil
}
func originalRuntimeStrings(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil, ErrInstall
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, ErrInstall
		}
		out = append(out, s)
	}
	return out, nil
}
func originalRuntimeDescriptor(v any) (map[string]any, string, int64, error) {
	m, e := originalRuntimeMap(v)
	if e != nil {
		return nil, "", 0, e
	}
	digest, ok := m["digest"].(string)
	size, okSize := m["size"].(json.Number)
	n, e := size.Int64()
	if !ok || !okSize || e != nil || n <= 0 || !strings.HasPrefix(digest, "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(digest, "sha256:")) {
		return nil, "", 0, ErrInstall
	}
	return m, strings.TrimPrefix(digest, "sha256:"), n, nil
}
func originalRuntimeAgentSHA(kind, value string, size int64) bool {
	// Exact independently audited per-runtime ELF identities in the same
	// accepted legacy and shared-native TLS bundles. Neither runtime may borrow the other's executable.
	// Identity remains comparison DATA, not current mode/cap/native authority.
	switch kind {
	case "openclaw":
		return value == "63a68c0a916a5d873c420c086f81a77d7d3c3f41bd5d798428b4608db0552cc1" && size == 9994402 || value == "bc1ef9abb276594f938cb27374b0ee05c50b6d9da1424b8fe87fb64940bd0158" && size == 10076322
	case "hermes":
		return value == "851104a524ff26797c58c6a5a1e0e8172353ecdd31c31a07032a81073a225a42" && size == 10072226 || value == "be46bb0525623bb9fb7f1393a6b668d7c8f705a998c90517915751c2be9d0102" && size == 10154146
	default:
		return false
	}
}

func readOriginalRuntimeLayer(ctx context.Context, pin BootstrapSourceFilePin, kind string, size int64) (diff, agent, wrapper string, err error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(pin.File) || filepath.Clean(pin.File) != pin.File || size < 1 || size > 128<<20 {
		return "", "", "", ErrInstall
	}
	canonical, e := filepath.EvalSymlinks(pin.File)
	if e != nil || canonical != pin.File {
		return "", "", "", ErrInstall
	}
	before, e := os.Lstat(pin.File)
	if e != nil || !before.Mode().IsRegular() || before.Size() != size || runtime.GOOS == "linux" && before.Mode().Perm()&0077 != 0 {
		return "", "", "", ErrInstall
	}
	f, e := os.Open(pin.File)
	if e != nil {
		return "", "", "", ErrInstall
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return "", "", "", ErrInstall
	}
	compressed := sha256.New()
	br := bufio.NewReader(io.TeeReader(f, compressed))
	gz, e := gzip.NewReader(br)
	if e != nil {
		return "", "", "", ErrInstall
	}
	defer gz.Close()
	gz.Multistream(false)
	limited := &io.LimitedReader{R: gz, N: (256 << 20) + 1}
	plain := sha256.New()
	body := io.TeeReader(limited, plain)
	archive := tar.NewReader(body)
	seen := map[string]bool{}
	privateDirectorySeen := false
	privateDirectory := "var/lib/openclaw-agent"
	if kind == "hermes" {
		privateDirectory = "var/lib/clawmanager-agent"
	}
	for {
		if ctx.Err() != nil {
			return "", "", "", ErrInstall
		}
		h, e := archive.Next()
		if e == io.EOF {
			break
		}
		if e == nil && h != nil && h.Typeflag == tar.TypeDir {
			if privateDirectorySeen || h.Name != privateDirectory && h.Name != privateDirectory+"/" || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 || h.Linkname != "" || h.Size != 0 || h.Mode != 0700 || h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 0 || h.Uname != "" || h.Gname != "" {
				return "", "", "", ErrInstall
			}
			privateDirectorySeen = true
			continue
		}
		if e != nil || h == nil || h.Typeflag != tar.TypeReg || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 || h.Linkname != "" || h.Uid != 0 || h.Gid != 0 || h.Size < 1 || h.Size > 64<<20 || seen[h.Name] {
			return "", "", "", ErrInstall
		}
		seen[h.Name] = true
		expectedMode := int64(0555)
		switch h.Name {
		case "usr/local/bin/clawmanager-agent":
		case "etc/services.d/openclaw-agent/run":
			if kind != "openclaw" {
				return "", "", "", ErrInstall
			}
			expectedMode = 0755
		default:
			return "", "", "", ErrInstall
		}
		if h.Mode != expectedMode {
			return "", "", "", ErrInstall
		}
		sum := sha256.New()
		n, e := io.Copy(sum, archive)
		if e != nil || n != h.Size {
			return "", "", "", ErrInstall
		}
		value := hex.EncodeToString(sum.Sum(nil))
		if h.Name == "usr/local/bin/clawmanager-agent" {
			if !originalRuntimeAgentSHA(kind, value, h.Size) {
				return "", "", "", ErrInstall
			}
			agent = value
		} else {
			if value != originalOpenclawGatedServiceSHA {
				return "", "", "", ErrInstall
			}
			wrapper = value
		}
	}
	// tar EOF must be followed only by record padding, then actual gzip EOF/CRC.
	buffer := make([]byte, 32768)
	for {
		n, e := body.Read(buffer)
		for _, b := range buffer[:n] {
			if b != 0 {
				return "", "", "", ErrInstall
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil || limited.N <= 0 || ctx.Err() != nil {
			return "", "", "", ErrInstall
		}
	}
	if limited.N <= 0 || agent == "" || kind == "openclaw" && (wrapper == "" || len(seen) != 2) || kind == "hermes" && len(seen) != 1 {
		return "", "", "", ErrInstall
	}
	if _, e := br.Peek(1); !errors.Is(e, io.EOF) {
		return "", "", "", ErrInstall
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || hex.EncodeToString(compressed.Sum(nil)) != pin.SHA256 {
		return "", "", "", ErrInstall
	}
	return hex.EncodeToString(plain.Sum(nil)), agent, wrapper, nil
}

func readOriginalRuntimeImage(ctx context.Context, in OriginalRuntimeStartupImageInput) (*originalRuntimeStartupImage, error) {
	kind := ""
	switch in.BaseManifest.SHA256 {
	case originalOpenclawSelectedManifest:
		if in.BaseConfig.SHA256 != originalOpenclawBaseConfig {
			return nil, ErrInstall
		}
		kind = "openclaw"
	case originalHermesSelectedManifest:
		if in.BaseConfig.SHA256 != originalHermesBaseConfig {
			return nil, ErrInstall
		}
		kind = "hermes"
	default:
		return nil, ErrInstall
	}
	base, baseRaw, e := originalRuntimeJSON(in.BaseManifest)
	if e != nil {
		return nil, e
	}
	baseConfig, baseConfigRaw, e := originalRuntimeJSON(in.BaseConfig)
	if e != nil {
		return nil, e
	}
	next, nextRaw, e := originalRuntimeJSON(in.Manifest)
	if e != nil {
		return nil, e
	}
	config, configRaw, e := originalRuntimeJSON(in.Config)
	if e != nil {
		return nil, e
	}
	if hash(baseRaw) != in.BaseManifest.SHA256 || hash(baseConfigRaw) != in.BaseConfig.SHA256 || hash(nextRaw) != in.Manifest.SHA256 || hash(configRaw) != in.Config.SHA256 {
		return nil, ErrInstall
	}
	if kind == "openclaw" && in.Manifest.SHA256 != originalOpenclawGatedManifest && in.Manifest.SHA256 != originalOpenclawSharedNativeTLSManifest {
		return nil, ErrInstall
	}
	_, baseDigest, baseSize, e := originalRuntimeDescriptor(base["config"])
	if e != nil || baseDigest != in.BaseConfig.SHA256 || baseSize != int64(len(baseConfigRaw)) {
		return nil, ErrInstall
	}
	configDescriptor, nextDigest, nextSize, e := originalRuntimeDescriptor(next["config"])
	if e != nil || nextDigest != in.Config.SHA256 || nextSize != int64(len(configRaw)) {
		return nil, ErrInstall
	}
	oldLayers, ok := base["layers"].([]any)
	newLayers, ok2 := next["layers"].([]any)
	if !ok || !ok2 || len(oldLayers) == 0 || len(newLayers) != len(oldLayers)+1 || !reflect.DeepEqual(oldLayers, newLayers[:len(oldLayers)]) {
		return nil, ErrInstall
	}
	layerDescriptor, layerDigest, layerSize, e := originalRuntimeDescriptor(newLayers[len(newLayers)-1])
	if e != nil || layerDigest != in.Layer.SHA256 {
		return nil, ErrInstall
	}
	media, _ := layerDescriptor["mediaType"].(string)
	if media != "application/vnd.oci.image.layer.v1.tar+gzip" && media != "application/vnd.docker.image.rootfs.diff.tar.gzip" {
		return nil, ErrInstall
	}
	diff, agent, wrapper, e := readOriginalRuntimeLayer(ctx, in.Layer, kind, layerSize)
	if e != nil {
		return nil, e
	}
	// Undo only the two exact append-only changes, then compare EVERY original
	// config and manifest field, including all Env/entrypoint/Cmd/working/user.
	rootfs, e := originalRuntimeMap(config["rootfs"])
	if e != nil {
		return nil, e
	}
	oldRoot, e := originalRuntimeMap(baseConfig["rootfs"])
	if e != nil {
		return nil, e
	}
	oldDiff, ok := oldRoot["diff_ids"].([]any)
	newDiff, ok2 := rootfs["diff_ids"].([]any)
	if !ok || !ok2 || rootfs["type"] != "layers" || oldRoot["type"] != "layers" || len(oldDiff) != len(oldLayers) || len(newDiff) != len(oldDiff)+1 || newDiff[len(newDiff)-1] != "sha256:"+diff || !reflect.DeepEqual(oldDiff, newDiff[:len(oldDiff)]) {
		return nil, ErrInstall
	}
	rootfs["diff_ids"] = newDiff[:len(oldDiff)]
	if history, has := baseConfig["history"]; has {
		old, ok := history.([]any)
		current, ok2 := config["history"].([]any)
		if !ok || !ok2 || len(current) != len(old)+1 || !reflect.DeepEqual(old, current[:len(old)]) {
			return nil, ErrInstall
		}
		last, e := originalRuntimeMap(current[len(current)-1])
		if e != nil || last["empty_layer"] != false {
			return nil, ErrInstall
		}
		config["history"] = current[:len(old)]
	}
	if !reflect.DeepEqual(config, baseConfig) {
		return nil, ErrInstall
	}
	next["layers"] = newLayers[:len(oldLayers)]
	oldDescriptor, e := originalRuntimeMap(base["config"])
	if e != nil {
		return nil, e
	}
	configDescriptor["digest"] = oldDescriptor["digest"]
	configDescriptor["size"] = oldDescriptor["size"]
	if !reflect.DeepEqual(next, base) {
		return nil, ErrInstall
	}
	actual, e := originalRuntimeMap(baseConfig["config"])
	if e != nil {
		return nil, e
	}
	entry, e := originalRuntimeStrings(actual["Entrypoint"])
	if e != nil {
		return nil, e
	}
	command, e := originalRuntimeStrings(actual["Cmd"])
	if e != nil {
		return nil, e
	}
	values, e := originalRuntimeStrings(actual["Env"])
	if e != nil {
		return nil, e
	}
	defaults := map[string]string{}
	for _, raw := range values {
		k, v, found := strings.Cut(raw, "=")
		if !found || k == "" {
			return nil, ErrInstall
		}
		if _, duplicate := defaults[k]; duplicate {
			return nil, ErrInstall
		}
		defaults[k] = v
	}
	return &originalRuntimeStartupImage{runtime: kind, manifest: in.Manifest.SHA256, config: in.Config.SHA256, defaults: defaults, entrypoint: entry, command: command, source: originalObjectSHA(struct{ BaseManifest, BaseConfig, Manifest, Config, Layer, Diff, Agent, Wrapper string }{in.BaseManifest.SHA256, in.BaseConfig.SHA256, in.Manifest.SHA256, in.Config.SHA256, in.Layer.SHA256, diff, agent, wrapper})}, nil
}

func readOriginalRuntimeImageSet(ctx context.Context, inputs []OriginalRuntimeStartupImageInput) (map[string]*originalRuntimeStartupImage, error) {
	if len(inputs) > 4 {
		return nil, ErrInstall
	}
	out := map[string]*originalRuntimeStartupImage{}
	for _, in := range inputs {
		p, e := readOriginalRuntimeImage(ctx, in)
		if e != nil || out[p.manifest] != nil {
			return nil, ErrInstall
		}
		out[p.manifest] = p
	}
	return out, nil
}
func loadOriginalRuntimeImageInputs(ctx context.Context, pin BootstrapSourceFilePin) ([]OriginalRuntimeStartupImageInput, error) {
	if pin.File == "" && pin.SHA256 == "" {
		return nil, nil
	}
	raw, e := readBootstrapSourcePin(pin, 262144)
	if e != nil {
		return nil, e
	}
	var in OriginalRuntimeStartupImageInputs
	if decodeOriginalWriterMaterialData(raw, &in) != nil || in.Version != "original-runtime-startup-image-inputs.v1" || len(in.Images) < 1 {
		return nil, ErrInstall
	}
	if _, e = readOriginalRuntimeImageSet(ctx, in.Images); e != nil {
		return nil, e
	}
	return in.Images, nil
}
func originalRuntimeInputDefinitionStill(pin BootstrapSourceFilePin, expected []OriginalRuntimeStartupImageInput) error {
	if pin.File == "" && pin.SHA256 == "" {
		if len(expected) == 0 {
			return nil
		}
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(pin, 262144)
	if e != nil {
		return e
	}
	var in OriginalRuntimeStartupImageInputs
	if decodeOriginalWriterMaterialData(raw, &in) != nil || in.Version != "original-runtime-startup-image-inputs.v1" || !reflect.DeepEqual(in.Images, expected) {
		return ErrInstall
	}
	return nil
}
func originalRuntimeImageForContainer(images map[string]*originalRuntimeStartupImage, c *corev1.Container, status *corev1.ContainerStatus) *originalRuntimeStartupImage {
	if c == nil || status == nil || status.Name != c.Name || status.ContainerID == "" {
		return nil
	}
	at := strings.LastIndex(c.Image, "@sha256:")
	if at <= 0 {
		return nil
	}
	digest := c.Image[at+8:]
	p := images[digest]
	if p == nil {
		return nil
	}
	// Kubelets may report the manifest or the associated config image digest.
	value := strings.TrimPrefix(strings.TrimPrefix(status.ImageID, "docker-pullable://"), "docker://")
	if i := strings.LastIndex(value, "@sha256:"); i >= 0 {
		value = value[i+1:]
	} else if strings.HasPrefix(value, "containerd://") {
		value = strings.TrimPrefix(value, "containerd://")
	}
	if value != "sha256:"+p.manifest && value != "sha256:"+p.config {
		return nil
	}
	return p
}
