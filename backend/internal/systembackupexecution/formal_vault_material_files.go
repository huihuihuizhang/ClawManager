package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"

	owner "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Init-only transport copy from the producer's immutable Secret projection.
// No network, original credentials, enrollment, task or permission is created.
// Runtime reads exclusively owner-private regular files, never Secret symlinks.
func InstallFormalVaultDependencyFiles(ctx context.Context, observerSHA, tokenSHA string) error {
	if ctx == nil || ctx.Err() != nil || len(observerSHA) != 64 || len(tokenSHA) != 64 {
		return install.ErrInstall
	}
	read := func(name, sha string, max int64) ([]byte, error) {
		f, e := os.Open("/input/" + name)
		if e != nil {
			return nil, install.ErrInstall
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max {
			return nil, install.ErrInstall
		}
		raw, e := io.ReadAll(io.LimitReader(f, max+1))
		if e != nil || int64(len(raw)) != st.Size() || hash(raw) != sha {
			clear(raw)
			return nil, install.ErrInstall
		}
		return raw, nil
	}
	raw, e := read("observer.json", observerSHA, 262144)
	if e != nil {
		return install.ErrInstall
	}
	var cfg owner.InstalledVaultDependencyConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(new(any)) != io.EOF || cfg.IdentityMode != "metadata-only" || cfg.TokenSHA256 != tokenSHA || cfg.TokenFile != formalVaultDependencyMount+"/token" {
		return install.ErrInstall
	}
	token, e := read("token", tokenSHA, 16384)
	if e != nil {
		return install.ErrInstall
	}
	defer clear(token)
	if len(token) < 16 {
		return install.ErrInstall
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return install.ErrInstall
		}
	}
	if os.Mkdir("/output/private", 0700) != nil {
		return install.ErrInstall
	}
	root, e := os.OpenRoot("/output/private")
	if e != nil {
		return install.ErrInstall
	}
	defer root.Close()
	for name, body := range map[string][]byte{"token": token, "observer.json": raw} {
		if ctx.Err() != nil {
			return install.ErrInstall
		}
		f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return install.ErrInstall
		}
		n, e := f.Write(body)
		if e == nil && n != len(body) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = f.Sync()
		}
		closed := f.Close()
		if e != nil || closed != nil {
			return install.ErrInstall
		}
		actual, e := install.ReadPrivateFile("/output/private/"+name, 262144)
		same := e == nil && bytes.Equal(actual, body)
		clear(actual)
		if !same {
			return install.ErrInstall
		}
	}
	return ctx.Err()
}
