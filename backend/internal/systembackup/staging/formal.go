package staging

import (
	"context"
	"io"
	"os"

	w "clawreef/internal/systembackupwire"
)

// FormalObservation binds both exact durable ciphertext versions. It can only
// be returned after the original envelope and every AEAD frame verify through
// an independently supplied Unwrapper; it is still not final publication.
type FormalObservation struct{ ciphertext, envelope Observation }

func (o FormalObservation) Reference() string {
	if o.ciphertext.reference == "" || o.envelope.reference == "" {
		return ""
	}
	return "controller-formal-seal.v1/" + o.ciphertext.receipt.Name + "/" + o.envelope.receipt.Name
}
func (o FormalObservation) Ciphertext() Receipt { return o.ciphertext.receipt }
func (o FormalObservation) Envelope() Receipt   { return o.envelope.receipt }

func formalEnvelopeScope(scope SealScope) SealScope { scope.Unit += "/formal-envelope"; return scope }

type FormalFiles struct{ Ciphertext, Envelope *os.File }

func (f FormalFiles) Close() {
	if f.Ciphertext != nil {
		f.Ciphertext.Close()
	}
	if f.Envelope != nil {
		f.Envelope.Close()
	}
}

// OpenFormalObserved rehashes both ORIGINAL private copies. It never consults
// a worker mount as fallback. Authentication/publication remain separate.
func OpenFormalObserved(ctx context.Context, custody *os.Root, scope SealScope, ciphertext, envelope Receipt) (FormalFiles, FormalObservation, error) {
	var files FormalFiles
	var observation FormalObservation
	f, c, err := OpenObserved(ctx, custody, scope, ciphertext)
	if err != nil {
		return files, observation, err
	}
	files.Ciphertext = f
	f, e, err := OpenObserved(ctx, custody, formalEnvelopeScope(scope), envelope)
	if err != nil {
		files.Close()
		return FormalFiles{}, observation, err
	}
	files.Envelope = f
	observation = FormalObservation{c, e}
	return files, observation, nil
}

// ObserveFormalManaged retains the original CMBKGC01 format and provider key
// binding; it never tries CMSTG01 or a functional key on any failure. The same
// lock, intent, capacity and create-only mechanics protect both private copies.
func ObserveFormalManaged(ctx context.Context, source, custody *os.Root, p CustodyPolicy, scope SealScope, ciphertext, envelope Receipt, spec w.StreamSpec, keys w.Unwrapper) (FormalObservation, error) {
	var zero FormalObservation
	if keys == nil || envelope.Size > 32<<20 || scope.Binding.BackupID != spec.Request.Context.BackupPublicID || scope.Binding.Attempt != spec.Request.Context.AttemptNo || scope.Binding.Path != spec.Request.Context.Part || scope.Binding.CaptureContextHash != spec.Request.Context.CaptureContextHash || scope.Binding.EnvelopeID != spec.Request.Context.EnvelopeID || scope.Installation != spec.Request.Context.InstallationID {
		return zero, ErrFile
	}
	_, err := observeManaged(ctx, source, custody, p, formalEnvelopeScope(scope), envelope, func() (Observation, error) {
		return observeAuthenticatedFile(ctx, source, custody, formalEnvelopeScope(scope), envelope, 32<<20, func(reader io.Reader) error {
			raw, err := io.ReadAll(io.LimitReader(reader, 32<<20+1))
			if err != nil || len(raw) > 32<<20 {
				return ErrFile
			}
			_, err = w.ParseStreamEnvelope(spec, raw)
			return err
		})
	})
	if err != nil {
		return zero, err
	}
	_, err = observeManaged(ctx, source, custody, p, scope, ciphertext, func() (Observation, error) {
		return observeAuthenticatedFile(ctx, source, custody, scope, ciphertext, spec.MaxPlaintextBytes+int64(spec.MaxFrames)*57, func(reader io.Reader) error {
			f, _, err := OpenObserved(ctx, custody, formalEnvelopeScope(scope), envelope)
			if err != nil {
				return err
			}
			defer f.Close()
			raw, err := io.ReadAll(io.LimitReader(f, 32<<20+1))
			if err != nil || len(raw) > 32<<20 {
				return ErrFile
			}
			verified, err := w.VerifyWrappedStream(ctx, spec, raw, reader, keys)
			if err != nil {
				return err
			}
			if verified.CiphertextSHA256() != ciphertext.SHA256 || verified.CiphertextBytes() != ciphertext.Size {
				return ErrFile
			}
			return nil
		})
	})
	if err != nil {
		return zero, err
	}
	files, observed, err := OpenFormalObserved(ctx, custody, scope, ciphertext, envelope)
	files.Close()
	return observed, err
}
