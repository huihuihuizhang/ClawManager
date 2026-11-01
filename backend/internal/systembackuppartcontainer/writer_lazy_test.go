package systembackuppartcontainer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

type trackedContainerInput struct {
	io.Reader
	closed bool
	close  func() error
}

func (f *trackedContainerInput) Close() error {
	if f.closed {
		return errors.New("double close")
	}
	f.closed = true
	return f.close()
}

func TestContainerLazyMembersBoundOpenFilesAndPreserveBytesData(t *testing.T) {
	for _, mode := range []string{"current", "open-error", "nil-file", "cipher-error", "envelope-error", "close-error", "eager-and-lazy", "invalid-checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			scope, source, eager, checkpoints, ciphers := containerData(t)
			var expected bytes.Buffer
			want, err := Write(context.Background(), &expected, scope, source, eager, checkpoints, MaxBytes, MaxIndexBytes)
			if err != nil {
				t.Fatal(err)
			}
			lazy := make([]Input, len(eager))
			active, opened, closed := 0, 0, 0
			for index, original := range eager {
				original := original
				lazy[index] = Input{Member: original.Member, Open: func(context.Context) (io.ReadCloser, []byte, error) {
					if active != 0 {
						t.Fatal("multiple C/envelopes retained simultaneously")
					}
					active++
					opened++
					file := &trackedContainerInput{Reader: bytes.NewReader(ciphers[original.Member.Part]), close: func() error {
						active--
						closed++
						if mode == "close-error" {
							return errors.New("close failed")
						}
						return nil
					}}
					if mode == "nil-file" {
						active--
						return nil, nil, nil
					}
					if mode == "open-error" {
						return file, nil, errors.New("open failed after acquiring file")
					}
					if mode == "cipher-error" {
						file.Reader = bytes.NewReader([]byte("changed C"))
					}
					envelope := bytes.Clone(original.Envelope)
					if mode == "envelope-error" {
						envelope[0] ^= 1
					}
					return file, envelope, nil
				}}
			}
			if mode == "eager-and-lazy" {
				lazy[0].Ciphertext = bytes.NewReader(ciphers[eager[0].Member.Part])
			}
			if mode == "invalid-checkpoint" {
				lazy[0].Member.Checkpoint = []byte(`{}`)
			}
			var actual bytes.Buffer
			got, err := Write(context.Background(), &actual, scope, source, lazy, checkpoints, MaxBytes, MaxIndexBytes)
			if active != 0 || (mode != "nil-file" && opened != closed) {
				t.Fatal("file leaked on exit", mode, active, opened, closed)
			}
			if mode != "current" {
				if err == nil || got.SHA256 != "" {
					t.Fatal("failed lazy member returned complete facts")
				}
				if (mode == "eager-and-lazy" || mode == "invalid-checkpoint") && opened != 0 {
					t.Fatal("invalid metadata opened source")
				}
				return
			}
			if err != nil || got.SHA256 != want.SHA256 || !bytes.Equal(actual.Bytes(), expected.Bytes()) || opened != len(lazy) {
				t.Fatal("lazy inputs changed original physical object", err)
			}
		})
	}
}
