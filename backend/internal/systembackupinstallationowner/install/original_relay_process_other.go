//go:build !linux

package install

import "context"

func originalRelayReadNativeProcess(int) (originalRelayNativeProcess, error) {
	return originalRelayNativeProcess{}, ErrInstall
}
func originalRelaySignalExactProcess(context.Context, originalRelayNativeProcess, string, string, string) (bool, error) {
	return false, ErrInstall
}
func originalRelayProcessAbsent(originalRelayNativeProcess) (bool, error) { return false, ErrInstall }
