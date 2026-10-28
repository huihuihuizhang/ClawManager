//go:build windows

package artifact

import "os"

// Windows is a library fixture host only; publication workers run on Linux.
func syncRoot(*os.Root) error { return nil }
