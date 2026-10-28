//go:build !windows

package artifact

import "os"

func syncRoot(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
