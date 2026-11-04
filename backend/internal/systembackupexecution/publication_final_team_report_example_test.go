package systembackupexecution

import (
	"bytes"
	"io"
)

// ExampleTeamContentReport shows package-internal consumption of a real Ready
// returned successfully by completeOriginalPublicationReady. The coordinator
// supplies the authorized private writer; this example creates neither one.
//
// Production already includes Teams in WriteBusinessContentReport and persists
// it through persistOriginalBusinessContentReport. Keep that outlet: this
// example is the Teams-only method contract, not a second production path.
func ExampleTeamContentReport() {
	exportToPrivateWriter := func(ready *publicationTerminalReady, privateOutput io.Writer) error {
		var content bytes.Buffer
		if err := ready.WriteTeamContentSamples(&content); err != nil {
			return err
		}
		_, err := io.Copy(privateOutput, &content)
		return err
	}
	_ = exportToPrivateWriter
	// No Output: compile-only usage example. A real authenticated Ready cannot
	// be manufactured here, and compilation is not formal-product acceptance.
}
