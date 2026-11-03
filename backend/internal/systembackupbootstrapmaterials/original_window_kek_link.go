package systembackupbootstrapmaterials

import (
	"clawreef/internal/systembackupinstallationowner/install"
	kek "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
)

// LoadOriginalSQLBootstrapKEKPreparation selects only the existing concrete
// source from independently pinned public deployment bytes. It creates no SQL
// connection, credential/provider observation, witness or admission. The same
// entry point supplies Installer.IssueBootstrapKEKWindow and the consumer link.
func LoadOriginalSQLBootstrapKEKPreparation(sourceFile, sourceSHA string) (*kek.SQLBootstrapKEKPreparation, error) {
	owners, err := LinkOriginalSQLBootstrapKEK(sec.BootstrapOwnerAdapters{}, sourceFile, sourceSHA)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	preparation, ok := owners.KEK.(*kek.SQLBootstrapKEKPreparation)
	if !ok || preparation == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return preparation, nil
}

// LinkOriginalWindowSQLBootstrapKEK composes before candidate/native-host
// wrapping, from the actual terminal resource graph. Every resource stays on
// that graph; missing owners stay missing. ONE bridge supplies reference:kek
// and the independently invoked KEK preparation. No legacy source is replaced.
func LinkOriginalWindowSQLBootstrapKEK(original *install.BootstrapTerminalOriginal, sourceFile, sourceSHA string, window install.BootstrapKEKWindowFiles) (sec.BootstrapOwnerAdapters, *install.BootstrapTerminalOriginal, error) {
	bad := func() (sec.BootstrapOwnerAdapters, *install.BootstrapTerminalOriginal, error) {
		return sec.BootstrapOwnerAdapters{}, nil, sec.ErrRegistrationUnavailable
	}
	if original == nil {
		return bad()
	}
	preparation, err := LoadOriginalSQLBootstrapKEKPreparation(sourceFile, sourceSHA)
	if err != nil {
		return bad()
	}
	linked, bridge, err := original.WithOriginalWindowKEK(preparation, window)
	if err != nil {
		return bad()
	}
	owners, err := linked.Owners()
	if err != nil {
		return bad()
	}
	owners.KEK = bridge
	return owners, linked, nil
}
