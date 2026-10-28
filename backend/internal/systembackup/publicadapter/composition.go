package publicadapter

import d "clawreef/internal/systembackupdispatch"

// NewLinuxDispatcher is the real D composition entry: a source-only SQL handle,
// admitted real client/Agent/Proof builders, owner evidence/recovery services,
// registry checks and public Ports produce the shared Dispatcher. Nothing is
// opened, granted or dispatched during construction. For several admitted
// profile revisions, construct each profile and call NewPublicRunner directly.
func NewLinuxDispatcher(key ProfileKey, source LinuxProfileConfig, execution Dependencies, ports d.Ports) (d.Dispatcher, error) {
	if nilValue(ports) || len(execution.Profiles) != 0 {
		return d.Dispatcher{}, d.ErrNotReady
	}
	profile, err := NewLinuxProfile(source)
	if err != nil {
		return d.Dispatcher{}, err
	}
	execution.Profiles = map[ProfileKey]Profile{key: profile}
	runner, err := NewPublicRunner(execution)
	if err != nil {
		return d.Dispatcher{}, err
	}
	return d.Dispatcher{Runner: runner, Ports: ports}, nil
}
