package systembackupevidence

// This runtime owns its dedicated failure journal until Close. Deployment must
// supply real SQL policy, material and providers; no grant or storage is made.
func NewJournaledDownloadRuntime(c DownloadRuntimeConfig, journalConfig DownloadFailureJournalConfig) (*DownloadRuntime, error) {
	r := c.Authority.Registry
	if c.Failure != nil || journalConfig.Installation != r.Installation || journalConfig.ServerUUID != r.ServerUUID || journalConfig.Database != r.Database {
		return nil, ErrInvalid
	}
	j, err := NewDownloadFailureJournal(journalConfig)
	if err != nil {
		return nil, err
	}
	c.Failure = j.Report
	runtime, err := NewDownloadRuntime(c)
	if err != nil {
		j.Close()
		return nil, err
	}
	runtime.journal = j
	runtime.authority.journal = j
	return runtime, nil
}

// A function callback alone cannot satisfy concrete production persistence.
func (r *DownloadRuntime) CheckFailurePersistence() error {
	if r == nil || r.closed.Load() || r.journal == nil {
		return ErrUnavailable
	}
	return r.journal.Check()
}
