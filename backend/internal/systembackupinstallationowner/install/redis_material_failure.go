package install

// Phase is fixed by the original material owner. Private API/SQL/native errors
// remain available to errors.Is/As without being printed by the field CLI.
type OriginalRedisMaterialFailure struct {
	phase string
	cause error
}

func (e OriginalRedisMaterialFailure) Error() string {
	return "original Redis materials refused at " + e.phase
}
func (e OriginalRedisMaterialFailure) Phase() string { return e.phase }
func (e OriginalRedisMaterialFailure) Unwrap() error { return e.cause }
