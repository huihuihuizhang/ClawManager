package systembackupwire

// ValidateStreamSpec checks the original wire shape only. A valid spec is
// neither a trusted KEK mapping nor permission to Unwrap/Generate; callers must
// authenticate those independently before opening an encrypted stream.
func ValidateStreamSpec(spec StreamSpec) error { _, err := spec.binding(); return err }
