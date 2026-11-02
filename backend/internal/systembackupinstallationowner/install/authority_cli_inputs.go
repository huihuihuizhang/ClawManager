package install

// DecodeEnrollmentPin and DecodeRequestFiles expose strict comparison data to
// the offline CLI. Their hashes are independently selected trusted inputs;
// neither decoder authenticates a principal or approves an action.
func DecodeEnrollmentPin(raw []byte, expectedSHA string) (EnrollmentPin, error) {
	var pin EnrollmentPin
	if hash(raw) != expectedSHA || decodeExact(raw, &pin) != nil || pin.ConfigMapUID == "" || !digestPattern.MatchString(pin.DocumentSHA256) {
		return EnrollmentPin{}, ErrInstall
	}
	return pin, nil
}
func DecodeRequestFiles(raw []byte, expectedSHA string) (RequestFiles, error) {
	var files RequestFiles
	if hash(raw) != expectedSHA || decodeExact(raw, &files) != nil {
		return RequestFiles{}, ErrInstall
	}
	return files, nil
}
