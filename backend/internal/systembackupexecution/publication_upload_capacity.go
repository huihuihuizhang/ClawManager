package systembackupexecution

// The candidate boundary checks ORIGINAL snapshot/097-matched budgets before
// grants, immutable materials or a Job send. Worker exact request hashes and
// per-object finite PUT grants carry that authorized object set and lengths.
// Transport ceilings alone do not supply task configuration authority.
func publicationUploadBytesWithinLimits(request PublicationUploadRequest, manifestBytes int64, limits ArtifactReadLimits) error {
	if limits.validate() != nil || manifestBytes < 1 || manifestBytes > 262144 || manifestBytes > limits.MaxArtifactBytes {
		return errPublicationUnavailable
	}
	total := manifestBytes
	index := false
	for _, object := range request.Objects {
		if object.Bytes < 1 || object.Bytes > limits.MaxArtifactBytes-total {
			return errPublicationUnavailable
		}
		total += object.Bytes
		if object.Path == "artifact-index.json" {
			if index || object.Bytes > limits.MaxIndexBytes {
				return errPublicationUnavailable
			}
			index = true
		}
	}
	if !index {
		return errPublicationUnavailable
	}
	return nil
}
