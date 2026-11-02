package install

import apierrors "k8s.io/apimachinery/pkg/api/errors"

const enrollmentAttemptAnnotation = "system-backup.clawmanager.io/enrollment-attempt"

// These completed API refusals establish that this request was rejected.
// Transport/timeout/5xx/unknown outcomes are never treated as no write.
func definiteEnrollmentRejection(e error) bool {
	return apierrors.IsForbidden(e) || apierrors.IsUnauthorized(e) || apierrors.IsBadRequest(e) || apierrors.IsInvalid(e) || apierrors.IsNotFound(e) || apierrors.IsMethodNotSupported(e) || apierrors.IsUnsupportedMediaType(e)
}
