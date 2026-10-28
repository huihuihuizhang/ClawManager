package systembackupresources

import "reflect"

// A typed nil in an interface is still a missing proof implementation, even
// when its methods accept a nil receiver and return success. Non-nil adapters
// remain responsible for authenticating the capture or isolated target.
func missingProofVerifier(proof any) bool {
	if proof == nil {
		return true
	}
	value := reflect.ValueOf(proof)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}
