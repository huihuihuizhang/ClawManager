package quiesce

// The existing native protocol separates mount registration from post-drain
// sync. Reject incomplete calls before transport as well as on the node.
func validLonghornRWXClientTransition(r LonghornExt4Request) bool {
	if r.Keeper != nil || r.ClientPodUID == "" || r.ClientPodName == "" || r.ClientContainerID == "" || r.RecoveryBoundarySHA256 != "" || !validObservationHash(r.RegistrationBoundarySHA256) {
		return false
	}
	switch r.Action {
	case "register-client":
		return r.DrainBoundarySHA256 == ""
	case "sync-client":
		return validObservationHash(r.DrainBoundarySHA256)
	}
	return false
}
