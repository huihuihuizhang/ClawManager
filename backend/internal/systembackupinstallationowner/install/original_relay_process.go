package install

type originalRelayNativeProcess struct {
	PID                                                                           int
	BootID, PIDNamespace, StartTicks, Executable, ExecutableSHA256, CommandSHA256 string
}
type originalRelayProcessRecord struct {
	Version, PlanSHA256, PKIMaterialSHA256, ServeInputsSHA256     string
	Pod, PodUID, ContainerID, ServiceUID, ServerCertificateSHA256 string
	Process                                                       originalRelayNativeProcess
}
