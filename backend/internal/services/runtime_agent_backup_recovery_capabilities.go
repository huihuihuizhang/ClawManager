package services

// Protocol DATA only. Actual owner/gate, original journal, B native checks and
// current recovery permission remain mandatory for every writer transition.
const RuntimeBackupOriginalRecoveryScope = "original_operation_same_agent_epoch"
const RuntimeBackupRestartQuarantinePolicy = "quarantine_active_reservation"

func runtimeBackupOriginalRecovery(durable, reconciliation bool, scope, policy string) bool {
	return durable && !reconciliation && scope == RuntimeBackupOriginalRecoveryScope && policy == RuntimeBackupRestartQuarantinePolicy
}

// Legacy false/missing metadata and unknown cross-incarnation modes refuse.
// Caller must independently compare the actual original Pod/AgentEpoch/slot.
func RuntimeBackupSupportsOriginalOperationRecovery(c *RuntimeBackupCapabilities) bool {
	return c != nil && c.Protocol == RuntimeBackupProtocol && c.Scope == RuntimeBackupStopScope && c.Supported &&
		c.Namespace != "" && c.PodUID != "" && stopTokenValid(c.AgentEpoch) && c.Slot != "" && c.GatewayPort > 0 && c.GatewayPort <= 65535 &&
		runtimeBackupOriginalRecovery(c.DurableReservation, c.AgentRestartReconciliation, c.RecoveryScope, c.AgentRestartPolicy)
}

func RuntimeStoppedBackupSupportsOriginalOperationRecovery(c *RuntimeStoppedBackupCapabilities) bool {
	return c != nil && c.Protocol == RuntimeStoppedBackupProtocol && c.Scope == RuntimeStoppedBackupScope && c.Supported && c.KeepStoppedComplete &&
		c.Namespace != "" && c.PodUID != "" && stopTokenValid(c.AgentEpoch) && c.Slot != "" && c.GatewayPort > 0 && c.GatewayPort <= 65535 &&
		runtimeBackupOriginalRecovery(c.DurableReservation, c.AgentRestartReconciliation, c.RecoveryScope, c.AgentRestartPolicy)
}
