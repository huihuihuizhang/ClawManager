package main

import (
	"context"
	"flag"
	"strings"
	"time"

	c "clawreef/internal/systembackupcontroller"
	"clawreef/internal/systembackupinstallationowner/install"
)

type participantWriterFlags map[string]string

func (p *participantWriterFlags) String() string { return "" }
func (p *participantWriterFlags) Set(value string) error {
	id, writer, ok := strings.Cut(value, "=")
	if !ok || id == "" || len(id) > 128 || writer == "" || len(writer) > 512 || strings.ContainsAny(value, "\x00\r\n") || strings.Contains(writer, "=") {
		return install.ErrInstall
	}
	if *p == nil {
		*p = map[string]string{}
	}
	if _, exists := (*p)[id]; exists {
		return install.ErrInstall
	}
	(*p)[id] = writer
	return nil
}

type writerSelectionFlags struct {
	configFile, configSHA, observerDefinition, observerDefinitionSHA, observerReceipt, observerReceiptSHA *string
	output, journal, custodyDirectory, custodyKey, custodyKeySHA                                          *string
	lockTTL, acquire, hold                                                                                *time.Duration
	participants                                                                                          participantWriterFlags
}

func registerWriterSelectionFlags(flags *flag.FlagSet) *writerSelectionFlags {
	s := &writerSelectionFlags{}
	s.configFile = flags.String("source-config-file", "", "existing independently pinned source configuration; not an enabled config or observation")
	s.configSHA = flags.String("source-config-sha256", "", "exact source configuration bytes")
	s.observerDefinition = flags.String("observer-definition-file", "", "actual PKI producer original definition")
	s.observerDefinitionSHA = flags.String("observer-definition-sha256", "", "exact original observer definition bytes")
	s.observerReceipt = flags.String("observer-receipt-file", "", "retained actual generated observer PKI receipt")
	s.observerReceiptSHA = flags.String("observer-receipt-sha256", "", "exact retained PKI receipt bytes")
	s.output = flags.String("selection-output-directory", "", "existing empty private directory; output is create-only")
	s.journal = flags.String("journal-directory", "", "distinct existing empty private directory reserved for the later real writer factory")
	s.custodyDirectory = flags.String("gateway-original-directory", "", "existing runtimecustody Store directory; required for an actual running Lite source")
	s.custodyKey = flags.String("gateway-original-key-file", "", "existing original 32-byte runtimecustody key, never a replacement key")
	s.custodyKeySHA = flags.String("gateway-original-key-sha256", "", "independently pinned existing custody key")
	s.lockTTL = flags.Duration("maintenance-lock-ttl", 900*time.Second, "ordinary bounded recovery policy")
	s.acquire = flags.Duration("acquisition-timeout", 60*time.Second, "ordinary bounded recovery policy")
	s.hold = flags.Duration("maximum-hold", 600*time.Second, "ordinary bounded recovery policy")
	flags.Var(&s.participants, "participant-writer", "repeat ID=actual-physical-writer-ID when the actual registered participant ID differs; no authorization JSON")
	return s
}
func (s *writerSelectionFlags) valid() bool {
	if s == nil || *s.configFile == "" || *s.configSHA == "" || *s.observerDefinition == "" || *s.observerDefinitionSHA == "" || *s.observerReceipt == "" || *s.observerReceiptSHA == "" || *s.output == "" || *s.journal == "" {
		return false
	}
	if (*s.custodyDirectory == "") != (*s.custodyKey == "") || (*s.custodyKey == "") != (*s.custodyKeySHA == "") {
		return false
	}
	return (c.GatePolicy{LockTTL: *s.lockTTL, AcquisitionTimeout: *s.acquire, MaxHold: *s.hold}).Validate() == nil
}
func (s *writerSelectionFlags) produce(ctx context.Context, i *install.Installer, password []byte, enrollment install.EnrollmentPin) (install.OriginalWriterSelectionReceipt, error) {
	if !s.valid() {
		return install.OriginalWriterSelectionReceipt{}, install.ErrInstall
	}
	return i.ProduceOriginalWriterSelection(ctx, password, enrollment, install.OriginalWriterSelectionOptions{
		DeploymentConfig:         install.BootstrapSourceFilePin{File: *s.configFile, SHA256: *s.configSHA},
		ObserverDefinition:       install.BootstrapSourceFilePin{File: *s.observerDefinition, SHA256: *s.observerDefinitionSHA},
		ObserverReceipt:          install.BootstrapSourceFilePin{File: *s.observerReceipt, SHA256: *s.observerReceiptSHA},
		GatewayOriginalKey:       install.BootstrapSourceFilePin{File: *s.custodyKey, SHA256: *s.custodyKeySHA},
		GatewayOriginalDirectory: *s.custodyDirectory, JournalDirectory: *s.journal, ParticipantWriters: s.participants,
		Policy: c.GatePolicy{LockTTL: *s.lockTTL, AcquisitionTimeout: *s.acquire, MaxHold: *s.hold},
	}, *s.output)
}
