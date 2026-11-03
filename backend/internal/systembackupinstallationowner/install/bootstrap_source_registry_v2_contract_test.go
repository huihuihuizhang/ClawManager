package install

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

// DATA/signature codec only. The original v1 issuer/selection is real; this
// v2 fixture is explicitly signed synthetic association data, NOT the actual
// V2 issuer, native source observation or a concrete registry owner.
func bootstrapSourceV2ContractFixture(t *testing.T) (BootstrapSourceRegistryV2Record, ed25519.PrivateKey) {
	t.Helper()
	ctx,cancel:=context.WithTimeout(context.Background(),time.Minute)
	defer cancel()
	f,selection,pack,_,definition:=bootstrapSourceProtocolFixture(t,ctx)
	signed,err:=f.i.IssueBootstrapSourceRegistries(ctx,f.password,f.enrollment,pack,hash(pack),definition.File,definition.SHA256,selection,f.files,f.key)
	if err!=nil {t.Fatal("positive original issuer",err)}
	b,err:=verifyBootstrapSourceRegistries(signed.Record,signed.Signature,f.i.public)
	if err!=nil {t.Fatal("positive original association",err)}
	s:=b.Source
	control:=s.Connections[3]
	control.Purpose="control_sql"
	control.Account="original_control_observer@localhost"
	control.ServerUUID,control.Database=b.Target.ServerUUID,b.Target.Database
	control.Credential=BootstrapSourceFilePin{File:s.Deployment.File,SHA256:s.Deployment.SHA256}
	d:=BootstrapSourceRegistryV2Definition{SchemaVersion:BootstrapSourceRegistryV2Version,Profile:s.Profile,ApplicationScope:"original_application",MetadataGrant:s.MetadataGrant,MetadataIssuerPublic:s.MetadataIssuerPublic,Deployment:s.Deployment,Materials:s.Materials,ExecutionProfile:s.ExecutionProfile,ForwardGrant:BootstrapSourceFilePin{File:s.ExecutionProfile.File,SHA256:b.Metadata.CaptureGrantSHA256},PartsRegistry:s.PartsRegistry,SourceWritersRegistry:s.SourceWritersRegistry,Controller:s.Controller,Connections:append([]BootstrapSourceConnection{control},s.Connections...)}
	for n:=range d.Connections {
		c:=&d.Connections[n]
		c.IdentitySHA256,err=BootstrapSourceConnectionIdentitySHA256(b.Target.InstallationID,*c)
		if err!=nil {t.Fatal(err)}
		c.ScopeSHA256,err=BootstrapSourceNativeRoleScopeSHA256(b.Target.InstallationID,d,*c,b.Metadata.ScopeSHA256)
		if err!=nil {t.Fatal(err)}
	}
	d.RuntimeAgent=&BootstrapSourceRuntimeAgentV2{Operations:[]string{"backup_capabilities_read","gateway_state_read"},CA:s.RuntimeAgent.CA,Credential:s.RuntimeAgent.Credential}
	d.RuntimeAgent.ScopeSHA256,err=BootstrapSourceAgentScopeSHA256(b.Target.InstallationID,d)
	if err!=nil {t.Fatal(err)}
	r:=BootstrapSourceRegistryV2Record{SchemaVersion:BootstrapSourceRegistryV2Version,Profile:b.Profile,PlanSHA256:b.PlanSHA256,CaptureRecordSHA256:b.CaptureRecordSHA256,DefinitionSHA256:b.DefinitionSHA256,Target:b.Target,Actor:b.Actor,Enrollment:b.Enrollment,NotBefore:b.NotBefore,Until:b.Until,Selection:b.Selection,Parts:b.Parts,SourceWriters:b.SourceWriters,Source:d,Metadata:b.Metadata,MetadataRecordSHA256:b.MetadataRecordSHA256,MetadataIssuerSHA256:b.MetadataIssuerSHA256}
	if validateBootstrapSourceV2(r)!=nil {t.Fatal("positive v2 DATA shape")}
	return r,f.key
}

func TestBootstrapSourceRegistryV2RejectsLegacySignatureDomains(t *testing.T) {
	r,key:=bootstrapSourceV2ContractFixture(t)
	raw,err:=canonical(r)
	if err!=nil {t.Fatal(err)}
	public:=key.Public().(ed25519.PublicKey)
	if _,err:=verifyBootstrapSourceV2(raw,ed25519.Sign(key,append([]byte(BootstrapSourceRegistryV2Domain),raw...)),public);err!=nil {t.Fatal("positive v2 signature",err)}
	for _,domain:=range []string{BootstrapSourceRegistryDomain,"system-backup-controller-source-metadata.v1\x00"} {
		if _,err:=verifyBootstrapSourceV2(raw,ed25519.Sign(key,append([]byte(domain),raw...)),public);err==nil {t.Fatal("legacy signature upgraded to v2",domain)}
	}
}

func TestBootstrapSourceRegistryV2ControlAndAgentClosure(t *testing.T) {
	r,_:=bootstrapSourceV2ContractFixture(t)
	for _,scenario:=range []string{"control_absent","control_business_account","control_business_credential","control_foreign_database","application_scope_missing","agent_gateway_only","agent_extra_write","agent_reordered"} {
		t.Run(scenario,func(t *testing.T){
			bad,err:=cloneBootstrapSourceV2(r)
			if err!=nil {t.Fatal(err)}
			switch scenario {
			case "control_absent":bad.Source.Connections=bad.Source.Connections[1:]
			case "control_business_account":bad.Source.Connections[0].Account=bad.Source.Connections[4].Account
			case "control_business_credential":bad.Source.Connections[0].Credential=bad.Source.Connections[4].Credential
			case "control_foreign_database":bad.Source.Connections[0].Database="foreign"
			case "application_scope_missing":bad.Source.ApplicationScope=""
			case "agent_gateway_only":bad.Source.RuntimeAgent.Operations=[]string{"gateway_state_read"}
			case "agent_extra_write":bad.Source.RuntimeAgent.Operations=append(bad.Source.RuntimeAgent.Operations,"stop")
			case "agent_reordered":bad.Source.RuntimeAgent.Operations=[]string{"gateway_state_read","backup_capabilities_read"}
			}
			// Recompute declared hashes so rejection tests the closed semantics,
			// not merely a stale hash after a structurally signed DATA mutation.
			for n:=range bad.Source.Connections {c:=&bad.Source.Connections[n];c.IdentitySHA256,_=BootstrapSourceConnectionIdentitySHA256(bad.Target.InstallationID,*c);c.ScopeSHA256,_=BootstrapSourceNativeRoleScopeSHA256(bad.Target.InstallationID,bad.Source,*c,bad.Metadata.ScopeSHA256)}
			bad.Source.RuntimeAgent.ScopeSHA256,_=BootstrapSourceAgentScopeSHA256(bad.Target.InstallationID,bad.Source)
			if validateBootstrapSourceV2(bad)==nil {t.Fatal("v2 native read scope widened",scenario)}
		})
	}
}
