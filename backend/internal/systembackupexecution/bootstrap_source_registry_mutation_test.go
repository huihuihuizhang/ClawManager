package systembackupexecution

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

func TestSourceRegistryEnableOnlyRequiresActualFourSlotSource(t *testing.T){
	dir:=t.TempDir()
	capture:=install.NewCaptureSigningConsumer(filepath.Join(dir,"capture.json"),filepath.Join(dir,"capture.sha256"))
	files:=install.BootstrapSourceRegistryFiles{RecordFile:filepath.Join(dir,"source.json"),RecordSHA256:strings.Repeat("a",64),SignatureFile:filepath.Join(dir,"source.sig")}
	native:=BootstrapSourceNativeRegistryFiles{RedisSources:install.BootstrapSourceFilePin{File:filepath.Join(dir,"redis.json"),SHA256:strings.Repeat("b",64)},SecretAllowlist:install.BootstrapSourceFilePin{File:filepath.Join(dir,"secret.json"),SHA256:strings.Repeat("c",64)}}
	mapping:=install.BootstrapTerminalFiles{MappingFile:filepath.Join(dir,"mapping.json"),MappingSHA256:strings.Repeat("d",64),SignatureFile:filepath.Join(dir,"mapping.sig")}
	legacy,err:=NewBootstrapSourceRegistryTerminalResource(capture,files);if err!=nil{t.Fatal(err)}
	if _,err=NewBootstrapSourceRegistryEnableOnlyMutation(legacy,mapping);err==nil{t.Fatal("two-slot bootstrap source silently promoted to four-slot mutation")}
	source,err:=NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture,files,native);if err!=nil{t.Fatal(err)}
	v,err:=NewBootstrapSourceRegistryEnableOnlyMutation(source,mapping);if err!=nil{t.Fatal(err)}
	if _,err=json.Marshal(v);err==nil{t.Fatal("serialized mutation validator")}
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
	if observation,err:=v.Prepare(ctx,sec.ConfigMutationResourceInput{});err==nil || observation!=nil{t.Fatal("empty mutation input admitted without actual enabled-only snapshots/source")}
	for _,slot:=range []string{"registry:parts","registry:redis_sources","registry:secret_allowlist","registry:source_writers"}{if !sourceRegistryMutationSlot(slot){t.Fatal("owned mutation slot missing",slot)}}
	for _,slot:=range []string{"registry:failure_domains","reference:capture_signing","deployment_switch"}{if sourceRegistryMutationSlot(slot){t.Fatal("unowned mutation slot accepted",slot)}}
}

func TestSourceRegistryEnableOnlyObservationIsNotDeadlineData(t *testing.T){
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
	o:=&sourceRegistryMutationObservation{ctx:ctx,started:time.Now().Add(-time.Second),until:time.Now().Add(time.Second)}
	o.origin=o
	if err:=o.Recheck(ctx,nil,time.Now());err==nil || !o.failed.Load() || !o.ValidUntil().IsZero(){t.Fatal("private times admitted without actual current source/SQL transaction")}
	original:=&sourceRegistryMutationObservation{ctx:ctx,until:time.Now().Add(time.Second)};original.origin=original
	detached:=&sourceRegistryMutationObservation{origin:original,ctx:ctx,until:original.until}
	if !detached.ValidUntil().IsZero() || !original.failed.Load() || !original.ValidUntil().IsZero(){t.Fatal("copied mutation observation resurrected original")}
	if _,err:=json.Marshal(o);err==nil{t.Fatal("serialized mutation observation")}
}
