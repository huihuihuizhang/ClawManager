//go:build linux

package quiesce

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/services"
	"golang.org/x/sys/unix"
)

// Mirror only the exact frozen Agent's original on-disk schema. These are not
// an alternative reservation implementation: this package never writes them.
type gatewayNativeAssignment struct {
	GatewayID string `json:"gateway_id"`
	InstanceID int `json:"instance_id"`
	UserID int `json:"user_id"`
	Generation int `json:"generation"`
	State string `json:"state"`
}
type gatewayNativeBackup struct {
	Request services.RuntimeBackupRequest `json:"request"`
	State string `json:"state"`
	Stop *services.RuntimeBackupReceipt `json:"stop,omitempty"`
	Resume *services.RuntimeBackupReceipt `json:"resume,omitempty"`
}
type gatewayNativeWriterCore struct {
	InstanceID,UserID,Generation int
	RuntimeType,PodUID,Slot string
}
type gatewayNativeStoppedBackup struct {
	Request services.RuntimeStoppedBackupRequest `json:"request"`
	State string `json:"state"`
	Original gatewayNativeWriterCore `json:"original"`
	Reserved *services.RuntimeStoppedBackupReceipt `json:"reserved,omitempty"`
	Completed *services.RuntimeStoppedBackupReceipt `json:"completed,omitempty"`
}
type gatewayNativeCompletion struct {
	Identity services.RuntimeStoppedBackupIdentity
	RequestSHA256 string
}
type gatewayNativeBook struct {
	StoppedCompletions map[string]gatewayNativeCompletion `json:"stopped_completions,omitempty"`
	StoppedBackup *gatewayNativeStoppedBackup `json:"stopped_backup,omitempty"`
	Backup *gatewayNativeBackup `json:"backup,omitempty"`
	Assignment *gatewayNativeAssignment `json:"assignment,omitempty"`
	Digest string `json:"digest,omitempty"`
}
type gatewayNativeWriter struct {
	StoppedBackup *gatewayNativeStoppedBackup `json:"stopped_backup,omitempty"`
	Backup *gatewayNativeBackup `json:"backup,omitempty"`
	InstanceID int `json:"instance_id"`
	UserID int `json:"user_id"`
	Generation int `json:"generation"`
	RuntimeType string `json:"runtime_type"`
	PodUID string `json:"pod_uid"`
	Slot string `json:"slot"`
	State string `json:"state"`
}
type gatewayNativeState struct {
	Agent observedProcess
	Worker observedProcess
	Book gatewayNativeBook
	Writer gatewayNativeWriter
	Lock,BookParent,LedgerParent gatewayNativePin
	BookRaw,WriterRaw []byte
}

func gatewayNativeRead(ctx context.Context,containerRoot,p string) ([]byte,gatewayNativePin,gatewayNativePin,error) {
	var none gatewayNativePin
	if !absoluteObservationPath(p) || p=="/" {return nil,none,none,observationFailure("gateway_journal_path")}
	parts:=strings.Split(strings.TrimPrefix(p,"/"),"/");current:=containerRoot;var parent unix.Stat_t
	for _,component:=range parts[:len(parts)-1] {current=filepath.Join(current,component);var st unix.Stat_t;if unix.Lstat(current,&st)!=nil || st.Mode&unix.S_IFMT!=unix.S_IFDIR || st.Uid!=0 || st.Mode&0022!=0 {return nil,none,none,observationFailure("gateway_journal_trust")};parent=st}
	file:=filepath.Join(current,parts[len(parts)-1]);var before,after unix.Stat_t
	if unix.Lstat(file,&before)!=nil || before.Mode&unix.S_IFMT!=unix.S_IFREG || before.Uid!=0 || before.Mode&0077!=0 {return nil,none,none,observationFailure("gateway_journal_trust")}
	b,e:=observationRead(ctx,file,256<<10);if e!=nil || unix.Lstat(file,&after)!=nil || before.Dev!=after.Dev || before.Ino!=after.Ino || before.Mode!=after.Mode || before.Uid!=after.Uid || before.Size!=after.Size || before.Mtim!=after.Mtim || before.Ctim!=after.Ctim {return nil,none,none,observationFailure("gateway_journal_drift")}
	return b,gatewayNativePin{uint64(before.Dev),before.Ino},gatewayNativePin{uint64(parent.Dev),parent.Ino},nil
}
func gatewaySlotNumber(slot string) (int,error) {
	if !strings.HasPrefix(slot,"slot-") {return 0,ErrNodeObservation};n,e:=strconv.Atoi(strings.TrimPrefix(slot,"slot-"));if e!=nil || n<0 || n>255 || slot!="slot-"+strconv.Itoa(n) {return 0,ErrNodeObservation};return n,nil
}
func gatewayNSpid(ctx context.Context,base string) ([]int,error) {
	b,e:=observationRead(ctx,filepath.Join(base,"status"),64<<10);if e!=nil {return nil,e}
	for _,l:=range strings.Split(string(b),"\n") {if strings.HasPrefix(l,"NSpid:") {var pids []int;for _,v:=range strings.Fields(strings.TrimPrefix(l,"NSpid:")) {n,e:=strconv.Atoi(v);if e!=nil || n<=0 {return nil,ErrNodeObservation};pids=append(pids,n)};if len(pids)>0 {return pids,nil}}};return nil,ErrNodeObservation
}
func gatewayParent(ctx context.Context,base string) (int,string,error) {
	b,e:=observationRead(ctx,filepath.Join(base,"stat"),64<<10);if e!=nil {return 0,"",e};s:=string(b);i:=strings.LastIndex(s,") ");if i<0 {return 0,"",ErrNodeObservation};f:=strings.Fields(s[i+2:]);if len(f)<20 {return 0,"",ErrNodeObservation};n,e:=strconv.Atoi(f[1]);return n,f[0],e
}
func (o *NodeObserver) gatewayLockOwner(ctx context.Context,pin gatewayNativePin,agent observedProcess) (observedProcess,error) {
	var out observedProcess;b,e:=observationRead(ctx,filepath.Join(o.HostProc,"locks"),observationReadLimit);if e!=nil {return out,observationFailure("gateway_lock_visibility")};pid:=0
	for _,l:=range strings.Split(string(b),"\n") {f:=strings.Fields(l);if len(f)<8 || f[1]!="FLOCK" || f[2]!="ADVISORY" || f[3]!="WRITE" {continue};dev:=strings.Split(f[5],":");if len(dev)!=3 {return out,ErrNodeObservation};major,e:=strconv.ParseUint(dev[0],16,32);if e!=nil {return out,e};minor,e:=strconv.ParseUint(dev[1],16,32);if e!=nil {return out,e};inode,e:=strconv.ParseUint(dev[2],10,64);if e!=nil {return out,e};if uint32(major)!=unix.Major(pin.Device) || uint32(minor)!=unix.Minor(pin.Device) || inode!=pin.Inode {continue};n,e:=strconv.Atoi(f[4]);if e!=nil || n<=0 || pid!=0 || f[6]!="0" || f[7]!="EOF" {return out,observationFailure("gateway_lock_owner")};pid=n}
	if pid==0 {return out,observationFailure("gateway_lock_not_held")};out,e=observationProcess(ctx,filepath.Join(o.HostProc,strconv.Itoa(pid)));if e!=nil || out.PIDNamespace!=agent.PIDNamespace || !withinObservation(out.Cgroup,agent.Cgroup) {return observedProcess{},observationFailure("gateway_lock_owner")}
	return out,nil
}
func (o *NodeObserver) gatewayState(ctx context.Context,r GatewayNodeObservationRequest,paths []observedPath) (gatewayNativeState,error) {
	var out gatewayNativeState
	roots,e:=o.running(ctx,r.Binding,[]PodIdentity{r.AgentPod},paths);if e!=nil || len(roots)!=1 {return out,observationFailure("gateway_agent_cri")};out.Agent=roots[0];root:=filepath.Join(o.HostProc,strconv.Itoa(out.Agent.PID),"root")
	_,_,_,_,runtime,instance,user,_:=gatewayOriginalIdentity(r);slot,e:=gatewaySlotNumber(r.Slot);if e!=nil {return out,e}
	guardPath:=fmt.Sprintf("/run/clawmanager-slots/slot-%d.sock.guard",slot)
	_,guard,_,e:=gatewayNativeRead(ctx,root,guardPath);if e!=nil {return out,e};out.Worker,e=o.gatewayLockOwner(ctx,guard,out.Agent);if e!=nil {return out,e}
	bookRaw,_,bookParent,e:=gatewayNativeRead(ctx,root,filepath.Join(r.AgentDataDir,"slot-assignment.json"));if e!=nil {return out,e}
	ledger:=filepath.Join(r.WorkspaceRoot,".clawmanager-slot-locks",fmt.Sprintf("%s-%d-%d.json",runtime,user,instance))
	writerRaw,_,ledgerParent,e:=gatewayNativeRead(ctx,root,ledger);if e!=nil {return out,e}
	_,lock,_,e:=gatewayNativeRead(ctx,root,strings.TrimSuffix(ledger,".json")+".lock");if e!=nil {return out,e}
	if observationJSON(strings.NewReader(string(bookRaw)),&out.Book)!=nil || observationJSON(strings.NewReader(string(writerRaw)),&out.Writer)!=nil || out.Book.Assignment==nil || !validObservationHash(out.Book.Digest) {return out,observationFailure("gateway_journal_schema")}
	out.Lock=lock;out.BookParent=bookParent;out.LedgerParent=ledgerParent;out.BookRaw=bookRaw;out.WriterRaw=writerRaw
	return out,nil
}
func gatewayStoppedCheckpoint(book gatewayNativeBook,core gatewayNativeWriterCore) string {
	return observationDigest(struct{Version string;Assignment *gatewayNativeAssignment;Digest string;Writer gatewayNativeWriterCore}{"original-stopped-checkpoint.v2",book.Assignment,book.Digest,core})
}
func gatewayWriterCore(w gatewayNativeWriter) gatewayNativeWriterCore {return gatewayNativeWriterCore{w.InstanceID,w.UserID,w.Generation,w.RuntimeType,w.PodUID,w.Slot}}
func gatewayNativeIdentity(r GatewayNodeObservationRequest,s gatewayNativeState,recovered bool) bool {
	_,pod,_,_,runtime,instance,user,generation:=gatewayOriginalIdentity(r);if recovered && r.Running!=nil {generation=r.Running.ResumeGeneration}
	a:=s.Book.Assignment;w:=s.Writer
	return a!=nil && a.GatewayID==fmt.Sprintf("gw-%d-%d",instance,generation) && a.InstanceID==instance && a.UserID==user && a.Generation==generation && w.InstanceID==instance && w.UserID==user && w.Generation==generation && w.RuntimeType==runtime && w.PodUID==pod && w.Slot==r.Slot
}
func (o *NodeObserver) prepareGateway(ctx context.Context,r GatewayNodeObservationRequest) (gatewayObservationAnchor,error) {
	var a gatewayObservationAnchor;paths:=append([]string(nil),r.SourcePaths...);sort.Strings(paths)
	for i,p:=range paths {if !absoluteObservationPath(p)||p=="/"||i>0&&observationRangesOverlap(p,paths[i-1]) {return a,ErrNodeObservation}}
	sources,e:=o.paths(ctx,paths);if e!=nil {return a,observationFailure("source_mount")};s,e:=o.gatewayState(ctx,r,sources);if e!=nil {return a,e}
	if !gatewayNativeIdentity(r,s,false) {return a,observationFailure("gateway_original_identity")}
	a=gatewayObservationAnchor{Version:GatewayNodeObservationProtocol,Binding:r.Binding,AgentPod:r.AgentPod,Agent:s.Agent,Worker:s.Worker,Slot:r.Slot,WorkspaceRoot:r.WorkspaceRoot,AgentDataDir:r.AgentDataDir,OriginalDigest:s.Book.Digest,RequestSHA256:gatewayRequestSHA(r),OriginalStateSHA256:r.OriginalStateSHA256,Paths:sources,Lock:s.Lock,BookParent:s.BookParent,LedgerParent:s.LedgerParent,BootID:o.BootID}
	if r.Running!=nil {
		// Ordinary begin() persists "starting"; it does not persist a later
		// "running" transition. Actual monitor/private-init observation and D's
		// authenticated live GatewayState establish running, not this journal word.
		if (s.Book.Assignment.State!="starting" && s.Book.Assignment.State!="running") || s.Writer.State!="running" || s.Writer.Backup!=nil || s.Book.Backup!=nil&&s.Book.Backup.State!="completed" || s.Writer.StoppedBackup!=nil || s.Book.StoppedBackup!=nil&&s.Book.StoppedBackup.State!="completed" {return a,observationFailure("gateway_original_running")}
		owner,e:=o.gatewayLockOwner(ctx,s.Lock,s.Agent);if e!=nil || owner!=s.Worker {return a,observationFailure("gateway_lock_owner")}
		a.Scope,e=o.gatewayScope(ctx,s.Agent,s.Worker,r.Running.ExpectedPID);if e!=nil {return a,e}
	} else {
		if s.Book.Assignment.State!="stopped" || s.Writer.State!="stopped" || s.Writer.Backup!=nil || s.Writer.StoppedBackup!=nil || s.Book.Backup!=nil&&s.Book.Backup.State!="completed" || s.Book.StoppedBackup!=nil&&s.Book.StoppedBackup.State!="completed" {return a,observationFailure("gateway_original_stopped")}
		a.Checkpoint=gatewayStoppedCheckpoint(s.Book,gatewayWriterCore(s.Writer));if a.Checkpoint!=r.Stopped.CheckpointSHA256 {return a,observationFailure("gateway_checkpoint")}
		a.PreparedTasks,a.PreparedFiles,e=o.gatewayScan(ctx,a,nil);if e!=nil {return a,e}
	}
	last,e:=o.gatewayState(ctx,r,sources);if e!=nil || last.Agent!=s.Agent || last.Worker!=s.Worker || last.Lock!=s.Lock || last.BookParent!=s.BookParent || last.LedgerParent!=s.LedgerParent || !reflect.DeepEqual(last.BookRaw,s.BookRaw) || !reflect.DeepEqual(last.WriterRaw,s.WriterRaw) {return a,observationFailure("gateway_journal_drift")}
	current,e:=o.paths(ctx,paths);if e!=nil || !reflect.DeepEqual(current,sources) {return a,observationFailure("source_mount_drift")}
	return a,nil
}

func (o *NodeObserver) gatewayScope(ctx context.Context,agent,worker observedProcess,expected int) (gatewayNativeScope,error) {
	var scope gatewayNativeScope;agentIDs,e:=gatewayNSpid(ctx,filepath.Join(o.HostProc,strconv.Itoa(agent.PID)));if e!=nil {return scope,e};level:=len(agentIDs)-1
	tasks,e:=o.tasks(ctx);if e!=nil {return scope,e};type item struct{p observedProcess;parent int;ids []int};var observed []item
	for _,base:=range tasks {p,e:=observationProcess(ctx,base);if e!=nil {return scope,observationFailure("task_identity_unreadable")};if !withinObservation(p.Cgroup,agent.Cgroup) {continue};parent,state,e:=gatewayParent(ctx,base);if e!=nil {return scope,e};if state=="Z"||state=="X" {continue};ids,e:=gatewayNSpid(ctx,base);if e!=nil {return scope,e};observed=append(observed,item{p,parent,ids});if p.PIDNamespace==agent.PIDNamespace && len(ids)>level && ids[level]==expected {if scope.Monitor.PID!=0&&scope.Monitor.PID!=p.PID {return scope,ErrNodeObservation};scope.Monitor=p}}
	if scope.Monitor.PID==0 {return scope,observationFailure("gateway_monitor_missing")}
	monitorParent,_,e:=gatewayParent(ctx,filepath.Join(o.HostProc,strconv.Itoa(scope.Monitor.PID)));if e!=nil || monitorParent!=worker.PID {return scope,observationFailure("gateway_monitor_owner")}
	for _,v:=range observed {if v.parent==scope.Monitor.PID && len(v.ids)>level+1 && v.ids[len(v.ids)-1]==1 && v.p.PIDNamespace!=agent.PIDNamespace {if scope.Init.PID!=0&&scope.Init.PID!=v.p.PID {return scope,observationFailure("gateway_private_init_ambiguous")};scope.Init=v.p}}
	if scope.Init.PID==0 || scope.Init.MountNamespace==agent.MountNamespace {return scope,observationFailure("gateway_private_init_missing")}
	for _,v:=range observed {if v.p.PIDNamespace==scope.Init.PIDNamespace || v.p.MountNamespace==scope.Init.MountNamespace || v.p.PID==scope.Monitor.PID {scope.Processes=append(scope.Processes,v.p)}}
	for _,p:=range scope.Processes {current,e:=observationProcess(ctx,filepath.Join(o.HostProc,strconv.Itoa(p.PID)));if e!=nil || current!=p {return scope,observationFailure("gateway_scope_drift")}}
	return scope,nil
}
func gatewayUnexpectedWritableMounts(ctx context.Context,base string,p observedProcess,a gatewayObservationAnchor) error {
	// The shared management namespace is protected by the ORIGINAL Agent entry
	// gates/ledger. A separate live sandbox/sidecar in the same Pod with a writable
	// source alias is a remaining writer even if it has not opened a file yet.
	if p.PIDNamespace==a.Agent.PIDNamespace && p.MountNamespace==a.Agent.MountNamespace || !withinObservation(p.Cgroup,a.Agent.Cgroup) {return nil}
	raw,e:=observationRead(ctx,filepath.Join(base,"mountinfo"),observationReadLimit);if e!=nil {return observationFailure("mount_visibility")}
	for _,line:=range strings.Split(string(raw),"\n") {if line=="" {continue};f:=strings.Fields(line);if mountSeparator(f)<0 {return observationFailure("mount_parse")};readOnly:=false;for _,v:=range strings.Split(f[5],",") {if v=="ro" {readOnly=true}};if readOnly {continue};root,e:=mountUnescape(f[3]);if e!=nil {return e};for _,source:=range a.Paths {device,sourceRoot,e:=observationSourceCoordinate(source);if e!=nil {return e};if device==f[2] && observationRangesOverlap(root,sourceRoot) {return observationFailure("gateway_unexpected_writable_mount")}}}
	return nil
}
func (o *NodeObserver) checkGateway(ctx context.Context,r GatewayNodeObservationRequest,a gatewayObservationAnchor) (int,int,error) {
	p:=make([]string,len(a.Paths));for i,v:=range a.Paths {p[i]=v.Path};paths,e:=o.paths(ctx,p);if e!=nil || !reflect.DeepEqual(paths,a.Paths) {return 0,0,observationFailure("source_mount_drift")}
	s,e:=o.gatewayState(ctx,r,paths);if e!=nil {return 0,0,e}
	if s.Agent!=a.Agent || s.Worker!=a.Worker || s.Lock!=a.Lock || s.BookParent!=a.BookParent || s.LedgerParent!=a.LedgerParent {return 0,0,observationFailure("gateway_agent_or_journal_replaced")}
	recovered:=r.Action=="recovered"
	if !gatewayNativeIdentity(r,s,recovered) {return 0,0,observationFailure("gateway_original_identity")}
	var successor *gatewayNativeScope
	if r.Running!=nil {
		backup:=s.Book.Backup
		if backup==nil || backup.Request!=*r.Running || backup.Stop==nil || !services.ValidateRuntimeBackupReceipt(*r.Running,*backup.Stop) || backup.Stop.State!="stopped" || s.Writer.StoppedBackup!=nil {return 0,0,observationFailure("gateway_v1_reservation")}
		owner,e:=o.gatewayLockOwner(ctx,s.Lock,s.Agent);if e!=nil || owner!=a.Worker {return 0,0,observationFailure("gateway_lock_owner")}
		observation,e:=services.DecodeRuntimeBackupWireObservation(*r.Running,r.RawAction,200,r.Raw);if e!=nil {return 0,0,e}
		if !recovered {
			if backup.State!="stopped" || s.Writer.State!="backup_stopped" || s.Book.Assignment.State!="stopped" || s.Book.Digest!=a.OriginalDigest || observationDigest(s.Writer.Backup)!=observationDigest(backup) || observation.Receipt!=*backup.Stop {return 0,0,observationFailure("gateway_v1_reservation")}
		} else {
			if s.Book.Assignment.State!="running" || s.Book.Digest!=r.Running.RestartSHA256 || backup.Resume==nil || observation.Receipt!=*backup.Resume || backup.Resume.State!="resumed" {return 0,0,observationFailure("gateway_v1_successor")}
			if backup.State=="resumed" {if s.Writer.State!="backup_resumed" || observationDigest(s.Writer.Backup)!=observationDigest(backup) {return 0,0,observationFailure("gateway_v1_successor")}} else if backup.State!="completed" || s.Writer.State!="running" || s.Writer.Backup!=nil {return 0,0,observationFailure("gateway_v1_successor")}
			next,e:=o.gatewayScope(ctx,s.Agent,s.Worker,backup.Resume.PID);if e!=nil {return 0,0,e};if gatewayScopeContains(next.Monitor,a.Scope) || next.Init.PIDNamespace==a.Scope.Init.PIDNamespace {return 0,0,observationFailure("gateway_old_scope_reused")};successor=&next
		}
	} else {
		if s.Book.Assignment.State!="stopped" || s.Book.Digest!=a.OriginalDigest || gatewayStoppedCheckpoint(s.Book,gatewayWriterCore(s.Writer))!=a.Checkpoint || a.Checkpoint!=r.Stopped.CheckpointSHA256 || s.Writer.Backup!=nil || s.Book.Backup!=nil&&s.Book.Backup.State!="completed" {return 0,0,observationFailure("gateway_checkpoint")}
		b:=s.Book.StoppedBackup
		if b==nil || observationDigest(b.Request)!=observationDigest(r.Stopped) || b.Original!=gatewayWriterCore(s.Writer) {return 0,0,observationFailure("gateway_v2_reservation")}
		if r.Action!="recovered-stopped" {
			var raw services.RuntimeStoppedBackupReceipt;if gatewayStrictJSON(r.Raw,&raw)!=nil || b.State!="reserved" || b.Reserved==nil || observationDigest(b.Reserved)!=observationDigest(raw) || s.Writer.State!="stopped_backup_reserved" || observationDigest(s.Writer.StoppedBackup)!=observationDigest(b) {return 0,0,observationFailure("gateway_v2_reservation")}
			owner,e:=o.gatewayLockOwner(ctx,s.Lock,s.Agent);if e!=nil || owner!=a.Worker {return 0,0,observationFailure("gateway_lock_owner")}
		} else {
			completed,e:=services.DecodeRuntimeStoppedBackupWireObservation(*r.Stopped,"complete-kept-stopped",200,r.CompletionRaw);if e!=nil || b.State!="completed" || b.Completed==nil || observationDigest(b.Completed)!=observationDigest(completed.Receipt) || s.Writer.State!="stopped" || s.Writer.StoppedBackup!=nil {return 0,0,observationFailure("gateway_v2_completion")}
			tombstone,ok:=s.Book.StoppedCompletions[r.Stopped.OperationID];if !ok || tombstone.Identity!=r.Stopped.RuntimeStoppedBackupIdentity || tombstone.RequestSHA256!=gatewayRequestSHA(r) {return 0,0,observationFailure("gateway_v2_completion")}
			_,lockErr:=o.gatewayLockOwner(ctx,s.Lock,s.Agent);failure,ok:=lockErr.(NodeObservationFailure);if !ok || failure.Stage!="gateway_lock_not_held" {return 0,0,observationFailure("gateway_v2_release_unconfirmed")}
		}
	}
	n,files,e:=o.gatewayScan(ctx,a,successor);if e!=nil {return 0,0,e}
	// Re-read both actual durable journals and lifecycle owners AFTER every
	// process/FD/maps observation; no native I/O is deferred to SQL recheck.
	last,e:=o.gatewayState(ctx,r,a.Paths);if e!=nil || last.Agent!=s.Agent || last.Worker!=s.Worker || last.Lock!=s.Lock || !reflect.DeepEqual(last.BookRaw,s.BookRaw) || !reflect.DeepEqual(last.WriterRaw,s.WriterRaw) {return 0,0,observationFailure("gateway_journal_drift")}
	if r.Action!="recovered-stopped" {owner,e:=o.gatewayLockOwner(ctx,last.Lock,last.Agent);if e!=nil || owner!=a.Worker {return 0,0,observationFailure("gateway_lock_owner")}} else {_,lockErr:=o.gatewayLockOwner(ctx,last.Lock,last.Agent);failure,ok:=lockErr.(NodeObservationFailure);if !ok || failure.Stage!="gateway_lock_not_held" {return 0,0,observationFailure("gateway_v2_release_unconfirmed")}}
	current,e:=o.paths(ctx,p);if e!=nil || !reflect.DeepEqual(current,a.Paths) {return 0,0,observationFailure("source_mount_drift")}
	return n,files,ctx.Err()
}
func (o *NodeObserver) gatewayScan(ctx context.Context,a gatewayObservationAnchor,successor *gatewayNativeScope) (int,int,error) {
	files,e:=o.files(ctx,a.Paths);if e!=nil {return 0,0,observationFailure("source_tree_visibility")};checked:=map[string]bool{}
	for round:=0;round<2;round++ {tasks,e:=o.tasks(ctx);if e!=nil {return 0,0,e};for _,base:=range tasks {
		p,e:=observationPinTask(ctx,base,o.HostProc);if e!=nil {return 0,0,e};e=func()error{defer p.close();if gatewayScopeContains(p.process,a.Scope) {return observationFailure("original_process_present")};if successor==nil||!gatewayScopeContains(p.process,*successor) {if e:=gatewayUnexpectedWritableMounts(ctx,p.base,p.process,a);e!=nil {return e};if e:=observationWritableHandles(ctx,p.base,o.HostProc,files,a.Paths);e!=nil {return e}};after,e:=observationProcess(ctx,p.base);if e!=nil {if p.exited() {return nil};return observationFailure("task_identity_lost")};if after!=p.process {return observationFailure("task_scope_drift")};checked[strconv.Itoa(after.PID)+":"+after.Start]=true;return nil}();if e!=nil {return 0,0,e}
	}}
	if successor==nil {after,e:=o.files(ctx,a.Paths);if e!=nil || !reflect.DeepEqual(files,after) {return 0,0,observationFailure("source_tree_drift")}}
	return len(checked),len(files),ctx.Err()
}
