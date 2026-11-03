//go:build linux

package quiesce

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const observationReadLimit = 16 << 20

// ReadNodeObservationKey requires a root-owned private deployment path; a
// controller request can never select this key or replace the native reader.
func ReadNodeObservationKey(p string) ([]byte,error) {
	if !absoluteObservationPath(p) {return nil,ErrNodeObservation}
	current:="/"
	for _,part:=range strings.Split(strings.TrimPrefix(filepath.Dir(p),"/"),"/") {if part=="" {continue};current=filepath.Join(current,part);var st unix.Stat_t;if unix.Lstat(current,&st)!=nil || st.Mode&unix.S_IFMT!=unix.S_IFDIR || st.Uid!=0 || st.Mode&0022!=0 {return nil,ErrNodeObservation}}
	fd,e:=unix.Open(p,unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,0);if e!=nil {return nil,ErrNodeObservation};f:=os.NewFile(uintptr(fd),p);defer f.Close()
	var st unix.Stat_t;if unix.Fstat(fd,&st)!=nil || st.Uid!=0 || st.Mode&unix.S_IFMT!=unix.S_IFREG || st.Mode&0777!=0600 || st.Size!=32 {return nil,ErrNodeObservation}
	b,e:=io.ReadAll(io.LimitReader(f,33));if e!=nil || len(b)!=32 {return nil,ErrNodeObservation};return b,nil
}

func observationRead(ctx context.Context,p string,limit int64) ([]byte,error) {
	if ctx.Err()!=nil { return nil,ErrNodeObservation }
	f,e:=os.Open(p);if e!=nil {return nil,ErrNodeObservation};defer f.Close()
	b,e:=io.ReadAll(io.LimitReader(f,limit+1))
	if e!=nil || int64(len(b))>limit || ctx.Err()!=nil {return nil,ErrNodeObservation};return b,nil
}
func (o *NodeObserver) hostIdentity(ctx context.Context) error {
	if os.Geteuid()!=0 {return ErrNodeObservation}
	b,e:=observationRead(ctx,filepath.Join(o.HostProc,"sys/kernel/random/boot_id"),256);if e!=nil || strings.TrimSpace(string(b))!=o.BootID {return ErrNodeObservation}
	b,e=observationRead(ctx,filepath.Join(o.HostRoot,"etc/machine-id"),256);if e!=nil || strings.TrimSpace(string(b))!=o.MachineID {return ErrNodeObservation}
	// Require the initial PID namespace (hostPID deployment), not a private
	// procfs whose process census merely looks complete inside a container.
	one,e:=os.Readlink(filepath.Join(o.HostProc,"1/ns/pid"));if e!=nil {return ErrNodeObservation}
	self,e:=os.Readlink("/proc/self/ns/pid");if e!=nil || self!=one {return ErrNodeObservation}
	hostSelf,e:=os.Readlink(filepath.Join(o.HostProc,strconv.Itoa(os.Getpid()),"ns/pid"));if e!=nil || hostSelf!=self {return ErrNodeObservation}
	hostCG,e:=os.Readlink(filepath.Join(o.HostProc,"1/ns/cgroup"));if e!=nil {return ErrNodeObservation}
	selfCG,e:=os.Readlink("/proc/self/ns/cgroup");if e!=nil || selfCG!=hostCG {return ErrNodeObservation}
	var st unix.Statfs_t
	if unix.Statfs(o.HostProc,&st)!=nil || uint64(st.Type)!=uint64(unix.PROC_SUPER_MAGIC) {return ErrNodeObservation}
	// hidepid/subset modes make a supposedly successful full enumeration unsafe.
	m,e:=observationRead(ctx,filepath.Join(o.HostProc,"1/mountinfo"),observationReadLimit);if e!=nil {return e}
	found:=false
	for _,line:=range strings.Split(string(m),"\n") {f:=strings.Fields(line);if len(f)<10 {continue};sep:=mountSeparator(f);if sep<0 {continue};if f[sep+1]=="proc" && f[4]=="/proc" {found=true;for _,opt:=range []string{f[5],f[sep+3]} {for _,v:=range strings.Split(opt,",") {if strings.HasPrefix(v,"hidepid=") && v!="hidepid=0" || strings.HasPrefix(v,"subset=") {return ErrNodeObservation}}}}}
	if !found {return ErrNodeObservation};return ctx.Err()
}
func mountSeparator(f []string) int {for i,s:=range f {if s=="-" && i>=6 && i+3<len(f) {return i}};return -1}
func mountUnescape(s string) (string,error) {
	var b strings.Builder
	for i:=0;i<len(s);i++ {if s[i]!='\\' {b.WriteByte(s[i]);continue};if i+3>=len(s) {return "",ErrNodeObservation};n,e:=strconv.ParseUint(s[i+1:i+4],8,8);if e!=nil || n==0 {return "",ErrNodeObservation};b.WriteByte(byte(n));i+=3};return b.String(),nil
}
func withinObservation(p,root string) bool {return p==root || strings.HasPrefix(p,strings.TrimSuffix(root,"/")+"/")}
func (o *NodeObserver) sourceNativePath(p string) (string,error) {
	if !absoluteObservationPath(p) || p=="/" {return "",ErrNodeObservation}
	current:=o.HostRoot
	for _,part:=range strings.Split(strings.TrimPrefix(p,"/"),"/") {current=filepath.Join(current,part);s,e:=os.Lstat(current);if e!=nil || s.Mode()&os.ModeSymlink!=0 {return "",ErrNodeObservation}}
	return current,nil
}
func (o *NodeObserver) paths(ctx context.Context,paths []string) ([]observedPath,error) {
	raw,e:=observationRead(ctx,filepath.Join(o.HostProc,"1/mountinfo"),observationReadLimit);if e!=nil {return nil,e}
	var out []observedPath
	for _,p:=range paths {
		native,e:=o.sourceNativePath(p);if e!=nil {return nil,e};var st unix.Stat_t;if unix.Stat(native,&st)!=nil {return nil,ErrNodeObservation}
		best:="";bestLen:=-1
		for _,line:=range strings.Split(string(raw),"\n") {
			f:=strings.Fields(line);if len(f)==0 {continue};sep:=mountSeparator(f);if sep<0 {return nil,ErrNodeObservation}
			mp,e:=mountUnescape(f[4]);if e!=nil {return nil,e}
			// A nested mount may hide part of the source subtree from the census.
			if mp!=p && withinObservation(mp,p) {return nil,ErrNodeObservation}
			if withinObservation(p,mp) && len(mp)>bestLen {
				// This slice handles local hostPath filesystems. External/network
				// writers require their own native observer and shared fence.
				best=line;bestLen=len(mp)
			}
		}
		if best=="" {return nil,ErrNodeObservation}
		f:=strings.Fields(best);sep:=mountSeparator(f)
		if (f[sep+1]!="ext4" && f[sep+1]!="xfs") || f[2]!=fmt.Sprintf("%d:%d",unix.Major(uint64(st.Dev)),unix.Minor(uint64(st.Dev))) {return nil,ErrNodeObservation}
		out=append(out,observedPath{Path:p,Device:uint64(st.Dev),Inode:st.Ino,Mount:best})
	}
	return out,ctx.Err()
}

func observationProcess(ctx context.Context,base string) (observedProcess,error) {
	var out observedProcess
	b,e:=observationRead(ctx,filepath.Join(base,"stat"),64<<10);if e!=nil {return out,e}
	s:=string(b);i:=strings.LastIndex(s,") ");if i<0 {return out,ErrNodeObservation}
	space:=strings.Index(s," ");if space<=0 {return out,ErrNodeObservation}
	pid,e:=strconv.Atoi(s[:space]);if e!=nil || pid<=0 {return out,ErrNodeObservation}
	f:=strings.Fields(s[i+2:]);if len(f)<20 {return out,ErrNodeObservation}
	out.PID=pid;out.Start=f[19];if _,e=strconv.ParseUint(out.Start,10,64);e!=nil {return out,ErrNodeObservation}
	out.PIDNamespace,e=os.Readlink(filepath.Join(base,"ns/pid"));if e!=nil {return out,ErrNodeObservation}
	out.MountNamespace,e=os.Readlink(filepath.Join(base,"ns/mnt"));if e!=nil {return out,ErrNodeObservation}
	b,e=observationRead(ctx,filepath.Join(base,"cgroup"),64<<10);if e!=nil {return out,e}
	for _,l:=range strings.Split(strings.TrimSpace(string(b)),"\n") {if strings.HasPrefix(l,"0::/") {out.Cgroup=strings.TrimPrefix(l,"0::")}}
	if out.Cgroup=="" || !absoluteObservationPath(out.Cgroup) {return out,ErrNodeObservation}
	return out,nil
}
func observationPodCgroup(cgroup,uid string) (string,error) {
	parts:=strings.Split(strings.TrimPrefix(cgroup,"/"),"/")
	for i,s:=range parts {if s=="pod"+uid || strings.HasSuffix(s,"-pod"+strings.ReplaceAll(uid,"-","_")+".slice") {return "/"+strings.Join(parts[:i+1],"/"),nil}}
	return "",ErrNodeObservation
}
func (o *NodeObserver) running(ctx context.Context,b ObservationBinding,pods []PodIdentity,paths []observedPath) ([]observedProcess,error) {
	var out []observedProcess
	matchedPaths:=map[string]bool{}
	for _,pod:=range pods {for _,cid:=range pod.Containers {
		id:=strings.Split(cid,"://")[1];raw,e:=o.CRI.Inspect(ctx,id);if e!=nil {return nil,ErrNodeObservation}
		var v struct {
			Status struct {ID string `json:"id"`;State json.RawMessage `json:"state"`;Labels map[string]string `json:"labels"`;Mounts []struct {HostPath string `json:"hostPath"`;ContainerPath string `json:"containerPath"`;Readonly bool `json:"readonly"`} `json:"mounts"`} `json:"status"`
			Info struct {PID json.Number `json:"pid"`} `json:"info"`
		}
		if json.Unmarshal(raw,&v)!=nil || v.Status.ID!=id || v.Status.Labels["io.kubernetes.pod.uid"]!=pod.UID || v.Status.Labels["io.kubernetes.pod.namespace"]!=b.Namespace || v.Status.Labels["io.kubernetes.pod.name"]!=pod.Name {return nil,ErrNodeObservation}
		state:=strings.Trim(string(v.Status.State),"\"");if state!="CONTAINER_RUNNING" && state!="1" {return nil,ErrNodeObservation}
		pid,e:=strconv.Atoi(v.Info.PID.String());if e!=nil || pid<=1 {return nil,ErrNodeObservation}
		base:=filepath.Join(o.HostProc,strconv.Itoa(pid));p,e:=observationProcess(ctx,base);if e!=nil {return nil,e}
		if !strings.Contains(p.Cgroup,id) {return nil,ErrNodeObservation}
		cg,e:=observationPodCgroup(p.Cgroup,pod.UID);if e!=nil {return nil,e};p.Cgroup=cg
		hostNS,e:=os.Readlink(filepath.Join(o.HostProc,"1/ns/pid"));if e!=nil || p.PIDNamespace==hostNS {return nil,ErrNodeObservation}
		// Every requested source must be a real writable CRI mount in at least
		// one container. Validate via actual device/inode, not path spelling.
		for _,m:=range v.Status.Mounts {if m.Readonly {continue};for _,src:=range paths {
			if !withinObservation(src.Path,m.HostPath) || !absoluteObservationPath(m.ContainerPath) {continue}
			suffix:=strings.TrimPrefix(src.Path,m.HostPath);target:=filepath.Join(base,"root",m.ContainerPath,strings.TrimPrefix(suffix,"/"));var st unix.Stat_t
			if unix.Stat(target,&st)!=nil || uint64(st.Dev)!=src.Device || st.Ino!=src.Inode {return nil,ErrNodeObservation}
			matchedPaths[src.Path]=true
		}}
		out=append(out,p)
	}}
	// Check coverage separately: no requested source may be silently unmatched.
	for _,src:=range paths {if !matchedPaths[src.Path] {return nil,ErrNodeObservation}}
	// Re-read the original PID to reject PID reuse/drift during CRI/mount I/O.
	for _,p:=range out {current,e:=observationProcess(ctx,filepath.Join(o.HostProc,strconv.Itoa(p.PID)));if e!=nil || current.Start!=p.Start || current.PIDNamespace!=p.PIDNamespace || current.MountNamespace!=p.MountNamespace || !withinObservation(current.Cgroup,p.Cgroup) {return nil,ErrNodeObservation}}
	return out,ctx.Err()
}

type observationInode struct {Major,Minor uint32;Inode uint64}
type observationFileState struct {Size int64;Mtime,Ctime unix.Timespec;Mode uint32;Links uint64}
func (o *NodeObserver) files(ctx context.Context,paths []observedPath) (map[observationInode]observationFileState,error) {
	out:=map[observationInode]observationFileState{}
	for _,source:=range paths {native,e:=o.sourceNativePath(source.Path);if e!=nil {return nil,e}
		e=filepath.WalkDir(native,func(p string,d os.DirEntry,e error) error {
			if e!=nil || ctx.Err()!=nil || len(out)>=100000 {return ErrNodeObservation}
			if d.Type()&os.ModeSymlink!=0 {return ErrNodeObservation}
			var s unix.Stat_t;if unix.Lstat(p,&s)!=nil || uint64(s.Dev)!=source.Device {return ErrNodeObservation}
			if s.Mode&unix.S_IFMT!=unix.S_IFREG && s.Mode&unix.S_IFMT!=unix.S_IFDIR {return ErrNodeObservation}
			out[observationInode{unix.Major(uint64(s.Dev)),unix.Minor(uint64(s.Dev)),s.Ino}]=observationFileState{s.Size,s.Mtim,s.Ctim,s.Mode,uint64(s.Nlink)};return nil
		});if e!=nil {return nil,ErrNodeObservation}
	}
	return out,ctx.Err()
}
func (o *NodeObserver) tasks(ctx context.Context) ([]string,error) {
	entries,e:=os.ReadDir(o.HostProc);if e!=nil {return nil,ErrNodeObservation};var out []string
	for _,entry:=range entries {if _,e:=strconv.ParseUint(entry.Name(),10,32);e!=nil {continue}
		base:=filepath.Join(o.HostProc,entry.Name(),"task");threads,e:=os.ReadDir(base);if e!=nil {return nil,ErrNodeObservation}
		for _,t:=range threads {if _,e:=strconv.ParseUint(t.Name(),10,32);e!=nil {return nil,ErrNodeObservation};out=append(out,filepath.Join(base,t.Name()));if len(out)>100000 || ctx.Err()!=nil {return nil,ErrNodeObservation}}
	};sort.Strings(out);if len(out)==0 {return nil,ErrNodeObservation};return out,nil
}
func (o *NodeObserver) originalScopes(ctx context.Context,a nodeObservationAnchor) ([]observedProcess,error) {
	tasks,e:=o.tasks(ctx);if e!=nil {return nil,e};out:=append([]observedProcess(nil),a.Processes...)
	for _,base:=range tasks {p,e:=observationProcess(ctx,base);if e!=nil {return nil,e};if originalObservationScope(p,a) {out=append(out,p)}}
	for _,p:=range out {current,e:=observationProcess(ctx,filepath.Join(o.HostProc,strconv.Itoa(p.PID)));if e!=nil || !withinObservation(current.Cgroup,p.Cgroup) {return nil,ErrNodeObservation};current.Cgroup=p.Cgroup;if !reflect.DeepEqual(current,p) {return nil,ErrNodeObservation}}
	return out,ctx.Err()
}
func originalObservationScope(p observedProcess,a nodeObservationAnchor) bool {
	for _,old:=range a.Processes {if p.PID==old.PID && p.Start==old.Start || p.PIDNamespace==old.PIDNamespace || p.MountNamespace==old.MountNamespace || withinObservation(p.Cgroup,old.Cgroup) {return true}};return false
}
func observationWritableHandles(ctx context.Context,base,hostProc string,files map[observationInode]observationFileState,sources []observedPath) error {
	mounts,e:=observationMountTable(ctx,base);if e!=nil {return e}
	// Keep this directory FD open while scanning: when observing this process,
	// ReadDir(path) would otherwise list and close its own FD before inspection.
	directory,e:=os.Open(filepath.Join(base,"fd"));if e!=nil {return observationFailure("fd_visibility")};defer directory.Close()
	fds,e:=directory.ReadDir(-1);if e!=nil || len(fds)>100000 {return observationFailure("fd_visibility")}
	for _,fd:=range fds {
		p:=filepath.Join(base,"fd",fd.Name());link,e:=os.Readlink(p);if e!=nil {return observationFailure("fd_visibility")}
		flags,mountID,_,e:=observationFDInfo(ctx,base,fd.Name());if e!=nil {return e}
		// An unrelated container whose actual bind roots cannot reach any
		// source is not blocked by async I/O. If a source is reachable, proc
		// cannot prove all in-flight/registered requests drained: stay unknown.
		if strings.Contains(link,"io_uring") {if !observationMountsDisjoint(mounts,sources) {return observationFailure("async_source_scope_unknown")};continue}
		var s unix.Stat_t;if unix.Stat(p,&s)!=nil {return observationFailure("fd_visibility")}
		afterFlags,afterMountID,_,e:=observationFDInfo(ctx,base,fd.Name());if e!=nil {return e};var afterStat unix.Stat_t
		if unix.Stat(p,&afterStat)!=nil || afterFlags!=flags || afterMountID!=mountID || afterStat.Dev!=s.Dev || afterStat.Ino!=s.Ino {return observationFailure("fd_identity_drift")}
		if flags&uint64(unix.O_ACCMODE)==uint64(unix.O_RDONLY) {continue}
		if (s.Nlink==0 || strings.HasSuffix(link," (deleted)")) && s.Mode&unix.S_IFMT==unix.S_IFREG {for inode:=range files {if inode.Major==unix.Major(uint64(s.Dev)) && inode.Minor==unix.Minor(uint64(s.Dev)) {if !observationDeletedFDDisjoint(ctx,base,hostProc,link,mountID,fmt.Sprintf("%d:%d",inode.Major,inode.Minor),mounts,sources) {return observationFailure("deleted_source_fd_unknown")};break}}}
		if _,ok:=files[observationInode{unix.Major(uint64(s.Dev)),unix.Minor(uint64(s.Dev)),s.Ino}];!ok {continue}
		return observationFailure("writable_source_fd")
	}
	raw,e:=observationRead(ctx,filepath.Join(base,"maps"),observationReadLimit);if e!=nil {return observationFailure("maps_visibility")}
	for _,line:=range strings.Split(string(raw),"\n") {if line=="" {continue};f:=strings.Fields(line);if len(f)<5 || len(f[1])!=4 {return observationFailure("maps_parse")};if f[1][1]!='w' || f[1][3]!='s' {continue}
		dev:=strings.Split(f[3],":");if len(dev)!=2 {return ErrNodeObservation};major,e:=strconv.ParseUint(dev[0],16,32);if e!=nil {return ErrNodeObservation};minor,e:=strconv.ParseUint(dev[1],16,32);if e!=nil {return ErrNodeObservation};ino,e:=strconv.ParseUint(f[4],10,64);if e!=nil {return ErrNodeObservation}
		if strings.HasSuffix(line," (deleted)") {for inode:=range files {if inode.Major==uint32(major) && inode.Minor==uint32(minor) {target:=strings.Join(f[5:]," ");if !observationDeletedMapDisjoint(base,hostProc,target,fmt.Sprintf("%d:%d",major,minor),mounts,sources) {return observationFailure("deleted_source_mapping_unknown")};break}}}
		if _,ok:=files[observationInode{uint32(major),uint32(minor),ino}];ok {return observationFailure("writable_source_mapping")}
	}
	return ctx.Err()
}
func (o *NodeObserver) scan(ctx context.Context,a nodeObservationAnchor,files map[observationInode]observationFileState) (int,[]observedProcess,error) {
	seen:=map[string]observedProcess{}
	// Observe two actual host enumerations; unrelated creation/exit does not
	// require identical host lists. Every enumerated live task is inspected;
	// unreadable initial identities or incomplete handle scans remain unknown.
	for round:=0;round<2;round++ {
		tasks,e:=o.tasks(ctx);if e!=nil {return 0,nil,observationFailure("task_enumeration")}
		for _,base:=range tasks {
			p,e:=observationPinTask(ctx,base,o.HostProc);if e!=nil {return 0,nil,e}
			e=func()error {defer p.close()
				if originalObservationScope(p.process,a) {return observationFailure("original_process_present")}
				if files!=nil {if e:=observationWritableHandles(ctx,p.base,o.HostProc,files,a.Paths);e!=nil {return e}}
				after,e:=observationProcess(ctx,p.base)
				if e!=nil {if p.exited() {return nil};return observationFailure("task_identity_lost")}
				if !reflect.DeepEqual(p.process,after) {return observationFailure("task_scope_drift")}
				seen[strconv.Itoa(after.PID)+":"+after.Start]=after;return nil
			}();if e!=nil {return 0,nil,e}
		}
	}
	observed:=make([]observedProcess,0,len(seen));for _,p:=range seen {observed=append(observed,p)}
	return len(seen),observed,ctx.Err()
}
func (o *NodeObserver) stopped(ctx context.Context,a nodeObservationAnchor) (int,int,error) {
	files,e:=o.files(ctx,a.Paths);if e!=nil {return 0,0,observationFailure("source_tree_visibility")}
	n,_,e:=o.scan(ctx,a,files);if e!=nil {return 0,0,e}
	after,e:=o.files(ctx,a.Paths);if e!=nil || !reflect.DeepEqual(files,after) {return 0,0,observationFailure("source_tree_drift")}
	p:=make([]string,len(a.Paths));for i,s:=range a.Paths {p[i]=s.Path};paths,e:=o.paths(ctx,p);if e!=nil || !reflect.DeepEqual(paths,a.Paths) {return 0,0,observationFailure("source_mount_drift")}
	return n,len(files),ctx.Err()
}
