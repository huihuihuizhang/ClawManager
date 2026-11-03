//go:build linux

package quiesce

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type observationPinnedTask struct {directory *os.File;pidfd int;base string;process observedProcess}
func observationPinTask(ctx context.Context,base,hostProc string) (*observationPinnedTask,error) {
	parts:=strings.Split(strings.TrimPrefix(base,strings.TrimSuffix(hostProc,"/")+"/"),"/");if len(parts)<1 {return nil,observationFailure("task_identity")};tgid,e:=strconv.Atoi(parts[0]);if e!=nil || tgid<=0 {return nil,observationFailure("task_identity")}
	dir,e:=os.Open(base);if e!=nil {return nil,observationFailure("task_identity_unreadable")}
	fd,e:=unix.PidfdOpen(tgid,0);if e!=nil && !errors.Is(e,unix.ENOSYS) {dir.Close();return nil,observationFailure("task_pidfd_unavailable")};if e!=nil {fd=-1}
	p:=&observationPinnedTask{directory:dir,pidfd:fd,base:filepath.Join("/proc/self/fd",strconv.Itoa(int(dir.Fd())))}
	p.process,e=observationProcess(ctx,p.base);if e!=nil {p.close();return nil,observationFailure("task_identity_unreadable")};return p,nil
}
func (p *observationPinnedTask) close() {p.directory.Close();if p.pidfd>=0 {unix.Close(p.pidfd)}}
// Only after a complete actual disjoint FD/maps observation may a vanished
// NON-source task be resolved as exited. The open proc directory cannot retarget
// a reused PID; pidfd/pinned-proc ESRCH is native evidence, not a swallowed race.
func (p *observationPinnedTask) exited() bool {
	fds:=[]unix.PollFd{{Fd:int32(p.pidfd),Events:unix.POLLIN|unix.POLLHUP}}
	if p.pidfd>=0 {if n,e:=unix.Poll(fds,0);e==nil && n>0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP)!=0 {return true}}
	_,e:=os.ReadFile(filepath.Join(p.base,"stat"));return errors.Is(e,unix.ESRCH)||errors.Is(e,os.ErrNotExist)
}

type observationMount struct {ID,Device,Root,Point string}
func observationMountTable(ctx context.Context,base string) ([]observationMount,error) {
	b,e:=observationRead(ctx,filepath.Join(base,"mountinfo"),observationReadLimit);if e!=nil {return nil,observationFailure("mount_visibility")}
	var out []observationMount
	for _,line:=range strings.Split(string(b),"\n") {if line=="" {continue};f:=strings.Fields(line);if mountSeparator(f)<0 {return nil,observationFailure("mount_parse")};root,e:=mountUnescape(f[3]);if e!=nil {return nil,e};point,e:=mountUnescape(f[4]);if e!=nil || !absoluteObservationPath(root) || !absoluteObservationPath(point) {return nil,observationFailure("mount_parse")};out=append(out,observationMount{f[0],f[2],root,point})}
	return out,nil
}
func observationSourceCoordinate(source observedPath) (string,string,error) {
	f:=strings.Fields(source.Mount);if mountSeparator(f)<0 {return "","",ErrNodeObservation}
	root,e:=mountUnescape(f[3]);if e!=nil {return "","",e};point,e:=mountUnescape(f[4]);if e!=nil || !withinObservation(source.Path,point) {return "","",ErrNodeObservation}
	return f[2],path.Join(root,strings.TrimPrefix(strings.TrimPrefix(source.Path,point),"/")),nil
}
func observationRangesOverlap(a,b string) bool {return withinObservation(a,b)||withinObservation(b,a)}
func observationMountsDisjoint(mounts []observationMount,sources []observedPath) bool {
	for _,m:=range mounts {for _,s:=range sources {device,root,e:=observationSourceCoordinate(s);if e!=nil {return false};if m.Device==device && observationRangesOverlap(m.Root,root) {return false}}};return true
}
func observationPhysicalPathDisjoint(m observationMount,target string,sources []observedPath) bool {
	if !absoluteObservationPath(target) || !withinObservation(target,m.Point) {return false}
	physical:=path.Join(m.Root,strings.TrimPrefix(strings.TrimPrefix(target,m.Point),"/"))
	for _,s:=range sources {device,root,e:=observationSourceCoordinate(s);if e!=nil || m.Device==device && withinObservation(physical,root) {return false}}
	return true
}
func observationSameHostMountNamespace(base,hostProc string) bool {
	p,e:=os.Readlink(filepath.Join(base,"ns/mnt"));if e!=nil {return false}
	h,e:=os.Readlink(filepath.Join(hostProc,"1/ns/mnt"));return e==nil && p==h
}
// Deleted inodes outside the source are not rejected merely because their
// superblock also backs hostPath. Use the actual FD mount ID (not the pathname
// alone) and its bind-root coordinate. Namespace-ambiguous aliases stay unknown.
func observationDeletedFDDisjoint(ctx context.Context,base,hostProc,link,mountID,device string,mounts []observationMount,sources []observedPath) bool {
	for _,m:=range mounts {if m.ID!=mountID || m.Device!=device {continue}
		intersects:=false
		for _,s:=range sources {d,root,e:=observationSourceCoordinate(s);if e!=nil {return false};if d==device && observationRangesOverlap(m.Root,root) {intersects=true}}
		if !intersects {return true}
		if !observationSameHostMountNamespace(base,hostProc) {return false}
		target:=strings.TrimSuffix(link," (deleted)")
		return observationPhysicalPathDisjoint(m,target,sources)
	};return false
}
func observationDeletedMapDisjoint(base,hostProc,target,device string,mounts []observationMount,sources []observedPath) bool {
	for _,s:=range sources {if strings.ContainsAny(s.Path," \t\\") {return false}}
	if observationMountsDisjoint(mounts,sources) {return true}
	if !observationSameHostMountNamespace(base,hostProc) {return false}
	target=strings.TrimSuffix(target," (deleted)")
	var selected observationMount;longest:=-1
	for _,m:=range mounts {if withinObservation(target,m.Point) && len(m.Point)>longest {selected=m;longest=len(m.Point)}}
	return longest>=0 && selected.Device==device && observationPhysicalPathDisjoint(selected,target,sources)
}
func observationFDInfo(ctx context.Context,base,name string) (uint64,string,[]byte,error) {
	b,e:=observationRead(ctx,filepath.Join(base,"fdinfo",name),observationReadLimit);if e!=nil {return 0,"",nil,observationFailure("fdinfo_visibility")}
	var flags uint64;id:="";found:=false
	for _,line:=range strings.Split(string(b),"\n") {if strings.HasPrefix(line,"flags:") {flags,e=strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line,"flags:")),8,64);if e!=nil {return 0,"",nil,observationFailure("fdinfo_parse")};found=true};if strings.HasPrefix(line,"mnt_id:") {id=strings.TrimSpace(strings.TrimPrefix(line,"mnt_id:"));if _,e=strconv.ParseUint(id,10,64);e!=nil {return 0,"",nil,observationFailure("fdinfo_parse")}}}
	if !found || id=="" {return 0,"",nil,observationFailure("fdinfo_parse")};return flags,id,b,nil
}
