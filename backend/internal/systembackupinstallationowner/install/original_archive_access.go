package install

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
)

type originalCustodyAccess struct {
	Version, RootIdentitySHA256, Boundary  string
	Processes, DescriptorSets, MappingSets int
}

func custodyWithin(root, path string) bool {
	path = strings.TrimSuffix(path, " (deleted)")
	return path == root || strings.HasPrefix(path, root+string(os.PathSeparator))
}

func (p *OriginalAdoptionArchiveProvider) stableCustodyStorageIdentity() string {
	info, err := os.Lstat(p.definition.CustodyRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ""
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return ""
	}
	fields := []string{"Dev", "Ino", "Uid"}
	numbers := make([]uint64, 3)
	for n, name := range fields {
		field := value.FieldByName(name)
		if !field.IsValid() || !field.CanUint() {
			return ""
		}
		numbers[n] = field.Uint()
	}
	if numbers[2] != uint64(os.Geteuid()) {
		return ""
	}
	raw, err := canonical(struct {
		Installation, Node, Path string
		Device, Inode, UID       uint64
	}{
		p.reservation.InstallationID, p.minio.Grant.Provider.NodeUID, p.definition.CustodyRoot, numbers[0], numbers[1], numbers[2]})
	if err != nil {
		return ""
	}
	return hash(raw)
}

// Real native current FD/mmap census, under the same custody lock. It is one
// necessary access-isolation fact in the original TRUSTED finite-host-writer
// model, not proof against malicious host root or future unregistered writers.
// B's original actual writer/reconciler/upgrade entry fence remains mandatory.
// No callback or caller Passed field can replace this native observation.
func (p *OriginalAdoptionArchiveProvider) inspectNativeOriginalCustodyAccess() (originalCustodyAccess, error) {
	result := originalCustodyAccess{Version: "original-native-custody-fd-mmap-census.v1",
		RootIdentitySHA256: p.custodyIdentity(), Boundary: "requires-original-complete-trusted-host-actors-and-current-entry-fence"}
	if runtime.GOOS != "linux" || result.RootIdentitySHA256 == "" {
		return originalCustodyAccess{}, ErrInstall
	}
	root := p.definition.CustodyRoot
	// Do not claim persistent retention for standard ephemeral cleanup roots.
	for _, temporary := range []string{"/tmp", "/var/tmp", "/run", "/dev/shm"} {
		if custodyWithin(temporary, root) {
			return originalCustodyAccess{}, ErrInstall
		}
	}
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return originalCustodyAccess{}, ErrInstall
	}
	for _, process := range processes {
		if p.ctx.Err() != nil {
			return originalCustodyAccess{}, ErrInstall
		}
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		result.Processes++
		if result.Processes > 100000 {
			return originalCustodyAccess{}, ErrInstall
		}
		base := filepath.Join("/proc", process.Name())
		fds, err := os.ReadDir(filepath.Join(base, "fd"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return originalCustodyAccess{}, ErrInstall
		}
		result.DescriptorSets++
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return originalCustodyAccess{}, ErrInstall
			}
			if !custodyWithin(root, target) {
				continue
			}
			flagsRaw, err := os.ReadFile(filepath.Join(base, "fdinfo", fd.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return originalCustodyAccess{}, ErrInstall
			}
			found := false
			for _, line := range strings.Split(string(flagsRaw), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 2 || fields[0] != "flags:" {
					continue
				}
				flags, err := strconv.ParseUint(fields[1], 8, 64)
				if err != nil {
					return originalCustodyAccess{}, ErrInstall
				}
				found = true
				// All versions and journals must have NO writable descriptors.
				// Waiting owners may open ONLY the stable shared control lock.
				if flags&3 != 0 && target != filepath.Join(root, ".custody.lock") {
					return originalCustodyAccess{}, ErrInstall
				}
			}
			if !found {
				return originalCustodyAccess{}, ErrInstall
			}
		}
		maps, err := os.ReadFile(filepath.Join(base, "maps"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return originalCustodyAccess{}, ErrInstall
		}
		result.MappingSets++
		for _, line := range strings.Split(string(maps), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			if strings.Contains(fields[1], "w") && strings.Contains(fields[1], "s") && custodyWithin(root, strings.Join(fields[5:], " ")) {
				return originalCustodyAccess{}, ErrInstall
			}
		}
	}
	return result, nil
}
