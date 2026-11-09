package install

import (
	"path"
	"slices"
	"strings"
)

// Append the opt-in update for the shared Node owner only. The operator must
// drain backup execution before disabling and stopping the unit. The existing
// install lock serializes reruns and the persistent owner store is retained.
func sharedObserverUpdateScript(script *strings.Builder, binaryDirectory string, kinds []string) {
	if !slices.Contains(kinds, "shared") {
		script.WriteString("[[ $# == 1 ]] || exit 30\n")
		return
	}
	const binary = "backup-shared-runtime-node-owner"
	const unit = "clawreef-" + binary + ".service"
	script.WriteString("shared_binary=" + observerShellArg(path.Join(binaryDirectory, binary)) + "\n")
	script.WriteString("shared_unit=" + observerShellArg(path.Join("/etc/systemd/system", unit)) + "\n")
	script.WriteString(`shared_update=0
check_update_target() {
    local source=$1 target=$2 mode=$3 previous=$4 installed next
    [[ -f $target && ! -L $target && $(stat -c %u:%g:%a -- "$target") == "0:0:$mode" ]] || return 1
    installed=$(sha256sum -- "$target" | cut -d ' ' -f 1) || return 1
    next=$(sha256sum -- "$source" | cut -d ' ' -f 1) || return 1
    [[ $installed == "$previous" || $installed == "$next" ]]
}
replace_update_target() (
    local source=$1 target=$2 mode=$3 previous=$4 temporary
    check_update_target "$source" "$target" "$mode" "$previous" || exit 30
    cmp -s -- "$source" "$target" && exit 0
    temporary=$(mktemp -- "${target}.update.XXXXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    install -o 0 -g 0 -m "$mode" -- "$source" "$temporary"
    sync -f -- "$temporary"
    mv -T -- "$temporary" "$target"
    sync -f -- "$(dirname -- "$target")"
)
shared_stopped() {
    local unit=${shared_unit##*/} dropins
    dropins=$(systemctl show --property=DropInPaths --value "$unit") || return 1
    [[ $(systemctl show --property=LoadState --value "$unit") == loaded &&
       $(systemctl show --property=FragmentPath --value "$unit") == "$shared_unit" &&
       -z $dropins &&
       $(systemctl show --property=UnitFileState --value "$unit") == disabled &&
       $(systemctl show --property=ActiveState --value "$unit") == inactive &&
       $(systemctl show --property=MainPID --value "$unit") == 0 &&
       $(systemctl show --property=ControlPID --value "$unit") == 0 ]]
}
if [[ $# != 1 ]]; then
    [[ $# == 4 && $2 == --update-shared && $3 =~ ^[0-9a-f]{64}$ && $4 =~ ^[0-9a-f]{64}$ ]] || exit 30
    for tool in cmp mktemp mv; do command -v "$tool" >/dev/null || exit 22; done
    shared_stopped || exit 30
    check_update_target ` + binary + ` "$shared_binary" 755 "$3" || exit 30
    check_update_target ` + unit + ` "$shared_unit" 644 "$4" || exit 30
    shared_update=1
fi
`)
}
