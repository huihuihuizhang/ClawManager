"""Early original NFS/SSH shape observation: after init, BEFORE any DB DDL.

Uses only the original pinned kubeconfig, direct pinned root SSH and sealed
read-only native observation actions. No SQL connection, enrollment, image
publication, Pod/Deployment/Secret mutation, pause, syncfs or hold is issued.
Private helper/journal files and temporary namespace observation handles are
operational artifacts. A successful shape read is NEVER backup qualification.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import stat


class EarlyPreflightRefused(Exception):
    def __init__(self,result):
        super().__init__(result["reason_code"] or "early_original_shape_unconfirmed")
        self.result=result


def load_sealed(operator,name):
    relative="scripts/"+name
    path=operator.root/relative
    pin=operator.pins["files"].get(relative)
    if not pin or path.resolve(strict=True) != path or hashlib.sha256(path.read_bytes()).hexdigest() != pin:
        raise RuntimeError("sealed_original_preflight_dependency_changed:"+name)
    spec=importlib.util.spec_from_file_location("early_"+name.replace("-","_").replace(".","_"),path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_ssh_materials(operator,module):
    key=operator.a.deployment_ssh_key_file
    known=operator.a.deployment_known_hosts_file
    cri=operator.a.deployment_crictl_file
    module.need(key is not None and known is not None and cri is not None,"both_actual_source_nodes_require_existing_direct_ssh_key_pinned_known_hosts_and_official_crictl")
    module.read(key,limit=65536)
    module.read(known,private=False)
    for path in (Path(key),Path(known)):
        info=path.stat()
        module.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode&0o022 == 0,"original_ssh_material_not_owned_or_writable_by_other_users")
    module.need(module.digest(module.read(cri,private=False,limit=64<<20)) == module.CRI_SHA,"sealed_official_crictl_release_required_before_ddl")


def read_only_owner(operator):
    # Operator.open validates the original sealed release, exact static TLS
    # kubeconfig, namespace/deployment UIDs and cluster identity. It does not
    # call upgraded_released, DB helpers, installer CLI or enrollment.
    operator.open()
    deployment=load_sealed(operator,"system-backup-operator-deployment.py")
    workspace=load_sealed(operator,"system-backup-workspace-localization.py")
    deployment.need(workspace.NATIVE_SHA == operator.pins["files"].get("scripts/system-backup-workspace-native.py"),"paired_original_native_and_workspace_source_required")
    private_ssh_materials(operator,deployment)
    owner=workspace.WorkspaceLocalization.__new__(workspace.WorkspaceLocalization)
    owner.op=operator
    owner.m=deployment
    owner.stages=deployment.DeploymentStages(operator)
    owner.sessions=[]
    return owner,workspace,deployment


def cleanup(operator):
    owner,workspace,module=read_only_owner(operator)
    module.need(not (owner.stages.directory/"workspace-localization.plan.json").exists(),"actual_forward_plan_exists_use_original_workspace_recovery")
    released=[]
    try:
        for path in sorted(owner.stages.directory.glob("workspace-native-definition-*.json")):
            definition=module.decode(module.read(path))
            module.need(definition["operation"] == owner.stages.operation,"same_original_readonly_preflight_operation_required")
            receipts=owner.stages.directory.glob("workspace-native-"+definition["session"]+"-*.actual-observation.json")
            retired=any((lambda value:value.get("action") == "retire-owner" and value.get("operation") == owner.stages.operation and value.get("session") == definition["session"] and value.get("data",{}).get("all_original_fds_released") is True)(module.decode(module.read(receipt))) for receipt in receipts)
            if retired:
                continue
            node=module.decode(operator.k("get","node",definition["node"]["name"],"-o","json"))
            session=workspace.NativeSession(owner,node,definition,attach_only=True)
            owner.sessions.append(session)
            owner.once(session,"abort-before-mutation")
            session.rpc("retire-owner")
            released.append(definition["session"])
    finally:
        owner.close()
    return {"version":"original-workspace-source-preflight-cleanup.v1","state":"actual_untouched_preflight_handles_released","sessions":released,"native_qualified":False,"backup_ready":False}


def dispatch(operator):
    owner,workspace,deployment=read_only_owner(operator)
    suffix=secrets.token_hex(8)
    observations=[]
    failed=None
    cleanup=[]
    inventory=None
    try:
        inventory=owner.inventory()
        owner.stages.retain("workspace-source-preflight-"+suffix+".kube.private.json",inventory)
        sessions=owner.native_sessions(inventory,"probe")
        # NativeSession already did actual direct SSH key/known-host checks,
        # original machineID/bootID vs each current Kube Node, actual CRI and
        # original export/root inode + namespace control filesystem checks.
        for name,session in sorted(sessions.items()):
            observations.append({"node":name,"definition":session.definition,"actual_probe":session.rpc("probe"),"actual_source_mounts":session.rpc("source-mount-census")})
        clients=owner.nfs_client_boundary(sessions,inventory,"workspace-source-preflight-nfs-v4-clients-"+suffix)
        owner.stages.retain("workspace-source-preflight-"+suffix+".native.private.json",{"observations":observations,"nfs_clients":clients,"backup_ready":False,"native_qualified":False})
    except Exception as error:
        # Only fixed codes, never exception text that might contain a secret.
        failed=str(error) if isinstance(error,deployment.Refused) else "original_readonly_nfs_or_ssh_observation_unconfirmed"
    finally:
        for session in owner.sessions:
            try:
                # Actual same-owner code refuses this if ANY source mutation
                # was sent. No timeout-driven thaw or synthetic cleanup flag.
                owner.once(session,"abort-before-mutation")
                session.rpc("retire-owner")
                cleanup.append({"session":session.definition["session"],"actual_handles_released":True})
            except Exception:
                cleanup.append({"session":session.definition["session"],"actual_handles_released":False})
                failed=failed or "original_readonly_observation_handle_cleanup_unconfirmed_use_workspace_abort_probe"
        owner.close()
    result={"version":"original-workspace-source-preflight.v1","operation":owner.stages.operation,
            "state":"readonly_original_nfs_and_direct_ssh_shapes_observed_not_qualified" if failed is None else "STOP_BEFORE_DATABASE_DDL_OR_DEPLOYMENT",
            "reason_code":failed,"nodes_observed":[item["node"] for item in observations],"actual_handle_cleanup":cleanup,
            "namespace_uid":None if inventory is None else inventory["namespace_uid"],
            "no_sql_or_business_deployment_mutation":True,"native_qualified":False,"backup_ready":False,"DR":False}
    pin=owner.stages.retain("workspace-source-preflight-"+suffix+".result.json",result)
    result["private_observation_result"]=pin
    if failed is not None:
        raise EarlyPreflightRefused(result)
    return result


def require_early_shapes(operator):
    """Repeat the REAL observation before db prepare; no saved Passed input."""
    return dispatch(operator)
