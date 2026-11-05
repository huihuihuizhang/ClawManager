"""Actual R18 owner invocation and automatic Archive location DATA author."""
import hashlib
import json
from pathlib import Path
import sys

ACTIONS=("adopt-prepare-archive-materials","adopt-query-archive-materials")
SUCCESS="original_archive_evidence_roles_jwts_native_verified_not_adopted"


def register_arguments(parser):
    parser.add_argument("--adoption-archive-max-files",type=int,default=1000000)
    parser.add_argument("--adoption-archive-max-bytes",type=int,default=1<<40)
    parser.add_argument("--adoption-archive-max-seconds",type=int,default=600)


def pin(path):
    path=Path(path)
    return {"File":str(path),"SHA256":hashlib.sha256(path.read_bytes()).hexdigest()}


def data(op,p):
    return op.source_helpers().load(op.pin_value(p))


def selected(op):
    path=op.run/"production-adoption/actual-archive-evidence-producer-selection.json"
    value=data(op,data(op,pin(path)))
    op.source_helpers().require(value.get("Version")=="original-archive-evidence-material-result.v1" and value.get("State")==SUCCESS,"actual_archive_native_owner_receipt_required")
    for name in ("Material","Signature"):
        op.pin_value(value[name])
    for name in ("Material","Signature","InstalledObserver","WriterSelection"):
        op.pin_value(value["C1"][name])
    return value


def prepare(op,production,query=False):
    m=op.source_helpers()
    m.require(not (op.run/"adopt.send-unknown.json").exists(),"archive_owner_must_precede_original_c1_capture")
    stages=op.deployment_stages()
    host=stages.host_result()["host"]
    stages.check_host(host)
    output=production.ensure_directory(op,stages.runtime_mirror()/"original-archive-evidence")
    if query:
        m.require((op.run/(ACTIONS[0]+".send-unknown.json")).exists(),"original_archive_dispatch_required_for_query")
        value={"Version":"original-archive-evidence-material-query-inputs.v1","OutputDirectory":str(output)}
    else:
        c1=op.c1_inputs_module().receipt(op,include_archive=False)
        value={"Version":"original-archive-evidence-material-inputs.v1","C1Material":c1["Material"],"C1Signature":c1["Signature"],"UnwrapDeployment":host["Deployment"],"UnwrapPodName":host["Pod"],"OutputDirectory":str(output)}
    source=production.save_selection(op,"actual-archive-material-query-inputs.json" if query else "actual-archive-material-inputs.json",value)
    binary,flags,_=production.common(op)
    argv=[binary,"--action","query-archive-materials" if query else "prepare-archive-materials",*flags,"--inputs-file",source["File"],"--inputs-sha256",source["SHA256"]]
    if not query:
        key=pin(stages.issuer_private())
        op.pin_value(key)
        argv += ["--issuer-private-file",key["File"],"--issuer-private-sha256",key["SHA256"]]
    receipt,out=op.invoke(ACTIONS[1] if query else ACTIONS[0],argv,repeat=query)
    m.require(receipt.get("Version")=="original-archive-evidence-material-result.v1" and receipt.get("State")==SUCCESS,"actual_archive_owner_roles_and_pod_jwts_required")
    stages.check_host(host)
    selector=op.run/"production-adoption/actual-archive-evidence-producer-selection.json"
    if selector.exists():
        old=selected(op)
        m.require(all(old[k]==receipt[k] for k in ("Material","Signature","Vault","WrapJWT","UnwrapJWT")),"same_original_archive_material_query_only_no_replacement")
    else:
        production.save_selection(op,selector.name,pin(out))
    selected(op)
    return {"state":receipt["State"],"private_receipt":str(out),"backup_ready":False,"page_backup_completed":False}


def template(op,production):
    m=op.source_helpers()
    actual=selected(op)
    locations=op.adoption_locations_module()
    _,terminal=locations.original_terminal(op)
    definition={"File":terminal["DefinitionFile"],"SHA256":terminal["DefinitionSHA256"]}
    grant=data(op,definition)["Grant"]
    provider=grant["Provider"]
    stages=op.deployment_stages()
    deployment=stages.get("deployment",provider["Deployment"]["Name"])
    m.require(deployment["metadata"]["uid"]==provider["Deployment"]["UID"],"actual_original_minio_deployment_required")
    spec=deployment["spec"]["template"]["spec"]
    containers=[c for c in spec["containers"] if c["name"]==provider["Container"]]
    m.require(len(containers)==1,"exact_actual_minio_container_required")
    mounts=[x for x in containers[0].get("volumeMounts",[]) if x["mountPath"]=="/data"]
    m.require(len(mounts)==1 and not any(mounts[0].get(k) for k in ("subPath","subPathExpr","readOnly")),"actual_original_minio_whole_data_mount_required")
    volumes=[v for v in spec["volumes"] if v["name"]==mounts[0]["name"]]
    m.require(len(volumes)==1 and not volumes[0]["persistentVolumeClaim"].get("readOnly"),"actual_minio_pvc_required")
    pvc=stages.get("pvc",volumes[0]["persistentVolumeClaim"]["claimName"])
    m.require(pvc["status"]["phase"]=="Bound","actual_bound_original_minio_pvc_required")
    pv=json.loads(op.k("get","pv",pvc["spec"]["volumeName"],"-o","json"))
    ref=pv["spec"]["claimRef"]
    m.require(ref["uid"]==pvc["metadata"]["uid"] and ref["name"]==pvc["metadata"]["name"] and ref["namespace"]==grant["Namespace"] and "hostPath" in pv["spec"],"actual_original_minio_pv_binding_required")
    custody=production.ensure_directory(op,production.ensure_directory(op,op.run/"production-adoption")/"archive-custody")
    python=Path(sys.executable).resolve(strict=True)
    script=op.root/"scripts/system-backup-minio-hostpath-cold-source.py"
    script_pin=pin(script)
    m.require(op.pins["files"].get("scripts/"+script.name)==script_pin["SHA256"],"sealed_original_minio_native_source_script_required")
    count,size,seconds=op.a.adoption_archive_max_files,op.a.adoption_archive_max_bytes,op.a.adoption_archive_max_seconds
    m.require(0<count<=1000000 and 0<size<=1<<40 and 1<=seconds<=600,"finite_original_archive_native_bounds_required")
    value={"Version":"original-adoption-evidence-archive-template.v1","PlanSHA256":"","OperationIdentitySHA256":"","MinIODefinitionFile":definition["File"],"MinIODefinitionSHA256":definition["SHA256"],"Vault":actual["Vault"],"WrapJWT":actual["WrapJWT"],"UnwrapJWT":actual["UnwrapJWT"],"CustodyRoot":str(custody),"PVCName":pvc["metadata"]["name"],"PVCUID":pvc["metadata"]["uid"],"PVName":pv["metadata"]["name"],"PVUID":pv["metadata"]["uid"],"NativePythonFile":str(python),"NativePythonSHA256":pin(python)["SHA256"],"NativeScriptFile":str(script),"NativeScriptSHA256":script_pin["SHA256"],"MaximumFiles":count,"MaximumBytes":size,"MaximumSeconds":seconds}
    return production.save_selection(op,"actual-original-archive-template.json",value)
