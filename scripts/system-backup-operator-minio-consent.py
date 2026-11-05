"""Invoke real original owner consent, retain fixed source, no SQL grant mint."""
import hashlib
from pathlib import Path

ACTIONS=("minio-runtime-consent","minio-runtime-consent-query")
SUCCESS="original_runtime_metadata_consent_exact_readback_sql_enrollment_not_proven"


def pin(path):
    path=Path(path)
    return {"File":str(path),"SHA256":hashlib.sha256(path.read_bytes()).hexdigest()}


def prepare(op,production,initial_runtime,query=False):
    m=op.source_helpers()
    original=initial_runtime.InitialRuntimeStages(op)
    forward=original.previous_forward()
    stages=op.deployment_stages()
    host=stages.host_result()["host"]
    stages.check_host(host)
    _,_,_,sql=stages.common()
    directory=production.ensure_directory(op,stages.runtime_mirror()/"original-minio-runtime-consent")
    owner={"Issuers":original.material,"Core":original.core_pin,"OriginalForward":forward["grant"],"RecoveryDescriptor":op.minio_recovery_module().input_descriptor(op),"ControllerDeployment":host["Deployment"],"ControllerPodName":host["Pod"],"OutputDirectory":str(directory)}
    source=production.save_selection(op,"actual-minio-runtime-consent-inputs.json",{"Version":"original-minio-runtime-metadata-owner-inputs.v1","Owner":owner,"RuntimeDSN":original.runtime_dsn,"RuntimeTLS":sql["source_tls"]})
    if query:
        m.require((op.run/(ACTIONS[0]+".send-unknown.json")).exists(),"query_only_original_runtime_consent_intent_required")
    binary,flags,_=production.common(op)
    argv=[binary,"--action","query-minio-runtime-metadata" if query else "issue-minio-runtime-metadata",*flags,"--inputs-file",source["File"],"--inputs-sha256",source["SHA256"]]
    if not query:
        issuer=pin(stages.issuer_private());op.pin_value(issuer)
        argv += ["--issuer-private-file",issuer["File"],"--issuer-private-sha256",issuer["SHA256"]]
    value,out=op.invoke(ACTIONS[1] if query else ACTIONS[0],argv,repeat=query)
    m.require(value.get("State")==SUCCESS,"actual_original_owner_consent_readback_required")
    op.pin_value(value["Consent"])
    stages.check_host(host)
    selector=op.run/"production-adoption/actual-minio-runtime-consent-selection.json"
    if selector.exists():
        old=m.load(op.pin_value(pin(selector)))
        m.require(old["Consent"]==value["Consent"] and old["Descriptor"]==owner["RecoveryDescriptor"] and old["Host"]==host,"same_original_consent_query_no_replacement")
    else:
        production.save_selection(op,selector.name,{"Consent":value["Consent"],"Descriptor":owner["RecoveryDescriptor"],"Host":host,"NativeReceipt":pin(out),"Inputs":source})
    stages.deliver_runtime_tree(host)
    stages.remote_pin(host,value["Consent"])
    return {"state":value["State"],"private_receipt":str(out),"sql_enrollment_proven":False,"backup_ready":False}
