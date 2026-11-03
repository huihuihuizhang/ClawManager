#!/usr/bin/env python3
"""Original operator: create a dedicated evidence key and private narrow probes.

No root/unseal export, original key rotation, future Job or authority JSON.
The bounded preparation tokens are NOT production task credentials/permission.
"""
import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone

STATE = Path("/root/sbk-vault-owner-20261102-01")
HELPER_SHA = "d2207885e0c91c81d47eec69b3dbd9d601a65739db1d2965520c481e64595514"
CA_SHA = "b60e97026a0d3e56e6d0456c82cb3f1c88b0e2ce587be0f19e4e6b1106f2bde3"
CLUSTER = "520416dc-1249-7d73-2b19-cb0f1ce53014"
PREFIX = "sbk-transit-zh-977a1b9a"
PHASE = "arguments"


class Refused(Exception):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def main():
    global PHASE
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation-id",required=True)
    parser.add_argument("--output-directory",required=True,type=Path)
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    require(args.apply and re.fullmatch(r"installation_[A-Za-z0-9_-]{1,115}",args.installation_id),"original installation selection and explicit apply required")
    require(os.name=="posix" and args.output_directory.is_absolute() and args.output_directory.resolve()==args.output_directory,"original Linux absolute private output required")
    os.umask(0o077)
    helper=Path(__file__).with_name("system-backup-d-transit-install.py")
    require(hashlib.sha256(helper.read_bytes()).hexdigest()==HELPER_SHA,"original reviewed installation helper changed")
    spec=importlib.util.spec_from_file_location("original_transit_install",helper)
    original=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    PHASE="original-private-state"
    owner=original.Owner(STATE)
    state=owner.state
    require(state.get("schema_version")=="d-transit-owned-install.v1" and state.get("prefix")==PREFIX and state.get("namespace_uid")==original.NAMESPACE_UID and state.get("context")==original.CONTEXT and state.get("pending") is None and state.get("cluster_id")==CLUSTER and state.get("configured") is True,"original owner state not the reported configured installation")
    require(hashlib.sha256(owner.read("ca.pem",False)).hexdigest()==CA_SHA,"original independently reported CA changed")
    image=state["image_input"]
    require(image.get("version")=="2.2.1" and image.get("entrypoint")=="/bin/vault","original provider binary profile changed")
    original.IMAGE,original.IMAGE_DIGESTS,original.CLI,original.VERSION=image["image"],set(image["image_id_digests"]),image["entrypoint"],image["version"]
    original.guard()
    deployment=original.get("deployments",PREFIX)
    require(deployment and deployment["metadata"]["uid"]==state["resources"]["deployments/"+PREFIX],"original provider Deployment UID changed")
    require(not args.output_directory.exists() and not args.output_directory.is_symlink(),"new private output required; retain unknown/partial outcomes")
    exported=original.Owner(args.output_directory,new=True)
    key_name=PREFIX+"-evidence-"+secrets.token_hex(6)
    key={"kek_identity_hash":secrets.token_hex(32),"kek_version":"evidence-20261103-"+secrets.token_hex(4)}
    context=base64.b64encode(canonical({"purpose":"system-backup-evidence-dek.v1","installation_id":args.installation_id,"key":key})).decode()
    # Exact existing EvidenceTransitContext: installation and opaque original
    # key identity/version, independent from capture data/signing contexts.
    exported.write("intent.json",{"version":"first-page-evidence-transit.v1","installation":args.installation_id,"provider_cluster_id":CLUSTER,"key_name":key_name,"key":key,"context_base64":context,"native_writes_attempted":False})
    api=None
    try:
        PHASE="original-provider-current-identity"
        api=original.API(owner)
        seal=api.call("GET","sys/seal-status")
        require(seal.get("cluster_id")==CLUSTER and seal.get("sealed") is False,"original provider unavailable/sealed/changed")
        root=owner.read("init-material.json")["root_token"]
        # Exact-name absence only. Any existing/unknown response refuses.
        api.call("GET","transit/keys/"+key_name,token=root,expected=(404,))
        names={purpose:key_name+"-"+purpose for purpose in ("wrap","unwrap","observer")}
        for policy in names.values():
            api.call("GET","sys/policies/acl/"+policy,token=root,expected=(404,))
        exported.write("native-writes-attempted.json",{"key_name":key_name,"provider_cluster_id":CLUSTER,"native_writes_attempted":True})
        PHASE="new-dedicated-nonexportable-evidence-key"
        api.call("POST","transit/keys/"+key_name,{"type":"aes256-gcm96","derived":True,"exportable":False,"allow_plaintext_backup":False},root)
        metadata=api.call("GET","transit/keys/"+key_name,token=root)["data"]
        require(metadata.get("type")=="aes256-gcm96" and metadata.get("derived") is True and metadata.get("exportable") is False and metadata.get("allow_plaintext_backup") is False and metadata.get("latest_version")==1,"new dedicated key profile not confirmed")
        exported.write("actual-key-metadata.json",metadata)
        wrap_path="transit/encrypt/"+key_name
        unwrap_path="transit/decrypt/"+key_name
        policies={
            "wrap":{"path":{wrap_path:{"capabilities":["update"],"required_parameters":["context","key_version","plaintext"],"allowed_parameters":{"context":[context],"key_version":["1"],"plaintext":["*"]}}}},
            "unwrap":{"path":{unwrap_path:{"capabilities":["update"],"required_parameters":["context","ciphertext"],"allowed_parameters":{"context":[context],"ciphertext":["vault:v1:*"]}}}},
            "observer":{"path":{"transit/keys/"+key_name:{"capabilities":["read"]},**{"sys/policies/acl/"+name:{"capabilities":["read"]} for name in names.values()}}},
        }
        tokens={}
        PHASE="exact-evidence-policies-and-bounded-preparation-tokens"
        for purpose,policy in policies.items():
            api.call("PUT","sys/policies/acl/"+names[purpose],{"policy":canonical(policy).decode()},root)
            actual=api.call("GET","sys/policies/acl/"+names[purpose],token=root)["data"]
            require(canonical(json.loads(actual["policy"]))==canonical(policy),"actual evidence policy differs")
            exported.write(purpose+".policy.json",policy)
            auth=api.call("POST","auth/token/create-orphan",{"policies":[names[purpose]],"no_default_policy":True,"ttl":"1800s","explicit_max_ttl":"1800s","renewable":False,"type":"service","display_name":"original-evidence-preparation"},root)["auth"]
            require(auth.get("policies")==[names[purpose]] and auth.get("renewable") is False and 1<=auth.get("lease_duration",0)<=1800 and auth.get("client_token"),"bounded preparation credential profile differs")
            tokens[purpose]=auth["client_token"]
            exported.write(purpose+"-preparation-token.raw",tokens[purpose].encode())
            exported.write(purpose+"-preparation-token-metadata.json",{"policy":names[purpose],"expires_at":(datetime.now(timezone.utc)+timedelta(seconds=auth["lease_duration"])).isoformat(),"production_task_credential":False})
        PHASE="actual-dedicated-key-preparation-probe"
        plaintext=bytearray(secrets.token_bytes(32))
        try:
            wrapped=api.call("POST",wrap_path,{"plaintext":base64.b64encode(plaintext).decode(),"context":context,"key_version":1},tokens["wrap"])["data"]["ciphertext"]
            opened=api.call("POST",unwrap_path,{"ciphertext":wrapped,"context":context},tokens["unwrap"])["data"]["plaintext"]
            require(hmac.compare_digest(base64.b64decode(opened,validate=True),plaintext),"dedicated key preparation roundtrip failed")
            api.call("POST",unwrap_path,{"ciphertext":wrapped,"context":context},tokens["wrap"],expected=(403,))
            api.call("POST",wrap_path,{"plaintext":base64.b64encode(plaintext).decode(),"context":context,"key_version":1},tokens["unwrap"],expected=(403,))
            api.call("POST",wrap_path,{"plaintext":base64.b64encode(plaintext).decode(),"context":"different-context","key_version":1},tokens["wrap"],expected=(403,))
        finally:
            plaintext[:]=bytes(len(plaintext))
        tail=api.call("GET","transit/keys/"+key_name,token=tokens["observer"])["data"]
        require(canonical(tail)==canonical(metadata),"dedicated key metadata drifted")
        ca=owner.read("ca.pem",False)
        exported.write("original-provider-ca.pem",ca)
        result={"status":"actual_dedicated_evidence_key_and_private_preparation_credentials_exported","endpoint":"https://"+PREFIX+"."+original.NAMESPACE+".svc:8200","provider_cluster_id":CLUSTER,"ca_sha256":CA_SHA,"key_name":key_name,"key":key,"provider_version":"1","context_base64":context,"policies":names,"preparation_probe_observed":True,"production_task_credentials_issued":False,"original_mapping_or_A_six_reference_authority_issued":False,"original_root_or_unseal_exported":False,"original_keys_rotated":False,"future_Job_created":False}
        exported.write("provider-materials.json",result)
        # Public receipt only, never credential bytes or low-entropy hashes.
        print(json.dumps(result,sort_keys=True))
    finally:
        if api is not None:
            api.close()


if __name__=="__main__":
    try:
        main()
    except Exception as error:
        # Native errors may contain secret/provider response text. A closed
        # stage is enough to retain/inspect the original private operation.
        print(json.dumps({"status":"refused_or_native_outcome_unknown","stage":PHASE,"error_kind":type(error).__name__,"retain_original_state_and_new_private_output":True}),file=sys.stderr)
        sys.exit(1)
