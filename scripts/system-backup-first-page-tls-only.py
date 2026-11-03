#!/usr/bin/env python3
"""Field-specific TLS/CA/private admin export and rollback. C owns all six principals.

prepare reads actual objects and writes a private create-only local bundle.
apply changes the two selected workloads; rollback restores the saved specs.
No MySQL rotation, bucket/PVC deletion, account overwrite or TLS bypass.
"""
import argparse
import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
from types import SimpleNamespace

CONTEXT = "kubernetes-admin@kubernetes"
NS = "clawmanager-zhanghui08-system"
NS_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
MINIO_UID = "9cd91bdc-2a9d-4f78-9cd7-413d611b2667"
APP_UID = "ed2c80de-9d24-4ca6-8f9c-877a990ac933"
SERVICE_UID = "22b590fd-bb1b-47f2-adda-c00a9bd36090"
MINIO_IP = "10.101.248.14"
HOST = "minio." + NS + ".svc"
MINIO_IMAGE = "10.130.14.23:5000/minio@sha256:52dfd5c0bbd38d3219f2058c7af216d9f9a27a994b7b5baad09bbd38866015ff"
PURPOSES = ("artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append", "observer")


class Refused(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def private_read(path, maximum=8 * 1024 * 1024):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or os.name != "nt" and info.st_mode & 0o077:
        raise Refused("private bundle file mode/type/size")
    raw = path.read_bytes()
    if len(raw) > maximum:
        raise Refused("private bundle file too large")
    return raw


def run(argv, data=None, timeout=45):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
        # Commands may contain credentials in output; never echo their output.
        raise Refused("external command refused: " + Path(argv[0]).name)
    return result.stdout


def kube(*args, data=None, timeout=45):
    return run(["kubectl", "--context", CONTEXT, "--namespace", NS, *args], data, timeout)


def get(kind, name):
    return json.loads(kube("get", kind, name, "-o", "json"))


def scope():
    if get("namespace", NS)["metadata"]["uid"] != NS_UID:
        raise Refused("namespace identity changed")
    service = get("service", "minio")
    if service["metadata"]["uid"] != SERVICE_UID or service["spec"]["clusterIP"] != MINIO_IP:
        raise Refused("original MinIO Service changed")
    if not any(p["port"] == 9000 and p.get("protocol", "TCP") == "TCP" for p in service["spec"]["ports"]):
        raise Refused("original API port changed")


def single_container(deployment):
    containers = deployment["spec"]["template"]["spec"]["containers"]
    if len(containers) != 1:
        raise Refused("workload container selection is ambiguous")
    return containers[0]


def verify_minio_image(deployment):
    selector = deployment["spec"]["selector"].get("matchLabels", {})
    if not selector or deployment["spec"]["selector"].get("matchExpressions"):
        raise Refused("unsupported MinIO selector")
    pods = json.loads(kube("get", "pods", "-l", ",".join(k + "=" + v for k, v in sorted(selector.items())), "-o", "json"))["items"]
    name = single_container(deployment)["name"]
    live = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
    if len(live) != 1:
        raise Refused("MinIO is not one stable current Pod")
    states = [s for s in live[0].get("status", {}).get("containerStatuses", []) if s["name"] == name]
    if len(states) != 1 or states[0].get("imageID") != MINIO_IMAGE or not states[0].get("ready") or "running" not in states[0].get("state", {}):
        raise Refused("original MinIO image/running identity changed")


def openssl(directory, *args):
    return run(["openssl", *args], timeout=60)


def add_volume(spec, name, source, mount):
    pod = spec["template"]["spec"]
    if any(v["name"] == name for v in pod.get("volumes", [])):
        raise Refused("selected TLS volume already exists")
    pod.setdefault("volumes", []).append({"name": name, **source})
    container = pod["containers"][0]
    if any(m["mountPath"] == mount for m in container.get("volumeMounts", [])):
        raise Refused("selected TLS mount already exists")
    container.setdefault("volumeMounts", []).append({"name": name, "mountPath": mount, "readOnly": True})


def prepare(directory, app_image):
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", app_image or ""):
        raise Refused("root-built app immutable digest required")
    scope()
    minio, app = get("deployment", "minio"), get("deployment", "clawmanager-app")
    if minio["metadata"]["uid"] != MINIO_UID or app["metadata"]["uid"] != APP_UID:
        raise Refused("original Deployment identity changed")
    verify_minio_image(minio)
    for obj in (minio, app):
        single_container(obj)
    if minio["spec"].get("replicas", 1) != 1:
        raise Refused("MinIO replicas changed")
    original = single_container(minio)
    arguments = original.get("args", [])
    command = original.get("command", [])
    if not arguments or arguments[0] != "server" or command not in ([], ["minio"], ["/usr/bin/minio"], ["/usr/local/bin/minio"]) or any("certs-dir" in a for a in arguments):
        raise Refused("unsupported actual MinIO argv; no shell/argv guessing")
    if any(e["name"] in ("OBJECT_STORAGE_TLS_CA_FILE", "OBJECT_STORAGE_TLS_CA_SHA256") for e in single_container(app).get("env", [])):
        raise Refused("app already has selected original CA")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    suffix = secrets.token_hex(6)
    secret_name, ca_name = "sbk-minio-tls-" + suffix, "sbk-minio-ca-" + suffix
    config = ("[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nCN=" + HOST + "\n[ext]\n"
              "subjectAltName=DNS:minio,DNS:" + HOST + ",DNS:" + HOST + ".cluster.local,IP:" + MINIO_IP + "\n"
              "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    private_write(directory / "server.cnf", config.encode())
    openssl(directory, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(directory / "ca.key"))
    openssl(directory, "req", "-x509", "-new", "-key", str(directory / "ca.key"), "-sha256", "-days", "30", "-subj", "/CN=ClawManager original MinIO TLS " + suffix,
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(directory / "ca.pem"))
    openssl(directory, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(directory / "private.key"))
    openssl(directory, "req", "-new", "-key", str(directory / "private.key"), "-config", str(directory / "server.cnf"), "-out", str(directory / "server.csr"))
    openssl(directory, "x509", "-req", "-in", str(directory / "server.csr"), "-CA", str(directory / "ca.pem"), "-CAkey", str(directory / "ca.key"), "-set_serial", str(secrets.randbits(120) + 1),
            "-days", "14", "-sha256", "-extfile", str(directory / "server.cnf"), "-extensions", "ext", "-out", str(directory / "public.crt"))
    for p in directory.iterdir():
        p.chmod(0o600)
    openssl(directory, "verify", "-CAfile", str(directory / "ca.pem"), "-verify_hostname", HOST, str(directory / "public.crt"))
    ca, cert, key = (private_read(directory / p, 65536) for p in ("ca.pem", "public.crt", "private.key"))
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret_name, "namespace": NS}, "immutable": True, "type": "Opaque", "data": {"public.crt": base64.b64encode(cert).decode(), "private.key": base64.b64encode(key).decode()}}
    ca_object = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": ca_name, "namespace": NS}, "immutable": True, "data": {"ca.pem": ca.decode("ascii")}}
    desired_minio, desired_app = copy.deepcopy(minio["spec"]), copy.deepcopy(app["spec"])
    desired_minio["strategy"] = {"type": "Recreate"}
    desired_minio["template"]["spec"]["containers"][0]["args"].extend(["--certs-dir", "/run/system-backup-minio-tls"])
    # One selected container only. Standard Secret projection permits its
    # existing image UID to read; no application private-file rule is changed.
    add_volume(desired_minio, secret_name, {"secret": {"secretName": secret_name, "defaultMode": 292}}, "/run/system-backup-minio-tls")
    add_volume(desired_app, ca_name, {"configMap": {"name": ca_name}}, "/run/system-backup-minio-ca")
    container = desired_app["template"]["spec"]["containers"][0]
    container["image"] = app_image
    selected = {"OBJECT_STORAGE_ENDPOINT": HOST + ":9000", "OBJECT_STORAGE_USE_SSL": "true", "OBJECT_STORAGE_TLS_CA_FILE": "/run/system-backup-minio-ca/ca.pem", "OBJECT_STORAGE_TLS_CA_SHA256": digest(ca), "SYSTEM_BACKUP_API_PROXY_ENABLED": "true"}
    container["env"] = [e for e in container.get("env", []) if e["name"] not in selected] + [{"name": k, "value": v} for k, v in selected.items()]
    bundle = {"version": "first-page-minio-tls.v1", "namespace_uid": NS_UID, "secret": secret, "ca_object": ca_object,
              "minio": {"before": minio, "desired_spec": desired_minio}, "app": {"before": app, "desired_spec": desired_app}, "ca_sha256": digest(ca)}
    private_write(directory / "bundle.json", canonical(bundle))
    leaf_der = openssl(directory, "x509", "-in", str(directory / "public.crt"), "-outform", "DER")
    public_key = openssl(directory, "x509", "-in", str(directory / "public.crt"), "-pubkey", "-noout")
    spki = run(["openssl", "pkey", "-pubin", "-outform", "DER"], data=public_key)
    receipt = {"status": "prepared_local_only", "namespace_uid": NS_UID, "ca_sha256": digest(ca), "server_leaf_sha256": digest(leaf_der), "server_spki_sha256": digest(spki), "app_image": app_image, "bundle_sha256": digest(canonical(bundle)), "six_principals_owner": "C system-backup-minio-native-install",
               "native_permission_observed": False, "mysql_rotated": False, "cluster_mutated": False}
    private_write(directory / "receipt.json", canonical(receipt))
    return receipt


def patch_spec(name, before, desired):
    current = get("deployment", name)
    if current["metadata"]["uid"] != before["metadata"]["uid"] or canonical(current["spec"]) != canonical(before["spec"]):
        raise Refused("workload changed since preparation")
    patch = [{"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]}, {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}, {"op": "replace", "path": "/spec", "value": desired}]
    # Pass patch on stdin through a private temporary file, never shell text.
    return json.loads(kube("patch", "deployment", name, "--type=json", "--patch-file=/dev/stdin", "-o", "json", data=canonical(patch)))


def apply(directory, expected):
    scope()
    raw = private_read(directory / "bundle.json")
    if digest(raw) != expected:
        raise Refused("bundle pin differs")
    bundle = json.loads(raw)
    if bundle["version"] != "first-page-minio-tls.v1" or bundle["namespace_uid"] != NS_UID:
        raise Refused("bundle scope differs")
    verify_minio_image(get("deployment", "minio"))
    for key in ("secret", "ca_object"):
        created = json.loads(kube("create", "-f", "-", "-o", "json", data=canonical(bundle[key])))
        private_write(directory / (key + ".created.json"), canonical({"name": created["metadata"]["name"], "uid": created["metadata"]["uid"]}))
    for key, name in (("minio", "minio"), ("app", "clawmanager-app")):
        changed = patch_spec(name, bundle[key]["before"], bundle[key]["desired_spec"])
        private_write(directory / (key + ".applied.json"), canonical(changed))
        kube("rollout", "status", "deployment/" + name, "--timeout=180s", timeout=200)
        if key == "minio":
            trust = ssl.create_default_context(cafile=str(directory / "ca.pem"))
            trust.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((MINIO_IP, 9000), timeout=10) as plain:
                with trust.wrap_socket(plain, server_hostname=HOST) as channel:
                    expected_leaf = ssl.PEM_cert_to_DER_cert(private_read(directory / "public.crt", 65536).decode())
                    if channel.getpeercert(binary_form=True) != expected_leaf:
                        raise Refused("deployed MinIO leaf differs")
                    channel.sendall(("GET /minio/health/live HTTP/1.1\r\nHost: " + HOST + "\r\nConnection: close\r\n\r\n").encode())
                    response = http.client.HTTPResponse(channel)
                    response.begin()
                    if response.status != 200:
                        raise Refused("MinIO TLS health did not return 200")
    return {"status": "tls_and_app_rollouts_completed", "permission_authority": False, "page_backup_complete": False, "ca_sha256": bundle["ca_sha256"]}


def rollback(directory, expected):
    scope()
    raw = private_read(directory / "bundle.json")
    if digest(raw) != expected:
        raise Refused("bundle pin differs")
    bundle = json.loads(raw)
    restored = []
    for key, name in (("app", "clawmanager-app"), ("minio", "minio")):
        applied_file = directory / (key + ".applied.json")
        if not applied_file.exists():
            continue
        applied = json.loads(private_read(applied_file))
        # Compare server-returned post-admission spec, including defaults.
        patch_spec(name, applied, bundle[key]["before"]["spec"])
        kube("rollout", "status", "deployment/" + name, "--timeout=180s", timeout=200)
        restored.append(name)
    return {"status": "saved_specs_restored", "deployments": restored, "data_deleted": False, "tls_objects_retained": True}




def export_mysql_ca(directory):
    scope()
    if not directory.exists():
        directory.mkdir(mode=0o700, parents=False)
    deployment = get("deployment", "mysql")
    if deployment["metadata"]["uid"] != "27916932-fc61-432c-b515-081f18db34a8":
        raise Refused("original MySQL Deployment changed")
    volumes = [v for v in deployment["spec"]["template"]["spec"].get("volumes", []) if v["name"] == "sbk-test-tls-runtime"]
    if len(volumes) != 1:
        raise Refused("original observed MySQL certificate volume missing")
    volume = volumes[0]
    if "secret" in volume:
        kind, name, encoded = "secret", volume["secret"]["secretName"], True
    elif "configMap" in volume:
        kind, name, encoded = "configmap", volume["configMap"]["name"], False
    else:
        raise Refused("MySQL original certificate source is not Secret/ConfigMap")
    found = []
    for key in ("ca.crt", "ca.pem", "root.crt"):
        # Request ONLY this named public CA key. Never fetch the Secret JSON,
        # server key, root password or other data into the public collector.
        template = '{{index .data "' + key + '"}}'
        raw = kube("get", kind, name, "-o", "go-template=" + template).strip()
        if raw in (b"", b"<no value>"):
            continue
        if encoded:
            raw = base64.b64decode(raw, validate=True)
        if b"PRIVATE KEY" in raw or len(raw) > 65536 or b"-----BEGIN CERTIFICATE-----" not in raw:
            raise Refused("selected public CA key is not bounded certificate PEM")
        found.append(raw)
    if not found or any(raw != found[0] for raw in found):
        raise Refused("one unambiguous original public MySQL CA not found")
    path = directory / "mysql-original-ca.pem"
    private_write(path, found[0])
    text = openssl(directory, "x509", "-in", str(path), "-noout", "-text")
    if b"CA:TRUE" not in text:
        raise Refused("selected MySQL public certificate is not a CA")
    helper = Path(__file__).with_name("system-backup-first-page-inputs.py")
    if digest(helper.read_bytes()) != "af8600aa44dd2e9db3835779a0bb438c4b172db8041d1a68aab49ffb1278c42e":
        raise Refused("frozen MySQL SSLRequest helper changed")
    spec = importlib.util.spec_from_file_location("original_public_mysql_probe", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    observed = module.mysql_tls(SimpleNamespace(mysql_host="10.108.2.110", mysql_port=3306, mysql_server_name="mysql." + NS + ".svc", mysql_ca_file=str(path)))
    if observed.get("status") != "tls_handshake_only" or not observed.get("chain_and_hostname_verified") or observed.get("leaf_sha256") != "f284af5e2e48f8bfe1c656f198de5ffa5f39fc2187ca1483e0932dc64cdc1814":
        raise Refused("original MySQL independent TLS verification failed")
    return {"status": "original_public_mysql_ca_exported_and_tls_verified", "ca_sha256": digest(found[0]), "tls_observation": observed, "sql_sent": False, "account_verified": False, "mysql_rotated": False}


def export_minio_admin(directory):
    scope()
    if not directory.exists():
        directory.mkdir(mode=0o700, parents=False)
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise Refused("operator-owned private export directory required")
    deployment=get("deployment","minio")
    if deployment["metadata"]["uid"]!=MINIO_UID:
        raise Refused("original MinIO Deployment changed")
    container=single_container(deployment)
    values=[]
    for variable,filename in (("MINIO_ROOT_USER","minio-original-admin-user.raw"),("MINIO_ROOT_PASSWORD","minio-original-admin-password.raw")):
        selected=[e for e in container.get("env",[]) if e["name"]==variable]
        if len(selected)!=1:
            raise Refused("exact original administrative env source unavailable")
        env=selected[0]
        if "value" in env and "valueFrom" not in env:
            raw=env["value"].encode()
        else:
            source=env.get("valueFrom",{}).get("secretKeyRef",{})
            name,key=source.get("name"),source.get("key")
            if not name or not re.fullmatch(r"[A-Za-z0-9._-]+",key or "") or source.get("optional"):
                raise Refused("exact original Secret key source required")
            template='{{index .data "'+key+'"}}'
            encoded=kube("get","secret",name,"-o","go-template="+template).strip()
            raw=base64.b64decode(encoded,validate=True)
        if not raw or len(raw)>4096 or any(c in raw for c in (b"\x00",b"\r",b"\n")):
            raise Refused("bounded original raw administrative credential required")
        if (directory/filename).exists() or (directory/filename).is_symlink():
            raise Refused("create-only private administrative export target exists")
        values.append((filename,raw))
    for filename,raw in values:
        private_write(directory/filename,raw)
    return {"status":"original_private_admin_files_exported_for_C_native_installer","cluster_mutated":False,"credentials_printed":False,"credential_hashes_printed":False,"C_native_permission_observation_still_required":True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "apply", "rollback", "export-mysql-ca", "export-minio-admin"))
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--app-image")
    parser.add_argument("--bundle-sha256")
    args = parser.parse_args()
    directory = args.state_directory
    if os.name == "nt" or not directory.is_absolute() or directory.resolve() != directory:
        raise Refused("run on original Linux operator host with an absolute private state directory")
    if args.action in ("export-mysql-ca", "export-minio-admin"):
        if args.app_image or args.bundle_sha256:
            raise Refused("export accepts no mutation selection inputs")
        result = (export_mysql_ca if args.action == "export-mysql-ca" else export_minio_admin)(directory)
    elif args.action == "prepare":
        if args.bundle_sha256:
            raise Refused("prepare consumes no existing bundle")
        result = prepare(directory, args.app_image)
    else:
        if args.app_image or not re.fullmatch(r"[0-9a-f]{64}", args.bundle_sha256 or ""):
            raise Refused("exact prepared bundle SHA required")
        result = (apply if args.action == "apply" else rollback)(directory, args.bundle_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "refused", "stage": str(error) if isinstance(error, Refused) else type(error).__name__, "cluster_may_be_partially_changed": True, "use_saved_bundle_for_guarded_rollback": True}), file=sys.stderr)
        sys.exit(1)
