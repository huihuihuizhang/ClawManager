#!/usr/bin/env python3
"""Publish the verified Hermes Lite base with the already deployed native TLS Agent.

Only two regular files and the private Agent directory change. Registry tags,
workloads and the release's unaccepted status are never modified by this module.
"""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

BASE = "sha256:47729188347a01d249d5a929e474b3bb9959a138c138031a84ec39a7c6412cc7"
OLD_AGENT = "b171fe72815d57f45ac07738a8bf69a7099794cb9ea95fd4307c62324737ba69"
AGENT = "be46bb0525623bb9fb7f1393a6b668d7c8f705a998c90517915751c2be9d0102"
OLD_PAYLOAD = "305f0d6cf0d9a19bcf07af8f5fad350ddb4d4692972ce523ac4dc23740e528b0"
HELPER_SHA = "f08a23b661afacff2634c151ba87f266a8697da8944a19e6c80a8f0f6a29100a"
RELEASE = "usr/local/share/hermes-lite/release.json"
TARGET = "usr/local/bin/clawmanager-agent"
PRIVATE = "var/lib/clawmanager-agent"


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def payload(artifacts):
    return sha("".join(path + "\0" + artifacts[path] + "\n" for path in sorted(artifacts)).encode())


def update_release(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate release JSON key")
            result[key] = value
        return result
    old = json.loads(raw, object_pairs_hook=pairs)
    need(old.get("schema_version") == 2 and old.get("backend_mode") == "serve"
         and old.get("rpc_protocol") == "hermes-jsonrpc-v1"
         and old.get("hermes_ref") == "v2026.8.31"
         and old.get("hermes_commit") == "29112bef099274229cadff79cdff7bf7b99c4b77"
         and old.get("desktop_web_accepted") is False and not old.get("acceptance"), "unexpected candidate release identity")
    artifacts = old.get("artifacts")
    need(isinstance(artifacts, dict) and artifacts.get("/" + TARGET) == OLD_AGENT
         and old.get("payload_sha256") == OLD_PAYLOAD and payload(artifacts) == OLD_PAYLOAD,
         "candidate release payload identity mismatch")
    for path, expected in {
        "/usr/local/bin/start-hermes-lite-runtime": "bad084163789bcc4cd01cf22286dcab743618245ff40a4d66b97f29e04ecf152",
        "/usr/local/bin/start-hermes-lite-backend": "3ef9fe1d6ecd71ae2ec179532fa2bd78782542b39184881df15de0b82aadb8d2",
        "/usr/local/bin/hermes-lite-entrypoint": "4e89d05db5ba1a62a676a4d30cc34a064be97ec6cf1a5bd53ae7f3dc12817817",
    }.items():
        need(artifacts.get(path) == expected, "candidate launcher identity mismatch")
    new = copy.deepcopy(old)
    new["artifacts"]["/" + TARGET] = AGENT
    new["payload_sha256"] = payload(new["artifacts"])
    check = copy.deepcopy(new)
    check["artifacts"]["/" + TARGET] = OLD_AGENT
    check["payload_sha256"] = OLD_PAYLOAD
    need(check == old, "release fields changed outside the actual Agent hash and payload hash")
    return (json.dumps(new, sort_keys=True, indent=2) + "\n").encode(), new["payload_sha256"]


def make_tar(agent, release):
    need(sha(agent) == AGENT and len(agent) == 10154146, "native Agent identity mismatch")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, content, mode in ((TARGET, agent, 0o555), (RELEASE, release, 0o444), (PRIVATE, None, 0o700)):
            member = tarfile.TarInfo(path)
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            member.mode = mode
            member.size = len(content) if content is not None else 0
            if content is None:
                member.type = tarfile.DIRTYPE
            archive.addfile(member, io.BytesIO(content) if content is not None else None)
    return output.getvalue()


def read_release(helper, registry, manifest, config):
    layers = manifest["layers"]
    diffs = config["rootfs"]["diff_ids"]
    need(len(layers) == len(diffs) and layers, "candidate layer inventory mismatch")
    ancestors = ("usr", "usr/local", "usr/local/share", "usr/local/share/hermes-lite")
    for descriptor, diff in reversed(list(zip(layers, diffs))):
        helper.validate_descriptor(descriptor)
        need(descriptor["mediaType"] in helper.LAYER_TYPES, "unsupported candidate layer media")
        found = None
        removed = False
        bad_parent = False
        with registry.blob(descriptor) as response:
            compressed = helper.CountedReader(response, descriptor["size"], registry)
            stream = gzip.GzipFile(fileobj=compressed, mode="rb") if helper.LAYER_TYPES[descriptor["mediaType"]] else compressed
            plain = helper.CountedReader(stream, helper.MAX_PLAIN, registry)
            with tarfile.open(fileobj=plain, mode="r|") as archive:
                count = 0
                for member in archive:
                    count += 1
                    need(count <= 2000000, "candidate layer member limit")
                    name = member.name
                    while name.startswith("./"):
                        name = name[2:]
                    name = name.rstrip("/")
                    need(not name.startswith("/") and ".." not in name.split("/"), "candidate tar path refused")
                    parent, _, leaf = name.rpartition("/")
                    if leaf == ".wh..wh..opq" and (not parent or RELEASE.startswith(parent + "/")):
                        removed = True
                    elif leaf.startswith(".wh."):
                        target = (parent + "/" if parent else "") + leaf[4:]
                        removed = removed or target == RELEASE or RELEASE.startswith(target + "/")
                    if name in ancestors:
                        bad_parent = bad_parent or not member.isdir() or member.uid != 0 or bool(member.mode & 0o022)
                    if name == RELEASE:
                        need(found is None and member.isfile() and member.uid == member.gid == 0
                             and not member.mode & 0o022 and 0 < member.size <= 4 << 20, "candidate release file metadata refused")
                        with archive.extractfile(member) as source:
                            found = source.read((4 << 20) + 1)
                        need(len(found) == member.size, "candidate release size mismatch")
            while plain.read(helper.CHUNK):
                pass
            need(compressed.count == descriptor["size"] and "sha256:" + compressed.sha.hexdigest() == descriptor["digest"]
                 and "sha256:" + plain.sha.hexdigest() == diff, "candidate release layer integrity mismatch")
            if stream is not compressed:
                stream.close()
        need(not bad_parent, "candidate managed parent path refused")
        if found is not None:
            return found
        need(not removed, "candidate release is hidden by a whiteout")
    raise RuntimeError("candidate release not found")


def publish(directory, records):
    path = directory / "agent_runtime_layer.py"
    need(sha(path.read_bytes()) == HELPER_SHA, "existing registry helper source changed")
    spec = importlib.util.spec_from_file_location("sbk_original_registry_helper", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    agent = helper.agent_from_bundle(directory / "agent-prebuilt-shared-native-236d56d85fea-linux-amd64.tar.gz", "hermes")
    registry = helper.Registry("hermes-lite", seconds=1800)
    manifest_raw, manifest = registry.manifest(BASE)
    need(manifest.get("mediaType") in (helper.OCI_MANIFEST, helper.DOCKER_MANIFEST), "candidate must be a platform manifest")
    config_raw, config = registry.json_blob(manifest["config"])
    need(config.get("os") == "linux" and config.get("architecture") == "amd64", "candidate platform mismatch")
    need(config["config"].get("Entrypoint") == ["/usr/bin/tini", "--", "/usr/local/bin/hermes-lite-entrypoint"]
         and not config["config"].get("Cmd"), "candidate entrypoint mismatch")
    print("Reading the pinned Lite release inventory", flush=True)
    original_release = read_release(helper, registry, manifest, config)
    release, payload_sha = update_release(original_release)
    plain = make_tar(agent, release)
    layer = helper.stored_gzip(plain)
    layer_descriptor = {"mediaType": ("application/vnd.oci.image.layer.v1.tar+gzip" if manifest["mediaType"] == helper.OCI_MANIFEST
                                    else "application/vnd.docker.image.rootfs.diff.tar.gzip"),
                        "digest": helper.digest(layer), "size": len(layer)}
    next_config = copy.deepcopy(config)
    next_config["rootfs"]["diff_ids"].append(helper.digest(plain))
    if "history" in next_config:
        next_config["history"].append({"created": "1970-01-01T00:00:00Z",
            "created_by": "clawmanager Hermes Lite native TLS Agent and truthful release inventory", "empty_layer": False})
    check = copy.deepcopy(next_config)
    check["rootfs"]["diff_ids"].pop()
    if "history" in check:
        check["history"].pop()
    need(check == config, "candidate runtime configuration changed")
    next_config_raw = helper.encode(next_config)
    config_descriptor = copy.deepcopy(manifest["config"])
    config_descriptor.update(digest=helper.digest(next_config_raw), size=len(next_config_raw))
    next_manifest = copy.deepcopy(manifest)
    next_manifest["config"] = config_descriptor
    next_manifest["layers"].append(layer_descriptor)
    next_manifest_raw = helper.encode(next_manifest)
    digest = helper.digest(next_manifest_raw)
    files = {"base-manifest.json": manifest_raw, "base-config.private.json": config_raw,
             "base-release.json": original_release, "release.json": release,
             "native-agent-layer.tar.gz": layer, "manifest.json": next_manifest_raw, "config.private.json": next_config_raw}
    pins = {}
    for name, raw in files.items():
        path = records / name
        with path.open("xb") as output:
            output.write(raw)
        pins[name] = {"File": str(path), "SHA256": sha(raw)}
    print("Publishing by immutable digest", digest, flush=True)
    registry.upload(layer_descriptor, layer)
    registry.upload(config_descriptor, next_config_raw)
    present = registry.manifest(digest, missing=True)
    if present is None:
        with registry.request("PUT", registry.path("manifests", digest), data=next_manifest_raw,
                              content_type=next_manifest["mediaType"]) as response:
            need(response.status == 201 and response.headers.get("Docker-Content-Digest") == digest, "image publication unconfirmed")
    else:
        need(present[0] == next_manifest_raw, "existing immutable manifest mismatch")
    need(registry.manifest(digest)[0] == next_manifest_raw and registry.json_blob(config_descriptor)[0] == next_config_raw
         and registry.manifest(BASE)[0] == manifest_raw, "image publication readback failed")
    need(registry.verify_blob_bytes(layer_descriptor, layer), "published layer readback failed")
    receipt = {"version": "hermes-lite-native-tls-repair.v1", "base_digest": BASE, "manifest_digest": digest,
               "config_digest": config_descriptor["digest"], "agent_sha256": AGENT, "release_sha256": sha(release),
               "payload_sha256": payload_sha, "desktop_web_accepted": False, "pins": pins,
               "image": "10.130.14.23:5000/hermes-lite@" + digest, "status": "image-published-no-rollout"}
    (records / "publication.receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("HERMES_LITE_NATIVE_IMAGE_PUBLISHED", receipt["image"], flush=True)
    return receipt
