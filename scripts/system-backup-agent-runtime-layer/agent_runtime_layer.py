#!/usr/bin/env python3
"""Append the pinned static Agent to a pinned runtime using only Registry V2.

No builders, SSH, subprocesses, workload operations or mutable tag writes.
The explicit HTTP origin below is the sole insecure registry exception.
"""
import argparse
import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

REGISTRY_ORIGIN = "http://10.130.14.23:5000"
REVISION = "52f47fc-core-2408962c473d-sameepoch-r1"
BUNDLE_SHA = "74257a0908591107fcfde27371e0799a593e02aab0e0d50c75890ccfc1191249"
PROFILES = {
    "openclaw": {"repository": "openclaw-lite",
        "base": "sha256:37c43ba05ff7fd4f0949f274fc67c3e9825f6d3d0f9124b5fc45dc8366c39cee",
        "agent_sha": "63a68c0a916a5d873c420c086f81a77d7d3c3f41bd5d798428b4608db0552cc1", "agent_size": 9994402},
    "hermes": {"repository": "hermes-lite",
        "base": "sha256:6688834a944161d8dada995cdffd90781533b24ab1e75bb2182c46eaee3fb52c",
        "agent_sha": "851104a524ff26797c58c6a5a1e0e8172353ecdd31c31a07032a81073a225a42", "agent_size": 10072226},
}
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar": False,
    "application/vnd.oci.image.layer.v1.tar+gzip": True,
    "application/vnd.docker.image.rootfs.diff.tar": False,
    "application/vnd.docker.image.rootfs.diff.tar.gzip": True,
}
TARGET = "usr/local/bin/clawmanager-agent"
TRACKED = ("usr", "usr/local", "usr/local/bin", TARGET)
MAX_JSON = 4 << 20
MAX_BINARY = 32 << 20
MAX_LAYER = 8 << 30
MAX_PLAIN = 32 << 30
CHUNK = 65536
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
ACCEPT = ", ".join((OCI_MANIFEST, DOCKER_MANIFEST, OCI_INDEX, DOCKER_INDEX))


class Refused(Exception):
    """Contains a fixed public error code only, never response bodies/secrets."""


def require(value, code):
    if not value:
        raise Refused(code)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise Refused("invalid_json_number")
    require(0 < len(raw) <= MAX_JSON, "json_size")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("invalid_json") from None
    require(isinstance(value, dict), "json_object_required")
    return value


def regular_bytes(path, limit, private=False):
    path = Path(path)
    require(path.is_absolute(), "absolute_input_path_required")
    for item in (path, *path.parents):
        require(not item.is_symlink() and not getattr(os.path, "isjunction", lambda _: False)(item), "input_link_refused")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, "input_size_or_kind")
        if private and os.name != "nt":
            require(before.st_uid == os.geteuid() and before.st_mode & 0o077 == 0, "credential_file_not_private")
        raw = source.read(limit + 1)
        after = os.fstat(source.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and len(raw) == before.st_size, "input_changed")
    return raw


def validate_elf(raw, profile):
    require(len(raw) == profile["agent_size"] and digest(raw) == "sha256:" + profile["agent_sha"], "agent_sha_or_size")
    require(len(raw) >= 64, "elf_header")
    fields = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    ident, kind, machine, version, entry, phoff = fields[:6]
    require(ident[:7] == b"\x7fELF\x02\x01\x01" and ident[7] in (0, 3) and ident[8] == 0,
            "elf_linux64_required")
    require(kind in (2, 3) and machine == 62 and version == 1 and fields[8:10] == (64, 56), "elf_amd64_required")
    count = fields[10]
    require(0 < count <= 4096 and 64 <= phoff <= len(raw) and phoff + count * 56 <= len(raw), "elf_program_table")
    executable = False
    for position in range(count):
        ptype, flags, offset, address, _, size, memory, _ = struct.unpack_from("<IIQQQQQQ", raw, phoff + position * 56)
        require(ptype not in (2, 3, 5), "elf_static_required")
        require(offset <= len(raw) and size <= len(raw) - offset, "elf_segment_bounds")
        if ptype == 1:
            require(size <= memory, "elf_load_memory")
            executable |= bool(flags & 1 and address <= entry < address + size)
    require(executable, "elf_executable_entry")


def agent_from_bundle(path, runtime):
    raw = regular_bytes(path, MAX_BINARY)
    require(digest(raw) == "sha256:" + BUNDLE_SHA, "bundle_sha")
    expected = {"BUILD_INPUT.json", "README.txt", "openclaw/clawmanager-agent", "hermes/clawmanager-agent"}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == 4 and {m.name for m in members} == expected and all(m.isfile() for m in members), "bundle_entries")
        for member in members:
            require(0 < member.size <= MAX_BINARY, "bundle_member_size")
        member = archive.getmember(runtime + "/clawmanager-agent")
        require(member.size == PROFILES[runtime]["agent_size"], "bundle_agent_size")
        with archive.extractfile(member) as source:
            agent = source.read(MAX_BINARY + 1)
    validate_elf(agent, PROFILES[runtime])
    return agent


def stored_gzip(raw):
    # Fixed RFC1951 stored blocks, independent of zlib encoder/platform/version.
    output = bytearray(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
    for offset in range(0, len(raw), 65535):
        part = raw[offset:offset + 65535]
        output.append(int(offset + len(part) == len(raw)))
        output.extend(struct.pack("<HH", len(part), len(part) ^ 65535))
        output.extend(part)
    output.extend(struct.pack("<II", zlib.crc32(raw) & 0xffffffff, len(raw) & 0xffffffff))
    return bytes(output)


def agent_layer(agent):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo(TARGET)
        member.size, member.mode, member.uid, member.gid, member.mtime = len(agent), 0o555, 0, 0, 0
        member.uname = member.gname = ""
        archive.addfile(member, io.BytesIO(agent))
    plain = output.getvalue()
    return stored_gzip(plain), digest(plain)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        # Refuse before the redirected request, including same-origin redirects.
        raise Refused("registry_redirect_refused")


class Registry:
    def __init__(self, repository, authorization=None, seconds=1800):
        require(repository in {p["repository"] for p in PROFILES.values()}, "repository_not_allowed")
        self.origin, self.repository = REGISTRY_ORIGIN, repository
        self.expiry = time.monotonic() + seconds
        self.authorization = authorization
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def live(self):
        require(time.monotonic() < self.expiry, "operation_deadline")

    def url(self, path):
        self.live()
        require(isinstance(path, str) and 0 < len(path) <= 8192 and all(32 < ord(c) < 127 for c in path), "registry_url")
        url = urllib.parse.urljoin(self.origin + "/", path)
        value, original = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.origin)
        require((value.scheme, value.netloc) == (original.scheme, original.netloc) and
                not value.fragment and value.username is None and value.password is None and
                value.path.startswith("/v2/" + self.repository + "/") and
                "%" not in value.path and "\\" not in value.path and
                ".." not in value.path.split("/"), "registry_origin_or_repository")
        return url

    def request(self, method, path, data=None, content_type=None, missing=False):
        headers = {"Accept": ACCEPT, "Accept-Encoding": "identity", "User-Agent": "cm-agent-runtime-layer/1"}
        if self.authorization:
            headers["Authorization"] = self.authorization
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.url(path), data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=max(0.1, min(30, self.expiry - time.monotonic())))
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if missing and status == 404:
                return None
            raise Refused("registry_http_" + str(status)) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise Refused("registry_io") from None
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            response.close()
            raise Refused("http_content_encoding")
        return response

    def path(self, category, reference):
        return "/v2/" + self.repository + "/" + category + "/" + reference

    def manifest(self, reference, missing=False):
        require(SHA.fullmatch(reference) or re.fullmatch(r"cm-agent-[0-9a-f]{64}", reference), "manifest_reference")
        response = self.request("GET", self.path("manifests", reference), missing=missing)
        if response is None:
            return None
        with response:
            require(response.status == 200, "manifest_http_status")
            raw = response.read(MAX_JSON + 1)
            require(len(raw) <= MAX_JSON and response.headers.get("Docker-Content-Digest") == digest(raw) and
                    (not reference.startswith("sha256:") or reference == digest(raw)), "manifest_digest")
            value = decode(raw)
            media = value.get("mediaType")
            require(value.get("schemaVersion") == 2 and media in (OCI_MANIFEST, DOCKER_MANIFEST, OCI_INDEX, DOCKER_INDEX) and
                    response.headers.get_content_type() == media, "manifest_schema_or_media")
        return raw, value

    def blob(self, descriptor, missing=False):
        validate_descriptor(descriptor)
        response = self.request("GET", self.path("blobs", descriptor["digest"]), missing=missing)
        if response is None:
            return None
        try:
            require(response.status == 200, "blob_http_status")
            header = response.headers.get("Docker-Content-Digest")
            length = response.headers.get("Content-Length")
            require((header is None or header == descriptor["digest"]) and
                    (length is None or length == str(descriptor["size"])), "blob_headers")
        except Exception:
            response.close()
            raise
        return response

    def json_blob(self, descriptor):
        require(descriptor["size"] <= MAX_JSON, "config_size")
        with self.blob(descriptor) as source:
            raw = source.read(MAX_JSON + 1)
        require(len(raw) == descriptor["size"] and digest(raw) == descriptor["digest"], "config_digest")
        return raw, decode(raw)

    def verify_blob_bytes(self, descriptor, expected, missing=False):
        response = self.blob(descriptor, missing=missing)
        if response is None:
            return False
        with response:
            raw = response.read(len(expected) + 1)
        require(raw == expected and digest(raw) == descriptor["digest"], "blob_readback")
        return True

    def upload(self, descriptor, raw):
        require(descriptor["size"] == len(raw) and descriptor["digest"] == digest(raw), "upload_input")
        if self.verify_blob_bytes(descriptor, raw, missing=True):
            return
        with self.request("POST", self.path("blobs/uploads", ""), data=b"") as response:
            require(response.status == 202, "upload_start_status")
            location = response.headers.get("Location")
        require(isinstance(location, str), "upload_location_missing")
        url = self.url(location)
        value = urllib.parse.urlsplit(url)
        prefix = self.path("blobs/uploads", "")
        require(value.path.startswith(prefix) and re.fullmatch(r"[A-Za-z0-9._-]{1,256}", value.path[len(prefix):]) and
                not any(key == "digest" for key, _ in urllib.parse.parse_qsl(value.query, keep_blank_values=True)), "upload_location_path")
        url += ("&" if value.query else "?") + urllib.parse.urlencode({"digest": descriptor["digest"]})
        with self.request("PUT", url, data=raw, content_type="application/octet-stream") as response:
            require(response.status == 201 and response.headers.get("Docker-Content-Digest") == descriptor["digest"], "upload_completion")
            location = response.headers.get("Location")
            require(location is not None and urllib.parse.urlsplit(self.url(location)).path == self.path("blobs", descriptor["digest"]), "upload_read_location")
        require(self.verify_blob_bytes(descriptor, raw), "upload_readback_missing")


def validate_descriptor(descriptor):
    require(isinstance(descriptor, dict) and isinstance(descriptor.get("digest"), str) and SHA.fullmatch(descriptor["digest"]) and
            type(descriptor.get("size")) is int and 0 < descriptor["size"] <= MAX_LAYER and
            not descriptor.get("urls") and "data" not in descriptor, "descriptor_invalid_or_external")


class CountedReader:
    def __init__(self, source, limit, registry):
        self.source, self.limit, self.registry = source, limit, registry
        self.count, self.sha = 0, hashlib.sha256()

    def read(self, size=-1):
        self.registry.live()
        raw = self.source.read(CHUNK if size < 0 else min(size, CHUNK))
        self.count += len(raw)
        require(self.count <= self.limit, "layer_size_limit")
        self.sha.update(raw)
        return raw


def check_layer(registry, descriptor, diff_id, agent=None):
    require(descriptor.get("mediaType") in LAYER_TYPES and isinstance(diff_id, str) and SHA.fullmatch(diff_id), "layer_media_or_diffid")
    whiteouts, entries = [], []
    with registry.blob(descriptor) as response:
        compressed = CountedReader(response, descriptor["size"], registry)
        stream = gzip.GzipFile(fileobj=compressed, mode="rb") if LAYER_TYPES[descriptor["mediaType"]] else compressed
        plain = CountedReader(stream, MAX_PLAIN, registry)
        try:
            with tarfile.open(fileobj=plain, mode="r|") as archive:
                count = 0
                for member in archive:
                    count += 1
                    require(count <= 2000000, "layer_member_limit")
                    name = member.name
                    while name.startswith("./"):
                        name = name[2:]
                    require(not name.startswith("/") and ".." not in name.split("/") and "\\" not in name, "layer_path")
                    name = name.rstrip("/")
                    parent, _, leaf = name.rpartition("/")
                    if leaf == ".wh..wh..opq":
                        whiteouts.append((parent, True))
                    elif leaf.startswith(".wh."):
                        whiteouts.append(((parent + "/" if parent else "") + leaf[4:], False))
                    if name in TRACKED:
                        entries.append((name, "directory" if member.isdir() else "regular" if member.isfile() else "other"))
                    if agent is not None:
                        require(count == 1 and name == TARGET and member.isfile() and member.mode == 0o555 and
                                member.uid == member.gid == member.mtime == 0 and member.size == len(agent), "new_layer_members")
                        with archive.extractfile(member) as source:
                            value = hashlib.sha256()
                            for chunk in iter(lambda: source.read(CHUNK), b""):
                                value.update(chunk)
                        require(value.hexdigest() == hashlib.sha256(agent).hexdigest(), "new_layer_agent")
                require(agent is None or count == 1, "new_layer_empty")
            for _ in iter(lambda: plain.read(CHUNK), b""):
                pass
        except (tarfile.TarError, OSError, EOFError, zlib.error):
            raise Refused("layer_archive_or_gzip_invalid") from None
        require(compressed.count == descriptor["size"] and "sha256:" + compressed.sha.hexdigest() == descriptor["digest"], "layer_blob_digest")
        require("sha256:" + plain.sha.hexdigest() == diff_id, "layer_diffid")
    return whiteouts, entries


def resolve_base(registry, reference):
    raw, manifest = registry.manifest(reference)
    root_digest = digest(raw)
    if manifest["mediaType"] in (OCI_INDEX, DOCKER_INDEX):
        descriptors = manifest.get("manifests")
        require(isinstance(descriptors, list) and 0 < len(descriptors) <= 1024, "index_manifests")
        selected = [item for item in descriptors if isinstance(item, dict) and isinstance(item.get("platform"), dict) and
                    item["platform"].get("os") == "linux" and item["platform"].get("architecture") == "amd64"]
        require(len(selected) == 1, "index_unique_linux_amd64")
        child = selected[0]
        validate_descriptor(child)
        raw, manifest = registry.manifest(child["digest"])
        require(len(raw) == child["size"] and manifest["mediaType"] == child.get("mediaType"), "index_child_descriptor")
    require(manifest["mediaType"] in (OCI_MANIFEST, DOCKER_MANIFEST) and not manifest.get("artifactType"), "runtime_manifest_required")
    config_descriptor, layers = manifest.get("config"), manifest.get("layers")
    validate_descriptor(config_descriptor)
    require(config_descriptor.get("mediaType") == (OCI_CONFIG if manifest["mediaType"] == OCI_MANIFEST else DOCKER_CONFIG), "runtime_config_media")
    require(isinstance(layers, list) and 0 < len(layers) <= 1000, "base_layers")
    _, config = registry.json_blob(config_descriptor)
    require(config.get("os") == "linux" and config.get("architecture") == "amd64", "base_platform")
    rootfs = config.get("rootfs")
    require(isinstance(rootfs, dict) and rootfs.get("type") == "layers" and isinstance(rootfs.get("diff_ids"), list) and
            len(rootfs["diff_ids"]) == len(layers), "base_rootfs")
    if "history" in config:
        history = config["history"]
        require(isinstance(history, list) and all(isinstance(item, dict) and type(item.get("empty_layer", False)) is bool for item in history) and
                sum(not item.get("empty_layer", False) for item in history) == len(layers), "base_history")
    state = {}
    for descriptor, diff_id in zip(layers, rootfs["diff_ids"]):
        validate_descriptor(descriptor)
        whiteouts, entries = check_layer(registry, descriptor, diff_id)
        for path, opaque in whiteouts:
            for item in list(state):
                if (not path or item.startswith(path + "/")) or (not opaque and item == path):
                    state.pop(item)
        for path, kind in entries:
            state[path] = kind
    require(all(state.get(item) in (None, "directory") for item in TRACKED[:-1]) and
            state.get(TARGET) in (None, "regular"), "agent_parent_or_target_kind")
    return root_digest, digest(raw), manifest, config


def build(registry, runtime, profile, agent, push=False):
    validate_elf(agent, profile)
    root_digest, base_digest, original_manifest, original_config = resolve_base(registry, profile["base"])
    layer, diff_id = agent_layer(agent)
    oci = original_manifest["mediaType"] == OCI_MANIFEST
    layer_descriptor = {"digest": digest(layer), "size": len(layer), "mediaType":
        "application/vnd.oci.image.layer.v1.tar+gzip" if oci else "application/vnd.docker.image.rootfs.diff.tar.gzip"}
    config = copy.deepcopy(original_config)
    config["rootfs"]["diff_ids"].append(diff_id)
    if "history" in config:
        config["history"].append({"created": "1970-01-01T00:00:00Z", "created_by": "clawmanager pinned original-operation Agent overlay", "empty_layer": False})
    # Exact semantic preservation of ALL original fields except the append-only
    # diff_ids/history arrays, including secret Env without printing it.
    check = copy.deepcopy(config)
    check["rootfs"]["diff_ids"].pop()
    if "history" in check:
        check["history"].pop()
    require(check == original_config, "runtime_configuration_changed")
    config_raw = encode(config)
    config_descriptor = copy.deepcopy(original_manifest["config"])
    config_descriptor.update({"digest": digest(config_raw), "size": len(config_raw)})
    manifest = copy.deepcopy(original_manifest)
    manifest["config"] = config_descriptor
    manifest["layers"].append(layer_descriptor)
    manifest_raw = encode(manifest)
    new_digest = digest(manifest_raw)
    if push:
        # Existing tags are NEVER PUT. Registry V2 lacks portable atomic create-
        # only tags; publish by the exact manifest digest to avoid overwrite races.
        registry.upload(layer_descriptor, layer)
        check_layer(registry, layer_descriptor, diff_id, agent=agent)
        registry.upload(config_descriptor, config_raw)
        present = registry.manifest(new_digest, missing=True)
        if present is None:
            with registry.request("PUT", registry.path("manifests", new_digest), data=manifest_raw,
                                  content_type=manifest["mediaType"]) as response:
                require(response.status == 201 and response.headers.get("Docker-Content-Digest") == new_digest, "manifest_upload_completion")
        else:
            require(present[0] == manifest_raw, "existing_manifest_conflict")
        require(registry.manifest(new_digest)[0] == manifest_raw, "manifest_readback")
        require(registry.json_blob(config_descriptor)[0] == config_raw, "config_readback")
        # Authenticate both pinned root and selected child again, without any
        # mutable tag lookup. A failed final read never reports image-pushed.
        require(digest(registry.manifest(profile["base"])[0]) == root_digest and
                registry.manifest(base_digest)[1] == original_manifest, "base_readback")
    prefix = registry.origin.split("://", 1)[1] + "/" + registry.repository
    return {"schema_version": "a-agent-runtime-registry-layer.v1", "status": "image-pushed" if push else "image-built",
        "runtime": runtime, "agent_revision": REVISION, "agent_sha256": profile["agent_sha"],
        "base_reference": prefix + "@" + root_digest, "resolved_base_reference": prefix + "@" + base_digest,
        "base_config_digest": original_manifest["config"]["digest"], "base_layer_count": len(original_manifest["layers"]),
        "immutable_reference": prefix + "@" + new_digest, "manifest_digest": new_digest,
        "config_digest": config_descriptor["digest"], "appended_layer_digest": layer_descriptor["digest"], "appended_diff_id": diff_id,
        "derived_tag": prefix + ":cm-agent-" + new_digest[7:], "tag_written": False,
        "page": False, "native": False, "live": False, "workload_mutated": False, "deployment_identity_rechecked": False}


def credentials(path):
    if path is None:
        return None
    value = decode(regular_bytes(path, 16384, private=True))
    if set(value) == {"username", "password"}:
        require(all(isinstance(v, str) and 0 < len(v) <= 4096 for v in value.values()) and ":" not in value["username"], "credential_shape")
        return "Basic " + base64.b64encode((value["username"] + ":" + value["password"]).encode()).decode("ascii")
    require(set(value) == {"bearer_token"} and isinstance(value["bearer_token"], str) and
            re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value["bearer_token"]) and len(value["bearer_token"]) <= 8192, "credential_shape")
    return "Bearer " + value["bearer_token"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, choices=sorted(PROFILES))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--credentials-file", type=Path)
    parser.add_argument("--push", action="store_true", help="publish only by immutable digest; never write tags")
    parser.add_argument("--max-seconds", type=int, default=1800)
    args = parser.parse_args(argv)
    require(30 <= args.max_seconds <= 7200, "deadline_range")
    agent = agent_from_bundle(args.bundle, args.runtime)
    profile = PROFILES[args.runtime]
    registry = Registry(profile["repository"], authorization=credentials(args.credentials_file), seconds=args.max_seconds)
    print(encode(build(registry, args.runtime, profile, agent, push=args.push)).decode("ascii"))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, Refused) else "operation_failed"
        print(encode({"status": "refused", "error": code, "page": False, "native": False, "live": False}).decode(), file=sys.stderr)
        sys.exit(1)
