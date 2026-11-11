#!/usr/bin/env python3
"""Read actual immutable OCI bytes for the existing original startup decoder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = {
    "openclaw": ("730758ed3025b5a1c7fd91b14214eea1d5a50950ef3fd56012a5efb48f345769", "c9798a575acf6d1c832a268fa53a057c3d1bb42ce7bdb06f887cddf7d00fb90a"),
    "hermes": ("5fe79507129002540c2fbc25fc49bbd10326cb65dbc752885cfc845b2860731d", "4a36a2cda56406be6c4183eca5c58ac91dcceb36cb3342b7520b315c564a6c92"),
}
HERMES_LITE_MANIFEST = "279fa5b365f875de1fad93b0f58cda20599d2339fa067bf062e08ef80d770254"
HERMES_LITE_BASE = ("47729188347a01d249d5a929e474b3bb9959a138c138031a84ec39a7c6412cc7", "e946aefc144302ff072039ff52f0ddeb749f8155a6a017bc4b5edc7a9f58c7b4")


def require(ok):
    if not ok:
        raise RuntimeError("actual_immutable_runtime_input_not_confirmed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("registry_redirect_refused")


def unique_json(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def write_new(path, raw):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as file:
        require(file.write(raw) == len(raw))
        file.flush()
        os.fsync(file.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="append", required=True, help="repeat actual runtime=10.130.14.23:5000/repository@sha256:digest")
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--registry-url", default="http://10.130.14.23:5000")
    parser.add_argument("--authorization-file", help="existing private Basic/Bearer header file, never an argv credential")
    a = parser.parse_args()
    origin = urllib.parse.urlsplit(a.registry_url)
    require(origin.scheme in ("http", "https") and origin.netloc == "10.130.14.23:5000"
            and origin.path in ("", "/") and not origin.query and not origin.fragment)
    headers = {"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}
    if a.authorization_file:
        path = Path(a.authorization_file)
        require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
                and path.stat().st_size <= 16384 and (os.name != "posix" or path.stat().st_mode & 0o077 == 0))
        value = path.read_text().strip()
        require(value.startswith(("Basic ", "Bearer ")) and "\n" not in value and "\r" not in value)
        headers["Authorization"] = value
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    directory = Path(a.output_directory)
    require(directory.is_absolute() and directory.parent.resolve(strict=True) == directory.parent
            and not directory.exists() and (os.name != "posix" or directory.parent.stat().st_mode & 0o077 == 0))
    directory.mkdir(mode=0o700)
    images, seen = [], set()

    def fetch(repository, category, digest, name, maximum, exact_size=None):
        require(re.fullmatch(r"[a-f0-9]{64}", digest))
        request = urllib.request.Request(a.registry_url.rstrip("/") + "/v2/" + repository + "/" + category + "/sha256:" + digest, headers=headers)
        target = directory / name
        count, hasher = 0, hashlib.sha256()
        with opener.open(request, timeout=30) as response:
            require(response.status == 200)
            with os.fdopen(os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as file:
                while True:
                    chunk = response.read(min(1 << 20, maximum + 1 - count))
                    if not chunk:
                        break
                    count += len(chunk)
                    require(count <= maximum)
                    require(file.write(chunk) == len(chunk))
                    hasher.update(chunk)
                file.flush()
                os.fsync(file.fileno())
        require(count > 0 and (exact_size is None or count == exact_size) and hasher.hexdigest() == digest)
        return {"File": str(target), "SHA256": digest}

    for selected in a.image:
        kind, sep, reference = selected.partition("=")
        require(sep and kind in BASE and kind not in seen)
        seen.add(kind)
        match = re.fullmatch(r"10\.130\.14\.23:5000/([a-z0-9][a-z0-9._/-]{0,200})@sha256:([a-f0-9]{64})", reference)
        require(match and all(part not in ("", ".", "..") for part in match.group(1).split("/")))
        repository, candidate = match.groups()
        original_manifest, original_config = HERMES_LITE_BASE if kind == "hermes" and candidate == HERMES_LITE_MANIFEST else BASE[kind]
        bm = fetch(repository, "manifests", original_manifest, kind + "-base-manifest.json", 262144)
        base = unique_json(Path(bm["File"]).read_bytes())
        require(base["config"]["digest"] == "sha256:" + original_config)
        bc = fetch(repository, "blobs", original_config, kind + "-base-config.json", 262144, base["config"]["size"])
        nm = fetch(repository, "manifests", candidate, kind + "-manifest.json", 262144)
        current = unique_json(Path(nm["File"]).read_bytes())
        nc = fetch(repository, "blobs", current["config"]["digest"].removeprefix("sha256:"), kind + "-config.json", 262144, current["config"]["size"])
        require(len(current["layers"]) == len(base["layers"]) + 1 and current["layers"][:-1] == base["layers"])
        descriptor = current["layers"][-1]
        layer = fetch(repository, "blobs", descriptor["digest"].removeprefix("sha256:"), kind + "-managed-layer.tar.gz", 128 << 20, descriptor["size"])
        images.append({"BaseManifest": bm, "BaseConfig": bc, "Manifest": nm, "Config": nc, "Layer": layer})
    raw = (json.dumps({"Version": "original-runtime-startup-image-inputs.v1", "Images": images}, sort_keys=True, separators=(",", ":")) + "\n").encode()
    definition = directory / "runtime-startup-images.json"
    write_new(definition, raw)
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print(json.dumps({"state": "actual_registry_bytes_exported_requires_go_content_and_original_native_verification",
                      "file": str(definition), "sha256": hashlib.sha256(raw).hexdigest(),
                      "runtime_count": len(images), "runtime_or_hold_authority": False}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Runtime input export unconfirmed; retain the partial private directory; no startup/ownership/hold claim.", file=sys.stderr)
        sys.exit(3)
