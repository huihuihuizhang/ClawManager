#!/usr/bin/env python3
"""Build one reviewed Linux snapshot without registry access.

The caller supplies an exported, accepted source tree and its exact Git commit.
This tool never connects to Kubernetes or starts the application. Its sole
container start removes old static assets from a disposable local image layer.
Pending delivery artifacts are retained; temporary containers are removed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import time


BASE = "sha256:c16f07c25c6dc8362aa09b7a1e81f5d1204f2812ae542bbcb21a3946975c6c9d"
GO = "sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039"
OWNER = "supervisor-page-trial-release-20261103"
LABEL = "io.clawmanager.page-release"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def shared_agent_inputs(path, expected_sha256):
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise RuntimeError("exact shared-agent build-input digest required")
    path = path.resolve(strict=True)
    if digest(path) != expected_sha256:
        raise RuntimeError("shared-agent build-input changed")
    raw = path.read_bytes()
    build = json.loads(raw)
    if (build.get("schema_version") != "shared-native-tls-agent-build-input.v1"
            or not re.fullmatch(r"[a-f0-9]{64}", build.get("source_tree_sha256", ""))
            or set(build.get("binaries", {})) != {"openclaw", "hermes"}):
        raise RuntimeError("reviewed finite shared-agent build-input required")
    bundle = build["bundle"]
    archive = path.parent / Path(bundle["path"]).name
    if (archive.resolve(strict=True).parent != path.parent
            or digest(archive) != bundle["sha256"]):
        raise RuntimeError("original shared-agent production bundle changed")
    agents = {}
    for runtime in ("openclaw", "hermes"):
        alias = runtime + "-lite-agent"
        binary = path.parent / alias
        pin = build["binaries"][runtime]
        if (binary.resolve(strict=True).parent != path.parent
                or binary.stat().st_size != pin["bytes"]
                or digest(binary) != pin["sha256"]):
            raise RuntimeError("original shared-agent ELF changed")
        with binary.open("rb") as source:
            header = source.read(20)
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
            raise RuntimeError("shared agent is not Linux amd64 ELF")
        agents[runtime] = {"alias": alias, "path": binary,
                           "sha256": pin["sha256"], "bytes": pin["bytes"]}
    if digest(path) != expected_sha256 or path.read_bytes() != raw:
        raise RuntimeError("shared-agent build-input changed while reading")
    return agents, {"build_input_sha256": expected_sha256,
                    "revision": build["revision"],
                    "source_tree_sha256": build["source_tree_sha256"],
                    "bundle_sha256": bundle["sha256"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--frontend-source", required=True, type=Path)
    p.add_argument("--work-root", required=True, type=Path)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--docker", required=True)
    p.add_argument("--docker-host", default="npipe:////./pipe/dockerDesktopLinuxEngine")
    p.add_argument("--module-cache", required=True, type=Path)
    p.add_argument("--cache-volume", required=True)
    p.add_argument("--work-volume", required=True)
    p.add_argument("--extra-tool", action="append", default=[])
    p.add_argument("--shared-agent-input", type=Path)
    p.add_argument("--shared-agent-input-sha256")
    args = p.parse_args()
    if (args.shared_agent_input is None) != (args.shared_agent_input_sha256 is None):
        raise RuntimeError("shared-agent input and exact digest must be supplied together")
    agents, agent_provenance = ({}, None)
    if args.shared_agent_input is not None:
        agents, agent_provenance = shared_agent_inputs(
            args.shared_agent_input, args.shared_agent_input_sha256)
    root = args.work_root.resolve(strict=True)
    if (root / ".owner").read_text().strip() != OWNER:
        raise RuntimeError("wrong work-root owner")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise RuntimeError("exact accepted Git commit required")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,80}", args.version):
        raise RuntimeError("invalid version")
    source = args.source.resolve(strict=True)
    web = args.frontend_source.resolve(strict=True)
    out = root / ("delivery-" + args.version)
    out.mkdir(exist_ok=False)
    (out / ".owner").write_text(OWNER, encoding="utf-8")
    dc = [args.docker, "--host", args.docker_host]
    label_value = root.name.removeprefix("codex-backup-page-trial-release-")
    label = LABEL + "=" + label_value
    receipt = {"scope": "local-build-not-page-acceptance", "commit": args.commit,
               "version": args.version, "base_image": BASE, "go_image": GO,
               "full_page_acceptance": False, "dr_qualified": False}

    def capture(argv):
        return subprocess.check_output(dc + argv, text=True, encoding="utf-8").strip()

    def run(argv, name):
        with (out / (name + ".log")).open("wb") as log:
            subprocess.run(dc + argv, stdout=log, stderr=subprocess.STDOUT, check=True)

    def remove_owned(cid):
        obj = json.loads(capture(["inspect", cid]))[0]
        if obj["Config"]["Labels"].get(LABEL) != label_value:
            raise RuntimeError("container owner changed")
        subprocess.run(dc + ["rm", cid], check=True)

    for image in (BASE, GO):
        obj = json.loads(capture(["image", "inspect", image]))[0]
        if obj["Id"] != image or obj["Architecture"] != "amd64" or obj["Os"] != "linux":
            raise RuntimeError("local image identity mismatch")
    for volume in (args.cache_volume, args.work_volume):
        obj = json.loads(capture(["volume", "inspect", volume]))[0]
        if (obj.get("Labels") or {}).get(LABEL) != label_value:
            raise RuntimeError("build volume owner mismatch")
    for image in ("clawmanager-page-trial:" + args.version,
                  "clawmanager-backup-worker:" + args.version):
        result = subprocess.run(dc + ["image", "inspect", image],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if result.returncode == 0:
            raise RuntimeError("delivery image tag already exists; choose a new version")
        if b"No such image" not in result.stderr and b"not found" not in result.stderr:
            raise RuntimeError("cannot confirm delivery image tag absence")
    # Use all original Dockerfile command mappings plus explicitly reviewed new tools.
    dockerfile = (source / "Dockerfile").read_text(encoding="utf-8")
    tools = dict(re.findall(r"-o /out/([\w-]+) ./cmd/([\w-]+)", dockerfile))
    for name in re.findall(r"(?m)^\s+(system-backup-[\w-]+|backup-(?:node|gateway-node|stopped-pro-node)-observer|backup-shared-runtime-node-owner)(?:\s+\\|;\s+do)", dockerfile):
        tools[name] = name
    for name in args.extra_tool:
        if not re.fullmatch(r"[a-z][a-z0-9-]+", name):
            raise RuntimeError("invalid command name")
        tools[name] = name
    if "clawreef-server" not in tools or "backup-worker" not in tools:
        raise RuntimeError("incomplete original command map")
    for command in tools.values():
        if not (source / "backend" / "cmd" / command).is_dir():
            raise RuntimeError("missing reviewed tool: " + command)
    receipt["tools"] = tools
    # Pin every backend build input, including embedded migrations and templates.
    inputs = {}
    for path in sorted((source / "backend").rglob("*")):
        if path.is_file() and not any(x.startswith(".") for x in path.relative_to(source / "backend").parts):
            inputs[path.relative_to(source).as_posix()] = digest(path)
    receipt["backend_inputs"] = inputs
    receipt["backend_inputs_sha256"] = hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    receipt["web_assets"] = {}
    for directory in ("frontend/dist", "frontend/public/hermes-desktop-web"):
        files = {p.relative_to(web).as_posix(): digest(p)
                 for p in sorted((web / directory).rglob("*")) if p.is_file()}
        if not files:
            raise RuntimeError("missing built web assets: " + directory)
        receipt["web_assets"].update(files)
    (out / "build-inputs.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    bins = out / "bin"
    bins.mkdir()
    date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # One Go invocation per linker-flag group shares package loading and
    # schedules link jobs under the existing -p=2 CPU/memory bound.
    # Unique target basenames and collision-free aliases permit direct output.
    if len(set(tools.values())) != len(tools) or any(
            alias != target and target in tools for alias, target in tools.items()):
        raise RuntimeError("review unique command basenames and output aliases")
    cmds = []
    for versioned in (False, True):
        selected = [(alias, target) for alias, target in sorted(tools.items())
                    if (alias in ("clawreef-server", "system-backup-v2-controller")) == versioned]
        if not selected:
            continue
        ld = "-s -w -buildid="
        if versioned:
            ld += " -X clawreef/internal/buildinfo.Version=" + args.version
            ld += " -X clawreef/internal/buildinfo.Commit=" + args.commit
            ld += " -X clawreef/internal/buildinfo.BuildTime=" + date
        cmds.append("go build -mod=readonly -trimpath -buildvcs=false -p=2 -ldflags '" + ld +
                    "' -o /out/ " + " ".join("./cmd/" + target for _, target in selected))
    for alias, target in sorted(tools.items()):
        if alias != target:
            cmds.append("mv /out/" + target + " /out/" + alias)
    run(["run", "--rm", "--pull=never", "--network", "none", "--label", label,
         "--name", "sbk-page-final-go-" + label_value[:8], "--memory", "3g", "--cpus", "2",
         "-v", str(source) + ":/source:ro", "-v", str(args.module_cache) + ":/deps:ro",
         "-v", str(bins) + ":/out", "-v", args.cache_volume + ":/cache",
         "-v", args.work_volume + ":/work", "-w", "/source/backend",
         "-e", "GOMODCACHE=/deps", "-e", "GOCACHE=/cache", "-e", "TMPDIR=/work",
         "-e", "GOPROXY=off", "-e", "GOSUMDB=off", "-e", "GOTOOLCHAIN=local",
         "-e", "GOMAXPROCS=2", "-e", "CGO_ENABLED=0", "-e", "GOOS=linux",
         "-e", "GOARCH=amd64", GO, "/bin/sh", "-ec", "\n".join(cmds)], "go-build")
    receipt["binaries"] = {}
    for alias in tools:
        binary = bins / alias
        with binary.open("rb") as src:
            header = src.read(20)
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
            raise RuntimeError("not Linux amd64 ELF: " + alias)
        receipt["binaries"][alias] = digest(binary)
    if agents:
        receipt["shared_agent_binaries"] = {}
        receipt["shared_agent_provenance"] = agent_provenance
        for runtime, agent in agents.items():
            alias = agent["alias"]
            if alias in tools:
                raise RuntimeError("shared-agent alias collides with original backend tool")
            shutil.copyfile(agent["path"], bins / alias)
            if digest(bins / alias) != agent["sha256"]:
                raise RuntimeError("copied shared-agent ELF differs from original production input")
            receipt["binaries"][alias] = agent["sha256"]
            receipt["shared_agent_binaries"][runtime] = alias
    app_tag = "clawmanager-page-trial:" + args.version
    worker_tag = "clawmanager-backup-worker:" + args.version
    layer = out / "app-overlay.tar"
    with tarfile.open(layer, "w") as tf:
        def add(path, name, executable=False):
            def metadata(info):
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mode = 0o755 if info.isdir() or executable else 0o644
                return info
            tf.add(path, arcname=name, filter=metadata)
        for alias in tools:
            add(bins / alias, "usr/local/bin/" + alias, True)
        add(bins / "clawmanager-secret-broker", "usr/local/bin/clawreef-secret-broker", True)
        add(web / "frontend/dist", "usr/share/nginx/html")
        add(web / "frontend/public/hermes-desktop-web", "usr/share/nginx/html/hermes-desktop-web")
        # Include every reviewed repository runtime COPY in the final app stage,
        # including newly introduced nginx/startup helpers. Stage outputs above
        # are supplied by our same-source binary and frontend builds.
        in_app = False
        receipt["runtime_files"] = {}
        for line in dockerfile.splitlines():
            if line.startswith("FROM "):
                in_app = line.strip().endswith(" AS app")
            if not in_app or not line.startswith("COPY ") or "--from=" in line:
                continue
            fields = shlex.split(line)
            if len(fields) != 3 or not fields[1].startswith("deployments/"):
                raise RuntimeError("unsupported runtime COPY; review explicit source mapping")
            src, dst = fields[1:]
            original = (source / src).resolve(strict=True)
            if not original.is_relative_to(source) or not original.is_file() or not dst.startswith("/"):
                raise RuntimeError("runtime COPY path outside reviewed source")
            add(original, dst.lstrip("/"), original.suffix == ".sh")
            receipt["runtime_files"][src] = {"target": dst, "sha256": digest(original)}
    cid = capture(["create", "--network", "none", "--label", label, "--entrypoint", "/bin/sh", BASE,
                   "-ec", "rm -rf -- /usr/share/nginx/html; mkdir -p /usr/share/nginx/html"])
    try:
        run(["start", "--attach", cid], "static-clean")
        with layer.open("rb") as src:
            subprocess.run(dc + ["cp", "-", cid + ":/"], stdin=src, check=True)
        capture(["commit", "--pause=false", "--change", 'ENTRYPOINT ["dumb-init","--"]',
                          "--change", 'CMD ["/app/start.sh"]', "--change", "LABEL " + label,
                          "--change", "LABEL org.opencontainers.image.revision=" + args.commit,
                          "--change", "LABEL io.clawmanager.source-sha256=" + receipt["backend_inputs_sha256"],
                          cid, app_tag])
        app_id = json.loads(capture(["image", "inspect", app_tag]))[0]["Id"]
    finally:
        remove_owned(cid)
    worker_tar = out / "worker-rootfs.tar"
    with tarfile.open(worker_tar, "w") as tf:
        for alias in ("backup-worker", "system-backup-seal-custody"):
            info = tf.gettarinfo(str(bins / alias), arcname=alias)
            info.mode, info.uid, info.gid = 0o555, 0, 0
            with (bins / alias).open("rb") as src:
                tf.addfile(info, src)
    capture(["import", "--platform", "linux/amd64", "--change", "USER 65532:65532",
                         "--change", 'ENTRYPOINT ["/backup-worker"]', "--change", "LABEL " + label,
                         "--change", "LABEL org.opencontainers.image.revision=" + args.commit,
                         str(worker_tar), worker_tag])
    worker_id = json.loads(capture(["image", "inspect", worker_tag]))[0]["Id"]
    receipt["images"] = {"app": {"tag": app_tag, "id": app_id},
                         "worker": {"tag": worker_tag, "id": worker_id}}
    for role, obj in receipt["images"].items():
        config = json.loads(capture(["image", "inspect", obj["id"]]))[0]
        (out / (role + "-image-inspect.json")).write_text(json.dumps(config, indent=2), encoding="utf-8")
    run(["save", "-o", str(out / "images.tar"), app_tag, worker_tag], "image-save")
    # Docker's containerd store may report a manifest digest as image Id.
    # Resolve the actual config digest from the exported bytes for registry checks.
    with tarfile.open(out / "images.tar", "r") as archive:
        manifests = json.load(archive.extractfile("manifest.json"))
        for obj in receipt["images"].values():
            entries = [x for x in manifests if obj["tag"] in x.get("RepoTags", [])]
            if len(entries) != 1:
                raise RuntimeError("exported image tag is ambiguous")
            raw = archive.extractfile(entries[0]["Config"]).read()
            obj["config_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    receipt["archive_sha256"] = digest(out / "images.tar")
    receipt["archive_bytes"] = (out / "images.tar").stat().st_size
    (out / "build-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps({"directory": str(out), "images": receipt["images"],
                      "sha256": receipt["archive_sha256"], "page_acceptance": False}))


if __name__ == "__main__":
    main()
