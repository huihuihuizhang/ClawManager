#!/usr/bin/env python3
"""Root-invoked LOCAL fixture only. This program never pulls images or starts an engine.

Required selection JSON: [{"package":"./internal/...","run":"^TestExact$",
"expected_tests":["TestExact","TestExact/required-case"]}]. Every observed test
must PASS; any SKIP, absent required test, malformed event, or nonzero exit fails.
Credentials env names receive /run/fixture/client/mysql.json, UUID env names receive the
independently socket-observed UUID. No fixture result is production acceptance.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import uuid


OWNER_LABEL = "io.clawmanager.b-local-mysql-fixture"
PIPE = "npipe:////./pipe/dockerDesktopLinuxEngine"
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
GO_IMAGE = "sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039"
MYSQL_IMAGE = "sha256:2952e3be7807f06fc18de50b3ea1a632d5c70d63482ff7d7376fe3aa8999babf"
ENV = re.compile(r"(?:TEST_[A-Z0-9_]+|[AD]_PERMIT_[A-Z0-9_]+)\Z")
PREPARE_PKI = """set -eu
mysqld --version
chown root:mysql /server
chmod 750 /server
cp /input/ca.pem /input/server.pem /input/server-key.pem /input/password /input/client.cnf /server/
chown mysql:mysql /server/server-key.pem /server/ca.pem /server/server.pem
chmod 600 /server/server-key.pem /server/ca.pem /server/server.pem
chmod 400 /server/password /server/client.cnf
"""
PREPARE_CLIENT = """set -eu
chown root:root /client
chmod 700 /client
cp /input/ca.pem /input/mysql.json /client/
chown root:root /client/ca.pem /client/mysql.json
chmod 600 /client/ca.pem /client/mysql.json
"""
PREPARE_WORK = "mkdir -p /work/cache /work/tmp /work/home"


class FixtureError(Exception):
    pass


def local_path(value, directory=False):
    path = Path(value)
    if (not path.is_absolute() or str(path).startswith("\\\\")
            or any(c in str(path) for c in ",\r\n\x00")):
        raise FixtureError("invalid_local_path")
    for item in (path, *path.parents):
        if item.exists():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise FixtureError("reparse_path_refused")
    if not (path.is_dir() if directory else path.is_file()):
        raise FixtureError("missing_local_input")
    return path.resolve()


def private_dir(path):
    path.mkdir(mode=0o700)
    system = Path(os.environ["SystemRoot"]) / "System32"
    who = subprocess.run([str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                         capture_output=True, check=True, timeout=15)
    # Only the numeric SID is consumed; account names may use an OEM code page.
    rows = list(csv.reader(who.stdout.decode("ascii", errors="replace").splitlines()))
    if len(rows) != 1 or not re.fullmatch(r"S-1-[0-9-]+", rows[0][-1]):
        raise FixtureError("local_sid_unavailable")
    result = subprocess.run([str(system / "icacls.exe"), str(path), "/inheritance:r",
                             "/grant:r", "*" + rows[0][-1] + ":(OI)(CI)F", "/q"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode:
        raise FixtureError("private_acl_failed")


def load_selections(path):
    raw = path.read_bytes()
    if not 1 <= len(raw) <= 65536:
        raise FixtureError("selection_size")
    values = json.loads(raw)
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise FixtureError("selection_list")
    for item in values:
        if (not isinstance(item, dict)
                or set(item) not in ({"package", "run", "expected_tests"},
                                     {"package", "run", "expected_tests", "timeout_seconds"})):
            raise FixtureError("selection_fields")
        if (not isinstance(item["package"], str)
                or not re.fullmatch(r"\./(?:internal|cmd)/[a-zA-Z0-9_/-]+", item["package"])
                or ".." in item["package"] or not isinstance(item["run"], str)
                or not 1 <= len(item["run"]) <= 4096):
            raise FixtureError("selection_package_or_regex")
        tests = item["expected_tests"]
        if (not isinstance(tests, list) or not tests or len(tests) != len(set(tests))
                or any(not isinstance(t, str) or not t.startswith("Test") or len(t) > 1024
                       or any(ord(c) < 32 for c in t) for t in tests)):
            raise FixtureError("selection_expected_tests")
        if "timeout_seconds" in item and (type(item["timeout_seconds"]) is not int
                                          or not 30 <= item["timeout_seconds"] <= 3600):
            raise FixtureError("selection_timeout")
    return values, hashlib.sha256(raw).hexdigest()


def audit_go_json(path, selection, package, exit_code):
    started, passed, package_pass = set(), set(), False
    for line in path.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise FixtureError("malformed_go_json_event")
        if event.get("Action") == "build-fail":
            raise FixtureError("go_build_failure")
        if event.get("Action") == "build-output" and isinstance(event.get("ImportPath"), str):
            continue
        if event.get("Package") != package:
            raise FixtureError("unexpected_go_json_package")
        action, test = event.get("Action"), event.get("Test")
        if action in ("skip", "fail"):
            raise FixtureError("go_skip_or_failure")
        if action not in ("start", "run", "pause", "cont", "pass", "output"):
            raise FixtureError("unexpected_go_json_action")
        if action == "run" and test:
            if test in started:
                raise FixtureError("duplicate_go_test_start")
            started.add(test)
        if action == "pass":
            if test:
                if test not in started or test in passed:
                    raise FixtureError("unexpected_go_test_pass")
                passed.add(test)
            else:
                if package_pass:
                    raise FixtureError("duplicate_go_package_pass")
                package_pass = True
    if (exit_code or not package_pass or not started or started != passed
            or not set(selection["expected_tests"]).issubset(passed)):
        raise FixtureError("go_exit_missing_or_incomplete_tests")
    return {"package": package, "passed_tests": sorted(passed),
            "json_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


class Fixture:
    def __init__(self, args, evidence, private, owner):
        self.args, self.evidence, self.private, self.owner = args, evidence, private, owner
        self.containers, self.volumes = [], []
        self.counter = 0
        self.execution_deadline = time.monotonic() + args.total_timeout_seconds
        self.cleanup_deadline = None

    def invoke(self, argv, stage, timeout=60, stdout=None):
        remaining = (self.cleanup_deadline or self.execution_deadline) - time.monotonic()
        if remaining <= 0:
            raise FixtureError("cleanup_deadline" if self.cleanup_deadline else "fixture_total_deadline")
        timeout = min(timeout, remaining)
        self.counter += 1
        error_log = self.evidence / (str(self.counter) + "-" + stage + ".stderr")
        try:
            error_output = error_log.open("xb")
        except OSError:
            if self.cleanup_deadline is None:
                raise
            # Disk/log failures cannot disable removal of verified owned assets.
            error_output = open(os.devnull, "wb")
        with error_output as err:
            try:
                result = subprocess.run(argv, stdout=stdout or subprocess.PIPE, stderr=err,
                                        timeout=timeout, check=False)
            except (OSError, subprocess.SubprocessError):
                raise FixtureError(stage + "_execution") from None
        return result

    def check_context(self):
        result = self.invoke([str(self.args.docker), "context", "inspect", "desktop-linux"],
                             "context", 20)
        if result.returncode:
            raise FixtureError("desktop_linux_not_available")
        context = json.loads(result.stdout)
        if (len(context) != 1 or context[0].get("Name") != "desktop-linux"
                or context[0].get("Endpoints", {}).get("docker", {}).get("Host", "").lower() != PIPE.lower()):
            raise FixtureError("nonlocal_docker_endpoint_refused")

    def docker(self, args, stage, timeout=60, stdout=None, required=True):
        self.check_context()
        result = self.invoke([str(self.args.docker), "--context", "desktop-linux", *args],
                             stage, timeout, stdout)
        if required and result.returncode:
            raise FixtureError(stage)
        return result

    def inspect_owned(self, name, volume=False):
        result = self.docker(["volume" if volume else "container", "inspect", name],
                             "inspect_owned", required=False)
        if result.returncode:
            # A failing inspect is not absence. Confirm through a successful
            # local inventory read; engine/permission failures remain failures.
            if volume:
                listed = self.docker(["volume", "ls", "--quiet", "--filter", "name=" + name], "confirm_volume_absence")
                if name in listed.stdout.decode().splitlines():
                    raise FixtureError("owned_volume_inspect_failed")
            else:
                full_id = bool(re.fullmatch(r"[0-9a-f]{64}", name))
                listed = self.docker(["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}} {{.Names}}",
                                      "--filter", ("id=" if full_id else "name=") + name], "confirm_container_absence")
                for line in listed.stdout.decode().splitlines():
                    fields = line.split()
                    if fields and ((full_id and fields[0] == name) or (not full_id and len(fields) == 2 and fields[1] == name)):
                        raise FixtureError("owned_container_inspect_failed")
            return None
        rows = json.loads(result.stdout)
        if len(rows) != 1:
            raise FixtureError("ambiguous_owned_asset")
        item = rows[0]
        labels = item.get("Labels", {}) if volume else item.get("Config", {}).get("Labels", {})
        if labels.get(OWNER_LABEL) != self.owner:
            raise FixtureError("ownership_label_mismatch")
        if volume:
            if item.get("Name") != name or item.get("Driver") != "local":
                raise FixtureError("volume_identity_mismatch")
        elif not re.fullmatch(r"[0-9a-f]{64}", item.get("Id", "")):
            raise FixtureError("container_identity_mismatch")
        return item

    def volume(self, suffix):
        name = self.owner + "-" + suffix
        self.volumes.append(name)  # Also reconcile an uncertain create result.
        self.docker(["volume", "create", "--driver", "local", "--label",
                     OWNER_LABEL + "=" + self.owner, name], "create_volume")
        if not self.inspect_owned(name, True):
            raise FixtureError("created_volume_missing")
        return name

    def create(self, suffix, image, options, command):
        name = self.owner + "-" + suffix
        entry = {"name": name, "id": None}
        self.containers.append(entry)
        self.docker(["create", "--pull=never", "--name", name, "--label",
                     OWNER_LABEL + "=" + self.owner, *options, image, *command], "create_container")
        actual = self.inspect_owned(name)
        if actual is None or actual.get("Image") != image:
            raise FixtureError("created_container_image_mismatch")
        entry["id"] = actual["Id"]
        return actual["Id"]

    def attached(self, container, stdout=None, timeout=180):
        result = self.docker(["start", "--attach", container], "attached", timeout, stdout,
                             required=False)
        actual = self.inspect_owned(container)
        if actual is None or actual.get("State", {}).get("Running"):
            raise FixtureError("attached_container_not_terminal")
        code = actual["State"].get("ExitCode")
        if result.returncode and code == 0:
            raise FixtureError("docker_attach_failed")
        return code, result.stdout

    def verify_image(self, image, mysql=False):
        result = self.docker(["image", "inspect", image], "image_inspect")
        objects = json.loads(result.stdout)
        if (len(objects) != 1 or objects[0].get("Id") != image
                or objects[0].get("Os") != "linux" or objects[0].get("Architecture") != "amd64"):
            raise FixtureError("image_identity_platform")

    def cleanup(self):
        # Cleanup has its own finite budget even after test timeout/cancellation.
        self.cleanup_deadline = time.monotonic() + 180
        failures = []
        for entry in reversed(self.containers):
            try:
                actual = self.inspect_owned(entry["id"] or entry["name"])
                if actual is None:
                    continue
                if entry["id"] and actual["Id"] != entry["id"]:
                    raise FixtureError("container_replaced")
                if entry["name"].endswith("-mysql"):
                    try:
                        with (self.evidence / "mysql.log").open("xb") as output:
                            logged = self.docker(["logs", "--timestamps", actual["Id"]], "mysql_logs",
                                                 timeout=15, stdout=output, required=False)
                        if logged.returncode:
                            failures.append("mysql_log_capture")
                    except Exception:
                        # Evidence failure must not leave the owned server running.
                        failures.append("mysql_log_capture")
                self.docker(["container", "rm", "--force", actual["Id"]], "cleanup_container")
                if self.inspect_owned(actual["Id"]) is not None:
                    raise FixtureError("container_remained")
            except Exception:
                failures.append("container_cleanup")
        for name in reversed(self.volumes):
            try:
                if self.inspect_owned(name, True) is not None:
                    self.docker(["volume", "rm", name], "cleanup_volume")
                    if self.inspect_owned(name, True) is not None:
                        raise FixtureError("volume_remained")
            except Exception:
                failures.append("volume_cleanup")
        return failures


def bind(source, target):
    return "type=bind,source=" + str(source) + ",target=" + target + ",readonly"


def volume_mount(source, target, readonly=False):
    return "type=volume,source=" + source + ",target=" + target + (",readonly" if readonly else "")


def make_pki(fixture):
    directory = fixture.private / "mysql"
    directory.mkdir()
    openssl = str(fixture.args.openssl)
    def run(args):
        if fixture.invoke([openssl, *args], "openssl", 90).returncode:
            raise FixtureError("openssl")
    run(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "2",
         "-subj", "/CN=" + fixture.owner, "-keyout", str(fixture.private / "ca-key.pem"),
         "-out", str(directory / "ca.pem")])
    run(["req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256", "-subj", "/CN=localhost",
         "-keyout", str(directory / "server-key.pem"), "-out", str(fixture.private / "server.csr")])
    extension = fixture.private / "server.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="ascii")
    run(["x509", "-req", "-sha256", "-days", "2", "-in", str(fixture.private / "server.csr"),
         "-CA", str(directory / "ca.pem"), "-CAkey", str(fixture.private / "ca-key.pem"),
         "-CAcreateserial", "-extfile", str(extension), "-out", str(directory / "server.pem")])
    password = secrets.token_hex(32)
    (directory / "password").write_text(password, encoding="ascii")
    (directory / "client.cnf").write_text("[client]\nuser=root\npassword=" + password + "\n", encoding="ascii")
    return directory, password


def start_mysql(fixture, pki, data_volume, pki_volume):
    helper = fixture.create("prepare-pki", fixture.args.mysql_image,
                            ["--network", "none", "--entrypoint", "/bin/sh", "--user", "0",
                             "--mount", bind(pki, "/input"), "--mount", volume_mount(pki_volume, "/server")],
                            ["-c", PREPARE_PKI])
    code, version = fixture.attached(helper)
    if code or not re.search(rb"\bVer 8\.4\.8\b", version):
        raise FixtureError("pki_volume_prepare")
    mysql = fixture.create("mysql", fixture.args.mysql_image,
                           ["--network", "none", "--memory", "2g", "--cpus", "2",
                            "--mount", volume_mount(data_volume, "/var/lib/mysql"),
                            "--mount", volume_mount(pki_volume, "/run/fixture/server", True),
                            "--env", "MYSQL_ROOT_PASSWORD_FILE=/run/fixture/server/password",
                            "--env", "MYSQL_ROOT_HOST=127.0.0.1"],
                           ["--port=13306", "--bind-address=127.0.0.1", "--mysqlx=OFF", "--skip-name-resolve",
                            "--innodb-use-native-aio=OFF", "--require-secure-transport=ON",
                            "--tls-version=TLSv1.3", "--ssl-ca=/run/fixture/server/ca.pem",
                            "--ssl-cert=/run/fixture/server/server.pem", "--ssl-key=/run/fixture/server/server-key.pem"])
    fixture.docker(["start", mysql], "mysql_start")
    query = "SELECT @@server_uuid,@@version,@@port,@@require_secure_transport,@@tls_version"
    until = time.monotonic() + 180
    result = None
    while time.monotonic() < until:
        result = fixture.docker(["exec", "--user", "0", mysql, "mysql",
                                 "--defaults-extra-file=/run/fixture/server/client.cnf", "--protocol=SOCKET",
                                 "--batch", "--skip-column-names", "--execute=" + query],
                                "mysql_ready", 15, required=False)
        if result.returncode == 0:
            break
        time.sleep(1)
    if result is None or result.returncode:
        raise FixtureError("mysql_readiness_deadline")
    fields = result.stdout.decode("ascii").strip().split("\t")
    if (len(fields) != 5 or not re.fullmatch(r"[0-9a-f-]{36}", fields[0])
            or fields[1] != "8.4.8" or fields[2:] != ["13306", "1", "TLSv1.3"]):
        raise FixtureError("mysql_socket_identity_or_policy")
    server_uuid = str(uuid.UUID(fields[0]))
    tls = fixture.docker(["exec", "--user", "0", mysql, "mysql",
                          "--defaults-extra-file=/run/fixture/server/client.cnf", "--protocol=TCP",
                          "--host=127.0.0.1", "--port=13306", "--ssl-mode=VERIFY_IDENTITY",
                          "--ssl-ca=/run/fixture/server/ca.pem", "--tls-version=TLSv1.3", "--batch",
                          "--skip-column-names", "--execute=SELECT @@server_uuid; SHOW SESSION STATUS LIKE 'Ssl_version'"],
                         "mysql_san_tls")
    if tls.stdout.decode("ascii").strip().splitlines() != [server_uuid, "Ssl_version\tTLSv1.3"]:
        raise FixtureError("mysql_verified_tls13")
    return mysql, server_uuid


def clean_private(directory, evidence, owner):
    if directory.parent != evidence or directory.name != "secrets":
        raise FixtureError("secret_cleanup_scope")
    if (evidence / ".owner").read_text(encoding="ascii") != owner:
        raise FixtureError("secret_cleanup_owner")
    for parent, dirs, files in os.walk(directory, followlinks=False):
        for name in [Path(parent), *(Path(parent) / n for n in dirs + files)]:
            value = name.lstat()
            if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
                raise FixtureError("secret_cleanup_reparse")
    shutil.rmtree(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("docker", "openssl", "source", "module-cache", "evidence-root", "selection-json", "mysql-image", "go-image"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--context", choices=["desktop-linux"], default="desktop-linux")
    parser.add_argument("--credentials-env", action="append", required=True)
    parser.add_argument("--uuid-env", action="append", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--total-timeout-seconds", type=int, default=1800)
    parser.add_argument("--go-cache-dir", help="optional supervisor-owned source.parent/linux-cache; never removed here")
    args = parser.parse_args()
    fixture, evidence, private = None, None, None
    result = {"schema_version": "b-local-mysql-fixture.v1", "status": "FAILED",
              "scope": "LOCAL_FIXTURE_DATA_ONLY", "production_accepted": False, "tests": []}
    owner = "b-mysql-" + uuid.uuid4().hex
    try:
        if os.name != "nt" or any(os.environ.get(k) for k in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")) or os.environ.get("DOCKER_CONTEXT", "desktop-linux") != "desktop-linux":
            raise FixtureError("local_windows_docker_context_required")
        if args.mysql_image != MYSQL_IMAGE or args.go_image != GO_IMAGE:
            raise FixtureError("immutable_local_image_ids_required")
        names = args.credentials_env + args.uuid_env
        if (len(names) != len(set(names)) or any(not ENV.fullmatch(n) for n in names)
                or not 30 <= args.timeout_seconds <= 3600
                or not 120 <= args.total_timeout_seconds <= 7200):
            raise FixtureError("test_environment_or_timeout")
        args.docker, args.openssl = local_path(args.docker), local_path(args.openssl)
        args.source, args.module_cache = local_path(args.source, True), local_path(args.module_cache, True)
        if args.go_cache_dir:
            args.go_cache_dir = local_path(args.go_cache_dir, True)
            if (args.go_cache_dir != args.source.parent / "linux-cache"
                    or (args.source.parent / ".owner").read_text(encoding="ascii").strip() not in {
                        "supervisor-sequence-sql-review-20261103",
                        "supervisor-signing-resource-review-20261103",
                    }):
                raise FixtureError("supervisor_cache_owner_or_path")
        selection_file = local_path(args.selection_json)
        root = local_path(args.evidence_root, True)
        selections, result["selection_sha256"] = load_selections(selection_file)
        module = (args.source / "backend" / "go.mod").read_text(encoding="utf-8")
        matches = re.findall(r"^module\s+(\S+)\s*$", module, re.MULTILINE)
        if len(matches) != 1:
            raise FixtureError("source_module")
        evidence = root / owner
        private_dir(evidence)
        (evidence / ".owner").write_text(owner, encoding="ascii")
        private = evidence / "secrets"
        private_dir(private)
        fixture = Fixture(args, evidence, private, owner)
        info = fixture.docker(["info", "--format", "{{json .}}"], "engine_info", 20)
        if json.loads(info.stdout).get("OSType") != "linux":
            raise FixtureError("already_running_linux_engine_required")
        fixture.verify_image(args.mysql_image, True)
        fixture.verify_image(args.go_image)
        pki, password = make_pki(fixture)
        data, pki_volume, work = fixture.volume("data"), fixture.volume("server-pki"), fixture.volume("work")
        client_volume = fixture.volume("client-pki")
        mysql, server_uuid = start_mysql(fixture, pki, data, pki_volume)
        runner = private / "runner"
        runner.mkdir()
        shutil.copyfile(pki / "ca.pem", runner / "ca.pem")
        credentials = {"Host": "127.0.0.1", "Port": 13306, "User": "root", "Password": password,
                       "CAFile": "/run/fixture/client/ca.pem", "TLSServerName": "localhost", "ServerUUID": server_uuid}
        (runner / "mysql.json").write_text(json.dumps(credentials), encoding="utf-8")
        del password
        prepare_client = fixture.create("prepare-client", args.mysql_image,
                                        ["--network", "none", "--entrypoint", "/bin/sh", "--user", "0",
                                         "--mount", bind(runner, "/input"),
                                         "--mount", volume_mount(client_volume, "/client")],
                                        ["-c", PREPARE_CLIENT])
        if fixture.attached(prepare_client)[0]:
            raise FixtureError("client_volume_private_permissions")
        options = ["--network", "container:" + mysql, "--memory", "4g", "--cpus", "2",
                   "--mount", bind(args.source, "/source"), "--mount", bind(args.module_cache, "/gomodcache"),
                   "--mount", volume_mount(client_volume, "/run/fixture/client", True), "--mount", volume_mount(work, "/work"),
                   "--workdir", "/source/backend"]
        for key, value in {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOTELEMETRY": "off",
                           "GOCACHE": "/review-cache" if args.go_cache_dir else "/work/cache", "GOTMPDIR": "/work/tmp", "GOMODCACHE": "/gomodcache",
                           "HOME": "/work/home", "TMPDIR": "/work/tmp", "CGO_ENABLED": "0", "GOMAXPROCS": "2", "GOMEMLIMIT": "2GiB"}.items():
            options += ["--env", key + "=" + value]
        for name in args.credentials_env:
            options += ["--env", name + "=/run/fixture/client/mysql.json"]
        for name in args.uuid_env:
            options += ["--env", name + "=" + server_uuid]
        if args.go_cache_dir:
            options += ["--mount", "type=bind,source=" + str(args.go_cache_dir) + ",target=/review-cache"]
        prepare = fixture.create("prepare-work", args.go_image, [*options, "--entrypoint", "/bin/sh"], ["-c", PREPARE_WORK])
        if fixture.attached(prepare)[0]:
            raise FixtureError("work_volume_prepare")
        version = fixture.create("go-version", args.go_image, [*options, "--entrypoint", "go"], ["version"])
        code, raw = fixture.attached(version)
        if code or raw.decode().strip() != "go version go1.26.1 linux/amd64":
            raise FixtureError("go_image_toolchain_identity")
        for index, selection in enumerate(selections):
            test_timeout = selection.get("timeout_seconds", args.timeout_seconds)
            container = fixture.create("test-" + str(index), args.go_image, [*options, "--entrypoint", "go"],
                                       ["test", "-json", "-mod=readonly", "-count=1", "-p", "1", "-tags", "systembackup_mysql",
                                        "-timeout=" + str(test_timeout) + "s", selection["package"], "-run", selection["run"]])
            log = evidence / ("go-" + str(index) + ".jsonl")
            with log.open("xb") as output:
                code, _ = fixture.attached(container, output, test_timeout + 120)
            package = matches[0] + "/" + selection["package"][2:]
            result["tests"].append(audit_go_json(log, selection, package, code))
        result.update(status="PASSED_LOCAL_FIXTURE", server_uuid=server_uuid, mysql_image=args.mysql_image,
                      go_image=args.go_image, san_verified=True, tls="TLSv1.3", host_ports_published=False,
                      supervisor_cache_preserved=bool(args.go_cache_dir))
    except Exception as error:
        result["failure_stage"] = str(error) if isinstance(error, FixtureError) else type(error).__name__
    finally:
        failures = fixture.cleanup() if fixture else []
        if private is not None and private.exists():
            try:
                clean_private(private, evidence, owner)
            except Exception:
                failures.append("private_directory_cleanup")
        result["cleanup_failures"] = failures
        result["owned_test_assets_removed"] = not failures
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        if failures:
            result["status"] = "FAILED"
        if evidence is not None and evidence.exists():
            (evidence / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            result["private_evidence_directory"] = str(evidence)
        print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASSED_LOCAL_FIXTURE" else 1


if __name__ == "__main__":
    sys.exit(main())
