"""Owned disposable storage for the data pipeline check; no deployment access."""
from contextlib import contextmanager
import json
import os
import secrets
import subprocess
import time
import urllib.request
import uuid


def docker(args, env=None):
    return subprocess.check_output(["docker", *args], env=env, stderr=subprocess.PIPE).decode().strip()


@contextmanager
def disposable_storage():
    run = uuid.uuid4().hex
    owned = []
    receipt = {"run": run, "created": [], "removed": [], "cleanup_failed": []}
    env = os.environ.copy()
    env["MINIO_ROOT_USER"] = "local_integration"
    env["MINIO_ROOT_PASSWORD"] = secrets.token_hex(24)

    def start(role, image, container_port, command, extra=()):
        # No pull here: use an already reviewed local image, never silently
        # upgrade the fixture to a moving registry tag.
        docker(["image", "inspect", image])
        identifier = docker(["run", "-d", "--pull=never", "--name", f"cm-backup-check-{run[:12]}-{role}",
                             "--label", "codex.task=backup-team-integration", "--label", f"codex.run={run}",
                             "-p", f"127.0.0.1::{container_port}", *extra, image, *command], env)
        owned.append(identifier)
        item = json.loads(docker(["inspect", identifier]))[0]
        published = item["NetworkSettings"]["Ports"][f"{container_port}/tcp"]
        if len(published) != 1 or published[0]["HostIp"] != "127.0.0.1":
            raise ValueError("fixture storage was not isolated to loopback")
        receipt["created"].append({"role": role, "id": identifier, "image_id": item["Image"]})
        return published[0]["HostPort"]

    try:
        source = start("redis-source", "redis:7-alpine", 6379,
                       ["redis-server", "--save", "", "--appendonly", "no"], ["--tmpfs", "/data:rw,size=128m"])
        target = start("redis-target", "redis:7-alpine", 6379,
                       ["redis-server", "--save", "", "--appendonly", "no"], ["--tmpfs", "/data:rw,size=128m"])
        objects = start("objects", "10.130.14.23:5000/minio:2026.6.5", 9000,
                        ["server", "/data"], ["--tmpfs", "/data:rw,size=512m", "-e", "MINIO_ROOT_USER", "-e", "MINIO_ROOT_PASSWORD"])
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{objects}/minio/health/ready", timeout=1) as response:
                    if response.status == 200:
                        break
            except (OSError, TimeoutError):
                time.sleep(0.25)
        else:
            raise ValueError("local object storage did not become ready")
        yield {
            "TEST_SYSTEM_BACKUP_REDIS_PORT": source,
            "TEST_SYSTEM_BACKUP_REDIS_TARGET_PORT": target,
            "TEST_SYSTEM_BACKUP_MINIO_PORT": objects,
            "TEST_SYSTEM_BACKUP_MINIO_USER": env["MINIO_ROOT_USER"],
            "TEST_SYSTEM_BACKUP_MINIO_PASSWORD": env["MINIO_ROOT_PASSWORD"],
            "TEST_SYSTEM_TEAM_DATA_MODE": "1",
        }, receipt
    finally:
        for identifier in reversed(owned):
            try:
                item = json.loads(docker(["inspect", identifier]))[0]
                labels = item["Config"].get("Labels", {})
                if item["Id"] != identifier or labels.get("codex.run") != run or labels.get("codex.task") != "backup-team-integration":
                    raise ValueError("container ownership changed")
                docker(["rm", "-f", identifier])
                receipt["removed"].append(identifier)
            except (ValueError, KeyError, subprocess.CalledProcessError):
                receipt["cleanup_failed"].append(identifier)
        env.pop("MINIO_ROOT_PASSWORD", None)
