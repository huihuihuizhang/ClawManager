#!/usr/bin/env python3
"""Enable through normal HTTPS strong-auth and config mutation APIs, once.

Business request is derived from live config, changing only enabled. The server
issues the proof using the existing password/TOTP flow. No handwritten grant,
SQL update, retry, authority issuance or source-facts refresh is implemented.
"""
import argparse
import base64
import copy
import decimal
import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("readback", Path(__file__).with_name("system-backup-d-enable-readback.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
PROOF = "/api/v1/admin/system-backup-strong-auth/proof"


def request_digest(installation, actor_id, request):
    """Comparison codec for the bounded ConfigValues profile, not admission.

    Config numbers are safe integers except source_size_safety_factor (1..2,
    hundredths). This deliberately rejects general JSON floating-point input.
    The exact A-reviewed hash vectors are used by the client regression suite.
    """
    r.require(re.fullmatch(r"[1-9][0-9]*", actor_id), "actor_binding_invalid")
    def normalize(value, key=""):
        if isinstance(value, dict):
            r.require(all(isinstance(k, str) and k.isascii() for k in value), "hash_keys_outside_config_profile")
            return {k: normalize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [normalize(v) for v in value]
        if type(value) is int:
            r.require(abs(value) <= 9007199254740991, "hash_number_outside_config_profile")
        if type(value) is float:
            number = decimal.Decimal(str(value))
            r.require(number.is_finite(), "hash_number_outside_config_profile")
            if number == number.to_integral_value():
                return normalize(int(number), key)
            r.require(key == "source_size_safety_factor" and 1 <= number <= 2 and
                      number * 100 == (number * 100).to_integral_value(), "hash_number_outside_config_profile")
        r.require(value is None or type(value) in (str, bool, int, float), "hash_value_outside_config_profile")
        return value
    document = {"domain": "clawmanager.system-backup.config-mutation.v1", "origin_installation_id": installation,
        "actor_type": "admin", "actor_id": actor_id, "endpoint": "updateSystemBackupConfig", "method": "PUT",
        "request": normalize(request)}
    return r.sha(r.canonical(document))


def proof_binding(proof, installation, key, request, token):
    r.require(proof.get("header_name") == "X-Strong-Auth-Proof" and
              isinstance(proof.get("header_value"), str) and len(proof["header_value"]) <= 65536,
              "normal_strong_auth_proof_unavailable")
    document = r.decode(base64.b64decode(proof["header_value"], validate=True))
    r.require(isinstance(document, dict) and isinstance(document.get("payload"), dict), "server_proof_shape_invalid")
    payload = document["payload"]
    subject = payload.get("subject", "")
    r.require(document.get("schema_version") == "system-backup-strong-auth-proof.v1" and
              re.fullmatch(r"user:[1-9][0-9]*", subject) and payload.get("session") == r.sha(token.encode()) and
              payload.get("endpoint") == "updateSystemBackupConfig" and payload.get("idempotency_key") == key,
              "server_proof_binding_mismatch")
    digest = request_digest(installation, subject[5:], request)
    r.require(payload.get("request_hash") == digest, "server_proof_request_hash_mismatch")
    # Only public comparison fields survive. No proof/signature/nonce/session.
    return {"actor_id": subject[5:], "request_hash": digest, "request_bytes_sha256": r.sha(r.canonical(request)),
            "idempotency_key": key, "installation": installation}


def save_bytes(directory, name, raw):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # Persist directory entries too, before any remote mutation on Linux.
    if os.name != "nt":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def save(directory, name, value):
    save_bytes(directory, name, r.canonical(value))


def sync_parent(directory):
    if os.name != "nt":
        fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class API(r.API):
    def send(self, path, method, value, headers=None):
        r.require((path, method) in ((PROOF, "POST"), (r.CONFIG, "PUT")), "mutation_scope_invalid")
        self.config_operation_response_raw = None
        fields = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json", "Accept": "application/json"}
        fields.update(headers or {})
        req = urllib.request.Request(self.origin + path, data=r.canonical(value), headers=fields, method=method)
        try:
            response = self.opener.open(req, timeout=100)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            r.require(response.headers.get_content_type() == "application/json", "api_json_required")
            raw = response.read(r.MAX + 1)
            body = r.decode(raw)
            if (path, method, response.code) == (r.CONFIG, "PUT", 200):
                self.config_operation_response_raw = raw
            r.require(isinstance(body, dict), "api_object_required")
            return response.code, response.headers, body

    def operation_bytes(self, operation_id):
        r.require(re.fullmatch(r"sop_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", operation_id), "original_operation_id_invalid")
        path = "/api/v1/admin/system-backup-operations/" + operation_id
        req = urllib.request.Request(self.origin + path, headers={"Authorization": "Bearer " + self.token,
            "Accept": "application/json"}, method="GET")
        try:
            response = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            r.require(response.code == 200 and response.headers.get_content_type() == "application/json" and
                      response.headers.get("X-System-Backup-Data-Source") == "live", "original_operation_http_bytes_not_live")
            raw = response.read(8193)
            r.require(1 < len(raw) <= 8192, "original_operation_http_bytes_size_invalid")
            body = r.decode(raw)
            r.require(isinstance(body, dict) and body.get("public_id") == operation_id, "original_operation_http_bytes_identity_invalid")
            return raw, body


def enable(api, installation, directory, check_identity, prompt=getpass.getpass, *, verify_readiness=True):
    # Directory is create-only; reusing it must never issue a second PUT.
    r.require(directory.is_absolute(), "absolute_journal_directory_required")
    directory.mkdir(mode=0o700)
    sync_parent(directory)
    first = r.active_config(api, installation)
    r.require(first["config"]["enabled"] is False, "already_enabled_observe_original_operation")
    proposed = copy.deepcopy(first["config"])
    proposed["enabled"] = True
    request = {"expected_version": first["version"], "change_reason": "Enable after original owner installation and coverage adoption", "config": proposed}
    key = "d-enable-" + os.urandom(24).hex()
    save(directory, "request.json", {"installation": installation, "idempotency_key": key, "request": request})
    # This prompts for actual credentials; no OTP seed/private issuer key is read.
    password = prompt("Existing local admin password (hidden): ")
    code = prompt("Current enrolled TOTP code (hidden): ")
    r.require(password and re.fullmatch(r"[0-9]{6}", code), "strong_auth_input_invalid")
    status, _, proof = api.send(PROOF, "POST", {"password": password, "code": code,
        "endpoint": "updateSystemBackupConfig", "idempotency_key": key, "request": request})
    password = code = None
    r.require(status == 200, "normal_strong_auth_proof_unavailable")
    binding = proof_binding(proof, installation, key, request, api.token)
    save(directory, "request-binding.json", binding)
    check_identity()
    r.require(r.active_config(api, installation) == first, "config_changed_before_submission")
    # A durable attempt marker precedes PUT. Even a crash before sending is
    # treated conservatively; this program has no resend/resume action.
    save(directory, "submission-intent.json", {"state": "outcome_requires_original_operation_readback", "idempotency_key": key})
    status, _, operation = api.send(r.CONFIG, "PUT", request,
        {"Idempotency-Key": key, "X-Strong-Auth-Proof": proof["header_value"]})
    proof = None
    save(directory, "response.json", {"http_status": status, "code": operation.get("code"),
        "reason": operation.get("details", {}).get("reason") if isinstance(operation.get("details"), dict) else None,
        "operation": operation if status == 200 else None})
    r.require(status == 200, "enable_refused_or_unknown_keep_original_journal")
    raw_operation = getattr(api, "config_operation_response_raw", None)
    r.require(isinstance(raw_operation, bytes) and 1 < len(raw_operation) <= 8192 and
              r.decode(raw_operation) == operation, "original_operation_http_bytes_missing")
    # Preserve the actual server body for the original owner SQL/evidence
    # comparison. Do not reconstruct canonical bytes from this parsed object.
    save_bytes(directory, "operation-response.raw.json", raw_operation)
    r.require(operation.get("schema_version") == "system-backup-operation.v1" and
        operation.get("origin_installation_id") == installation and operation.get("target_public_id") == installation and
        operation.get("operation_type") == "config_update" and operation.get("endpoint") == "updateSystemBackupConfig" and
        operation.get("idempotency_key") == key and operation.get("status") == "succeeded" and
        operation.get("result_config_version") == first["version"] + 1 and
        operation.get("request_hash") == binding["request_hash"] and operation.get("actor_id") == binding["actor_id"] and
        re.fullmatch(r"sop_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", operation.get("public_id", "")), "operation_response_unconfirmed")
    path = "/api/v1/admin/system-backup-operations/" + operation["public_id"]
    status, headers, reread = api.request(path)
    r.require(status == 200 and headers.get("X-System-Backup-Data-Source") == "live" and
              reread == operation, "original_operation_readback_unconfirmed")
    current = r.active_config(api, installation)
    r.require(current["version"] == first["version"] + 1 and current["config"] == proposed,
              "enabled_config_readback_unconfirmed")
    check_identity()
    save(directory, "committed-readback.json", {"operation": operation, "config_version": current["version"],
         "enabled": True, "effective_enabled": current["effective_enabled"], "readiness_verified": False})
    if not verify_readiness:
        return {"status": "ENABLE_COMMIT_READBACK_VERIFIED_READINESS_PENDING",
                "operation_public_id": operation["public_id"], "config_version": current["version"],
                "readiness_verified": False, "browser_path_verified": False}
    # Failure here leaves the successful original operation intact; no rollback
    # or another enable is attempted just because readiness is unavailable.
    result = r.verify_api(api, installation, False)
    check_identity()
    save(directory, "readiness.json", result)
    return {"status": "ENABLED_AND_API_READBACK_VERIFIED", "operation_public_id": operation["public_id"],
            "config_version": current["version"], "browser_path_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("context", "namespace", "namespace-uid", "app-pod", "controller-pod", "origin", "ca-sha256", "installation", "receipt-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "receipt", "journal-directory"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = args.receipt.read_bytes()
        r.require(r.sha(raw) == args.receipt_sha256, "identity_receipt_pin_mismatch")
        receipt = r.decode(raw)
        r.require(receipt["schema_version"] == "d-field-pod-comparison.v1", "identity_receipt_schema_invalid")
        def check():
            r.require(r.identity(args) == receipt["identity"], "identity_changed_reissue_required")
        check()
        api = API(args.origin, args.ca_file, args.ca_sha256, getpass.getpass("Existing normal login bearer token (hidden): "))
        result = enable(api, args.installation, args.journal_directory, check)
        print(json.dumps(result, sort_keys=True))
        return 0
    except r.Refused as error:
        reason = str(error)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError, r.subprocess.SubprocessError, urllib.error.URLError):
        reason = "observation_or_submission_unconfirmed_keep_original_journal"
    print(json.dumps({"status": "STOP_RETAIN_ORIGINAL_JOURNAL", "reason": reason,
        "automatic_retry": False, "automatic_rollback": False}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
