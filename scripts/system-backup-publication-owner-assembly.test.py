#!/usr/bin/env python3
"""Root-run data projection models; no real grant/capability or native I/O."""
import copy
import importlib.util
from pathlib import Path
import types
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location("owner_assembly", Path(__file__).with_name("system-backup-publication-owner-assembly.py"))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


class SourceJoinTests(unittest.TestCase):
    def setUp(self):
        self.m = types.SimpleNamespace(need=need)
        self.owner = {"Version": "original-publication-runtime-owner-inputs.v1", "SigningPin": {"InstallationID": "model-installation", "Issuer": "original-public-issuer"},
                      "SigningRecord": {"RecordFile": "original-record", "SignatureFile": "original-signature"},
                      "PublisherGrant": {"File": "actual-owner-output-location", "SHA256": "original-native-output-pin", "Issuer": "original-public-issuer"},
                      "SigningMounts": [{"binding": {"Purpose": purpose}, "jwt_file": purpose + ".jwt", "ca_file": "original-ca.pem"} for purpose in ("acceptance_record", "capture_certificate", "catalog_record")]}
        self.mapping = {"Binding": {"InstallationID": "model-installation"}, "Source": {"RecordID": "original-mapping"}}
        self.pins = {"MappingSource": {"RecordID": "original-mapping"}, "MappingIssuer": "actual-original-mapping-issuer", "Generate": {"Source": "actual-generate-source", "Issuer": "original-permission-issuer"}, "Unwrap": {"Source": "actual-unwrap-source", "Issuer": "original-permission-issuer"}}

    def test_every_business_grant_and_signing_mount_is_from_native_output(self):
        actual = s.assemble_sources(self.m, self.owner, self.mapping, self.pins, "new-bound-token-file", "original-ca-file", "original-pod")
        self.assertIs(actual["VerifierGrant"], self.owner["PublisherGrant"])
        self.assertIs(actual["SigningPin"], self.owner["SigningPin"])
        self.assertIs(actual["GenerateCapability"], self.pins["Generate"])
        self.assertIs(actual["UnwrapCapability"], self.pins["Unwrap"])
        self.assertEqual([x["JWTFile"] for x in actual["SigningFiles"]], [x["jwt_file"] for x in self.owner["SigningMounts"]])
        self.assertNotIn("Passed", actual)
        self.assertNotIn("SQLOwner", actual)

    def test_foreign_installation_or_replaced_mapping_source_refused(self):
        changed = copy.deepcopy(self.mapping)
        changed["Binding"]["InstallationID"] = "another-installation"
        with self.assertRaises(Refused):
            s.assemble_sources(self.m, self.owner, changed, self.pins, "jwt", "ca", "pod")
        changed = copy.deepcopy(self.mapping)
        changed["Source"]["RecordID"] = "other-mapping"
        with self.assertRaises(Refused):
            s.assemble_sources(self.m, self.owner, changed, self.pins, "jwt", "ca", "pod")

    def test_cross_purpose_mount_replacement_refused(self):
        changed = copy.deepcopy(self.owner)
        changed["SigningMounts"][1] = changed["SigningMounts"][0]
        with self.assertRaises(Refused):
            s.assemble_sources(self.m, changed, self.mapping, self.pins, "jwt", "ca", "pod")

    def test_wrong_pod_role_cannot_even_request_a_new_token(self):
        stage = types.SimpleNamespace(check_host=Mock(), call=Mock())
        host = {"PodUID": "current-pod", "ServiceAccount": "controller", "ServiceAccountUID": "current-sa"}
        role = {"Namespace": "clawmanager-zhanghui08-system", "PodUID": "retired-pod", "ServiceAccountName": "controller", "ServiceAccountUID": "current-sa", "Audience": "actual-provider-role-audience"}
        with self.assertRaises(Refused):
            s.token_request(self.m, stage, role, host)
        stage.call.assert_not_called()
        stage.check_host.assert_not_called()

    def test_wrong_service_account_role_refused(self):
        host = {"PodUID": "current-pod", "ServiceAccount": "controller", "ServiceAccountUID": "current-sa"}
        role = {"Namespace": "clawmanager-zhanghui08-system", "PodUID": "current-pod", "ServiceAccountName": "controller", "ServiceAccountUID": "other-sa", "Audience": "actual-provider-role-audience"}
        with self.assertRaises(Refused):
            s.check_publisher_role(self.m, role, host)


if __name__ == "__main__":
    unittest.main()
