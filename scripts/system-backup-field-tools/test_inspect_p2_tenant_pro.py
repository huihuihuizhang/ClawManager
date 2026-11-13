import copy
import importlib.util
import json
from pathlib import Path
import unittest
import urllib.request

spec = importlib.util.spec_from_file_location('tenant', Path(__file__).with_name('inspect-p2-tenant-pro.py'))
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)


class TenantDiagnosticTests(unittest.TestCase):
    def fixture(self):
        return {'spec': {'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'source-pvc'}}],
                        'containers': [{'name': 'runtime', 'env': [{'name': 'SECRET', 'value': 'private-value'}],
                                        'volumeMounts': [{'name': 'data', 'mountPath': '/data'}]}]}}

    def test_primary_workspace_and_output_privacy(self):
        report = T.mount_report(self.fixture(), '/data/workspace')
        self.assertEqual(report['Issues'], [])
        self.assertEqual(report['PrimaryMappingCount'], 1)
        self.assertNotIn('private-value', json.dumps(report))
        self.assertNotIn('/data/workspace', json.dumps(report))

    def test_side_mount_even_readonly_is_not_silently_ignored(self):
        pod = self.fixture()
        pod['spec']['volumes'].append({'name': 'team', 'persistentVolumeClaim': {'claimName': 'team-pvc'}})
        pod['spec']['containers'][0]['volumeMounts'].append({'name': 'team', 'mountPath': '/team', 'readOnly': True})
        report = T.mount_report(pod, '/data/workspace')
        self.assertIn('additional_persistent_mount', report['Issues'])
        self.assertEqual(len(report['Mounts']), 2)

    def test_init_container_mounts_are_checked(self):
        pod = self.fixture()
        pod['spec']['initContainers'] = [{'name': 'init', 'volumeMounts': [{'name': 'data', 'mountPath': '/outside'}]}]
        self.assertIn('additional_persistent_mount', T.mount_report(pod, '/data/workspace')['Issues'])

    def test_subpath_expr_and_escape_are_refused(self):
        for change in [{'subPathExpr': '$(UNRESOLVED)'}, {'subPath': '../escape'}, {'subPath': '/absolute'}, {'subPath': 'x/../y'}]:
            pod = self.fixture(); pod['spec']['containers'][0]['volumeMounts'][0].update(change)
            self.assertIn('tenant_primary_mount_mismatch', T.mount_report(pod, '/data/workspace')['Issues'])

    def test_valid_subpath_and_duplicate_claim_conflict(self):
        pod = self.fixture(); mount = pod['spec']['containers'][0]['volumeMounts'][0]
        mount['subPath'] = 'original'
        self.assertEqual(T.mount_report(pod, '/data/workspace')['Issues'], [])
        second = copy.deepcopy(pod['spec']['containers'][0]); second['name'] = 'second'
        second['volumeMounts'][0]['subPath'] = 'different'
        pod['spec']['containers'].append(second)
        self.assertIn('primary_claim_ambiguous_or_missing', T.mount_report(pod, '/data/workspace')['Issues'])

    def test_config_overlay_is_reported(self):
        pod = self.fixture(); pod['spec']['volumes'].append({'name': 'cfg', 'secret': {'secretName': 'private-name'}})
        pod['spec']['containers'][0]['volumeMounts'].append({'name': 'cfg', 'mountPath': '/data/workspace/hidden'})
        report = T.mount_report(pod, '/data/workspace')
        self.assertIn('workspace_overlay', report['Issues'])
        self.assertNotIn('private-name', json.dumps(report))

    def test_ephemeral_and_block_are_reported(self):
        pod = self.fixture(); pod['spec']['ephemeralContainers'] = [{'name': 'debug'}]
        pod['spec']['containers'][0]['volumeDevices'] = [{'name': 'data', 'devicePath': '/dev/volume'}]
        report = T.mount_report(pod, '/data/workspace')
        self.assertIn('ephemeral_containers', report['Issues']); self.assertIn('block_device', report['Issues'])

    def test_paths_preserve_native_cleaning_constraints(self):
        for value in ('/', '//data', '/data/', '/data/../x', '/data\\x', '/data:1', '/data\n'):
            self.assertFalse(T.clean_root(value), value)
        self.assertTrue(T.clean_root('/data/workspace'))

    def test_redirect_does_not_forward_source_authorization(self):
        req = urllib.request.Request('https://original/api', headers={'Authorization': 'Bearer private-token'})
        self.assertIsNone(T.NoRedirect().redirect_request(req, None, 302, '', {}, 'https://different/api'))


if __name__ == '__main__':
    unittest.main()
