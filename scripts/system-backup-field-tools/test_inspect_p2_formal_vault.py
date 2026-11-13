import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('preflight', Path(__file__).with_name('inspect-p2-formal-vault.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class FormalVaultPreflightTests(unittest.TestCase):
    def fixture(self):
        ref = {'Namespace': P.NS, 'Deployment': 'controller', 'DeploymentUID': 'original', 'ServiceAccount': 'controller-sa'}
        dep = {'metadata': {'namespace': P.NS, 'name': 'controller', 'uid': 'original', 'generation': 1},
               'spec': {'replicas': 1, 'template': {'spec': {'serviceAccountName': 'controller-sa',
                    'securityContext': {'runAsUser': 1000, 'fsGroup': 1000},
                    'containers': [{'name': 'owner', 'image': 'image@sha256:' + 'a' * 64,
                        'env': [{'name': 'SECRET', 'value': 'must-not-print'}], 'args': ['must-not-print'],
                        'volumeMounts': [{'name': 'runtime', 'mountPath': '/run/system-backup'}]}]}}},
               'status': {'readyReplicas': 1}}
        return dep, ref

    def test_projection_excludes_credentials_and_keeps_parent_unchanged(self):
        dep, ref = self.fixture()
        before = copy.deepcopy(dep)
        report = P.controller_projection(dep, ref)
        self.assertEqual(dep, before)
        self.assertNotIn('must-not-print', json.dumps(report))
        self.assertTrue(report['Containers'][0]['ExplicitIdentityEligible'])
        self.assertTrue(report['Containers'][0]['DigestPinned'])
        self.assertFalse(report['Containers'][0]['ProviderMountConflict'])

    def test_security_and_mount_conditions_are_not_assumed(self):
        for fault in ['no-uid', 'no-group', 'root', 'override', 'ancestor-mount', 'tagged-image']:
            with self.subTest(fault=fault):
                dep, ref = self.fixture()
                pod = dep['spec']['template']['spec']; container = pod['containers'][0]
                if fault == 'no-uid': pod['securityContext'].pop('runAsUser')
                if fault == 'no-group': pod['securityContext'].pop('fsGroup')
                if fault == 'root': pod['securityContext'] = {'runAsUser': 0}
                if fault == 'override': container['securityContext'] = {'runAsUser': 2000}
                if fault == 'ancestor-mount': container['volumeMounts'][0]['mountPath'] = '/var/run'
                if fault == 'tagged-image': container['image'] = 'image:latest'
                row = P.controller_projection(dep, ref)['Containers'][0]
                self.assertEqual(row['ExplicitIdentityEligible'], fault not in ('no-uid', 'no-group'))
                self.assertEqual(row['ProviderMountConflict'], fault == 'ancestor-mount')
                self.assertEqual(row['DigestPinned'], fault != 'tagged-image')
                if fault == 'override': self.assertEqual(row['RunAsUser'], 2000)

    def test_replaced_controller_refuses(self):
        dep, ref = self.fixture()
        dep['metadata']['uid'] = 'replacement'
        with self.assertRaises(ValueError): P.controller_projection(dep, ref)

    def test_mutation_and_arbitrary_exec_never_spawn(self):
        site = P.Site(None, None)
        with patch.object(P.subprocess, 'run') as run:
            for argv in [[], ['patch', 'deployment', 'controller'], ['exec', 'pod', '-c', 'owner', '--', 'sh', '-c']]:
                with self.assertRaises(ValueError): site.run(argv)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
