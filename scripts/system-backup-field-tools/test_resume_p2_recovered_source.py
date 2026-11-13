import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('recovered', Path(__file__).with_name('resume-p2-recovered-source.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)


class RecoveredSourceTests(unittest.TestCase):
    def fixture(self):
        scope = dict(Version='explicit-running-tenant-runtime-test-scope.v3', InstallationID='installation',
                     ServerUUID='server', Database='db', NamespaceUID='namespace',
                     Deferred=[{'ID': i, 'Generation': 1} for i in [4,5,6]], OriginalInstancesSHA256='old')
        original = {'Deployment': {'runtime_sources': {'runtime_test_scope': scope, 'shared_runtime_protocol': 'shared-container-freeze.v1'},
                                  'profile_file': '/old/execution-profile.json', 'capture_modules': {'path': '/old/capture-materials.json'},
                                  'provider_dependencies': [{'observer': {'File': '/provider/observer.json', 'SHA256': 'same'}}]},
                    'Materials': {'CaptureGrantSHA256': '', 'DeploymentConfigSHA256': ''},
                    'Connections': [{'Purpose': 'source_api', 'Credential': {'File': '/original/jwt', 'SHA256': 'same'}}],
                    'Until': '2026-11-13T08:57:02Z', 'Controller': {'PodUID': 'same'}}
        data = {'RuntimeTestScope': dict(copy.deepcopy(scope), OriginalInstancesSHA256='new'),
                'Instances': [{'ID': i, 'Generation': g, 'UserID': 1, 'Mode': 'lite', 'Type': 'hermes', 'Backend': 'gateway',
                               'Status': 'running' if i in [1,2,3,7,8] else 'error'}
                              for i, g in [(1,4),(2,0),(3,9),(4,1),(5,1),(6,1),(7,4),(8,4)]]}
        return original, data

    def test_preserves_authority_provider_credentials_and_window(self):
        original, data = self.fixture(); before = copy.deepcopy(original)
        value = R.successor(original, data, Path('/new'))
        expected = copy.deepcopy(original)
        expected['Deployment']['runtime_sources']['runtime_test_scope'] = data['RuntimeTestScope']
        expected['Deployment']['profile_file'] = str(Path('/new') / 'execution-profile.json')
        expected['Deployment']['capture_modules']['path'] = str(Path('/new') / 'capture-materials.json')
        self.assertEqual(value, expected); self.assertEqual(original, before)

    def test_rejects_generation_and_identity_drift(self):
        for field, val in [('Generation',8), ('UserID',2), ('Type','openclaw'), ('Mode','pro'), ('Backend','desktop')]:
            original, data = self.fixture(); data['Instances'][2][field] = val
            with self.assertRaises(ValueError): R.successor(original, data, Path('/new'))
        original, data = self.fixture(); data['Instances'][0]['Generation'] = 5
        with self.assertRaises(ValueError): R.successor(original, data, Path('/new'))

    def test_rejects_changed_scope_identity_deferred_or_roster(self):
        for key in ('InstallationID','NamespaceUID','ServerUUID','Deferred'):
            original, data = self.fixture(); data['RuntimeTestScope'][key] = 'changed'
            with self.assertRaises(ValueError): R.successor(original, data, Path('/new'))
        original, data = self.fixture(); data['Instances'][0]['Status'] = 'stopped'
        with self.assertRaises(ValueError): R.successor(original, data, Path('/new'))

    def test_requires_actual_observed_completion(self):
        done = {'Version': 'p2-runtime-pool-recovered.v1', 'SourceRevision': '312eaa9e47ad45f71479640185496aa4323e6d06',
                'Image': R.IMAGE, 'InstanceID': 3, 'Generation': 9, 'Pool': 8,
                'PodUID': 'a384ba3f-984d-4108-ae5d-14eaf19ccea8', 'VerifiedLiteIDs': [1,3,7,8],
                'SourceReauthorRequired': True, 'BackupReady': False}
        R.validate_recovery(done)
        for key, value in [('Generation',8), ('Image','other'), ('VerifiedLiteIDs',[3]), ('BackupReady',True), ('Pool',5), ('SourceReauthorRequired',1)]:
            with self.assertRaises(ValueError): R.validate_recovery(dict(done, **{key:value}))


if __name__ == '__main__':
    unittest.main()
