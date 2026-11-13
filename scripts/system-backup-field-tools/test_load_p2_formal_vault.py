import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('loader', Path(__file__).with_name('load-p2-formal-vault.py'))
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)


class FormalVaultLoadTests(unittest.TestCase):
    def fixture(self):
        controller = {'name': 'controller', 'image': 'registry/app@sha256:original', 'imagePullPolicy': 'IfNotPresent',
                      'securityContext': {'runAsUser': 65532}, 'command': ['/controller'],
                      'volumeMounts': [{'name': 'inputs', 'mountPath': '/run/system-backup', 'readOnly': True}]}
        before = {'replicas': 1, 'template': {'spec': {'serviceAccountName': 'controller', 'securityContext': {'fsGroup': 65532},
                  'containers': [controller, {**copy.deepcopy(controller), 'name': 'installation-owner'}],
                  'volumes': [{'name': 'inputs', 'persistentVolumeClaim': {'claimName': 'inputs'}}]}}}
        desired = copy.deepcopy(before)
        pod = desired['template']['spec']
        pod['volumes'] += [{'name': 'provider-dependency-input', 'secret': {'secretName': 'metadata', 'defaultMode': 0o440}},
                           {'name': 'provider-dependency', 'emptyDir': {'medium': 'Memory'}}]
        pod['initContainers'] = [{'name': 'provider-dependency-install', 'image': controller['image'],
                                 'imagePullPolicy': controller['imagePullPolicy'], 'securityContext': controller['securityContext'],
                                 'command': ['/usr/local/bin/system-backup-source-registries'],
                                 'args': ['install-provider-files', '--observer-sha256', 'observer', '--token-sha256', 'token'],
                                 'volumeMounts': [{'name': 'provider-dependency-input', 'mountPath': '/input', 'readOnly': True},
                                                  {'name': 'provider-dependency', 'mountPath': '/output'}],
                                 'resources': {}, 'terminationMessagePath': '/dev/termination-log', 'terminationMessagePolicy': 'File'}]
        pod['containers'][0]['volumeMounts'].append({'name': 'provider-dependency', 'mountPath': L.MOUNT, 'subPath': 'private', 'readOnly': True})
        secret = {'metadata': {'name': 'metadata', 'namespace': L.NS}, 'immutable': True, 'type': 'Opaque', 'data': {'token': 'fixture'}}
        return before, desired, secret

    def test_cas_rebase_only_when_entire_spec_is_unchanged(self):
        before, _, _ = self.fixture()
        original = {'metadata': {'uid': 'original', 'resourceVersion': '1'}, 'spec': before}
        current = {**original, 'metadata': {'uid': 'original', 'resourceVersion': '2'}}
        native = [{'op': 'test', 'path': '/metadata/uid', 'value': 'original'},
                  {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '1'},
                  {'op': 'add', 'path': '/spec/new', 'value': 'test'}]
        saved = copy.deepcopy(native)
        actual = L.guarded_patch(original, current, native)
        self.assertEqual(native, saved)
        self.assertEqual(actual[1]['value'], '2')
        self.assertEqual(actual[2], {'op': 'test', 'path': '/spec', 'value': before})
        for change in ('spec', 'uid', 'deleting', 'native'):
            with self.subTest(change=change):
                candidate, operations = copy.deepcopy(current), copy.deepcopy(native)
                if change == 'spec': candidate['spec']['replicas'] = 2
                if change == 'uid': candidate['metadata']['uid'] = 'replacement'
                if change == 'deleting': candidate['metadata']['deletionTimestamp'] = 'now'
                if change == 'native': operations[1]['value'] = 'unobserved'
                with self.assertRaises(ValueError): L.guarded_patch(original, candidate, operations)

    def test_native_delivery_and_api_defaults_are_accepted(self):
        before, desired, secret = self.fixture()
        unchanged = copy.deepcopy(desired)
        L.validate_delivery_spec(before, desired, secret, 'observer', 'token')
        self.assertEqual(desired, unchanged)

    def test_delivery_rejects_unrelated_changes_or_insecure_mounts(self):
        for change in ('image', 'startup', 'secret', 'mode', 'readwrite', 'other-container', 'root', 'init-extra', 'memory'):
            with self.subTest(change=change):
                before, desired, secret = self.fixture()
                pod = desired['template']['spec']
                if change == 'image': pod['containers'][0]['image'] = 'replacement'
                if change == 'startup': pod['containers'][1]['command'] = ['/replacement']
                if change == 'secret': pod['volumes'][-2]['secret']['secretName'] = 'other'
                if change == 'mode': pod['volumes'][-2]['secret']['defaultMode'] = 0o644
                if change == 'readwrite': pod['containers'][0]['volumeMounts'][-1]['readOnly'] = False
                if change == 'other-container': pod['containers'][1]['volumeMounts'].append(pod['containers'][0]['volumeMounts'][-1])
                if change == 'root': pod['initContainers'][0]['securityContext'] = {'runAsUser': 0}
                if change == 'init-extra': pod['initContainers'][0]['env'] = [{'name': 'EXTRA', 'value': 'changed'}]
                if change == 'memory': pod['volumes'][-1]['emptyDir'] = {}
                with self.assertRaises(ValueError): L.validate_delivery_spec(before, desired, secret, 'observer', 'token')

    def test_actual_pod_allows_service_account_projection_but_rejects_mutation(self):
        _, desired, _ = self.fixture()
        actual = {'spec': copy.deepcopy(desired['template']['spec'])}
        actual['spec']['volumes'].append({'name': 'kube-api-access-fixture', 'projected': {}})
        actual['spec']['containers'][0]['volumeMounts'].append({'name': 'kube-api-access-fixture', 'mountPath': '/var/run/secrets/kubernetes.io/serviceaccount'})
        L.validate_running_pod(desired, actual)
        for change in ('image', 'extra', 'provider-mount', 'identity'):
            with self.subTest(change=change):
                current = copy.deepcopy(actual)
                if change == 'image': current['spec']['containers'][0]['image'] = 'other'
                if change == 'extra': current['spec']['containers'].append({'name': 'unexpected'})
                if change == 'provider-mount': current['spec']['containers'][0]['volumeMounts'][1]['readOnly'] = False
                if change == 'identity': current['spec']['serviceAccountName'] = 'other'
                with self.assertRaises(ValueError): L.validate_running_pod(desired, current)

    def test_secret_adoption_requires_exact_immutable_native_data(self):
        _, _, secret = self.fixture()
        observed = copy.deepcopy(secret); observed['metadata']['uid'] = 'real-uid'
        L.verify_secret(observed, secret)
        for field, value in [('data', {'token': 'foreign'}), ('immutable', False), ('type', 'other')]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError): L.verify_secret({**observed, field: value}, secret)

    def test_source_refresh_preserves_authority_roles_scope_and_credentials(self):
        profile = str(Path('old') / 'execution-profile.json')
        ref = {'NamespaceUID': 'ns-uid', 'DeploymentUID': 'dep-uid', 'ServiceAccountUID': 'sa-uid', 'Pod': 'old-pod', 'PodUID': 'old-uid', 'ReplicaSet': 'old-rs', 'ReplicaSetUID': 'old-rs-uid'}
        original = {'Controller': ref, 'Connections': ['pinned'], 'RuntimeAgent': 'pinned', 'Until': 'unchanged'}
        core = {'profile_file': profile, 'capture_modules': {'path': str(Path('old') / 'capture-materials.json')},
                'database_workload': 'mysql', 'provider_dependencies': ['vault'], 'runtime_test_scope': {'deferred': [4, 5, 6]}}
        materials = {'DeploymentConfigSHA256': 'formal-core', 'CaptureGrantSHA256': ''}
        selected = {'Controller': ref, 'ExecutionProfile': {'File': profile}, 'Deployment': {'SHA256': 'formal-core'}}
        fresh = {**ref, 'Pod': 'new', 'PodUID': 'new-uid', 'ReplicaSet': 'new-rs', 'ReplicaSetUID': 'new-rs-uid'}
        args = (original, core, materials, selected, fresh, Path('new'))
        saved = copy.deepcopy(args)
        result = L.successor_definition(*args)
        self.assertEqual(args, saved)
        self.assertEqual(result['Connections'], original['Connections'])
        self.assertEqual(result['RuntimeAgent'], original['RuntimeAgent'])
        self.assertEqual(result['Deployment']['provider_dependencies'], core['provider_dependencies'])
        self.assertEqual(result['Deployment']['runtime_test_scope'], core['runtime_test_scope'])
        self.assertEqual(result['Materials']['DeploymentConfigSHA256'], '')
        self.assertEqual(result['Controller'], fresh)
        for change in ('identity', 'signed'):
            changed = list(copy.deepcopy(args))
            if change == 'identity': changed[4]['ServiceAccountUID'] = 'different'
            else: changed[2]['CaptureGrantSHA256'] = 'issued'
            with self.assertRaises(ValueError): L.successor_definition(*changed)

    def test_unknown_send_is_not_repeated_and_marker_precedes_api(self):
        site = L.Site.__new__(L.Site)
        site.directory = Path('journal'); site.A = SimpleNamespace(retain=Mock(), sha=lambda body: 'digest')
        site.call = Mock(return_value=b'ok')
        with patch.object(Path, 'exists', return_value=True):
            with self.assertRaises(ValueError): site.send('controller-patch', ['patch'], b'body')
        site.call.assert_not_called(); site.A.retain.assert_not_called()
        order = []
        site.A.retain.side_effect = lambda *args: order.append('marker')
        site.call.side_effect = lambda *args: order.append('api')
        with patch.object(Path, 'exists', return_value=False): site.send('controller-patch', ['patch'], b'body')
        self.assertEqual(order, ['marker', 'api'])


if __name__ == '__main__':
    unittest.main()
