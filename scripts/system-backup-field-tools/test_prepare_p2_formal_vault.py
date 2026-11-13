import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('prepare-p2-formal-vault.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class FormalVaultSuccessorTests(unittest.TestCase):
    def fixture(self):
        sha = lambda raw: hashlib.sha256(raw).hexdigest()
        workload = {'Deployment': 'vault', 'DeploymentUID': 'vault-uid'}
        ref = lambda name: {'namespace': 'ns', 'name': name, 'uid': name + '-uid'}
        original = {'namespace': 'ns', 'platform_writers': [ref('app'), ref('vault')], 'database_workload': ref('mysql')}
        old_observer = {'Endpoint': 'https://vault.ns.svc:8200', 'ClusterID': 'original-cluster', 'IdentityMode': 'original-owner-readonly', 'TokenFile': '/old', 'TokenSHA256': 'old', 'ObserverPolicy': ''}
        observer = {**old_observer, 'IdentityMode': 'metadata-only', 'TokenFile': P.MOUNT + '/token',
                    'TokenSHA256': sha(b'fixture-metadata-only'), 'ObserverPolicy': 'sbk-fixture'}
        encoded = json.dumps(observer).encode()
        secret = {'kind': 'Secret', 'immutable': True, 'metadata': {'namespace': 'ns'},
                  'data': {'observer.json': base64.b64encode(encoded).decode(), 'token': base64.b64encode(b'fixture-metadata-only').decode()}}
        successor = {**original, 'platform_writers': [ref('app')], 'provider_dependencies': [
            {'schema_version': 'formal-vault-provider-dependency.v1', 'workload': workload,
             'observer': {'File': P.MOUNT + '/observer.json', 'SHA256': sha(encoded)}}]}
        before, after = {'Deployment': 'old', 'MaterialsTemplate': 'old', 'Controller': 'same'}, {'Deployment': 'new', 'MaterialsTemplate': 'new', 'Controller': 'same'}
        deployment = {'metadata': {'uid': 'controller-uid', 'resourceVersion': '7'}, 'spec': {'template': {'spec': {'containers': [{'name': 'controller'}, {'name': 'installation-owner'}]}}}}
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': 'controller-uid'}, {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'},
                 {'op': 'test', 'path': '/spec/template/spec/containers/0/name', 'value': 'controller'},
                 {'op': 'add', 'path': '/spec/template/spec/containers/0/volumeMounts/-', 'value': {'name': 'provider-dependency', 'mountPath': P.MOUNT}}]
        return [before, after, original, successor, workload, secret, patch, deployment, sha, old_observer]

    def test_only_native_provider_transition_changes(self):
        args = self.fixture()
        before = copy.deepcopy(args[:-2])
        P.validate_successor(*args)
        self.assertEqual(args[:-2], before)

    def test_rejects_broadened_config_token_route_and_patch(self):
        for case in ['database', 'controller', 'token', 'root', 'loopback', 'patch-uid', 'other-container', 'image-change']:
            with self.subTest(case=case):
                args = self.fixture()
                if case == 'database': args[3]['database_workload'] = {'name': 'other'}
                if case == 'controller': args[1]['Controller'] = 'other'
                if case == 'token': args[5]['data']['token'] = base64.b64encode(b'foreign').decode()
                if case in ('root', 'loopback'):
                    observer = json.loads(base64.b64decode(args[5]['data']['observer.json']))
                    if case == 'root': observer['IdentityMode'] = 'original-owner-readonly'
                    else: observer['Endpoint'] = 'https://127.0.0.1:1234'
                    raw = json.dumps(observer).encode()
                    args[5]['data']['observer.json'] = base64.b64encode(raw).decode()
                    args[3]['provider_dependencies'][0]['observer']['SHA256'] = args[8](raw)
                if case == 'patch-uid': args[6][0]['value'] = 'replacement'
                if case == 'other-container': args[6][-1]['path'] = '/spec/template/spec/containers/1/volumeMounts/-'
                if case == 'image-change': args[6].append({'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': 'different'})
                with self.assertRaises(ValueError): P.validate_successor(*args)


if __name__ == '__main__':
    unittest.main()
