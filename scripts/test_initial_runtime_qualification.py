"""Pure Python models of actual first-install entries; no native/cluster calls."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


m = load('system-backup-zhanghui08-operator.py')
d = load('system-backup-operator-deployment.py')


class InitialRuntimeModels(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.run = self.directory/'run'
        self.run.mkdir()
        self.root = self.directory/'release'
        self.root.mkdir()
        self.op = m.Operator(SimpleNamespace(release_directory=self.root, run_directory=self.run, action='host-observer'))
        self.stage = object.__new__(d.DeploymentStages)
        self.stage.op, self.stage.run = self.op, self.run
        self.stage.directory = self.run/'deployment'
        self.stage.directory.mkdir()
        self.events = []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.operation = {'operation': '3'*32, 'scope': {'app_replicas': 1}}
        self.ca = 'c'*64
        self.image = 'sha256:'+'a'*64
        self.images = {'app': {'reference': 'registry/app@'+self.image,
                               'manifest_sha256': 'a'*64, 'config_digest': 'sha256:'+'b'*64},
                       'worker': {'reference': 'registry/worker@sha256:'+'d'*64}}
        self.spec = {'replicas': 1, 'selector': {'matchLabels': {'app': 'business'}},
                     'template': {'spec': {'containers': [{'name': 'app', 'image': self.images['app']['reference'],
                                                          'env': [{'name': 'DB_TLS_CA_SHA256', 'value': self.ca}]}],
                                           'volumes': [{'name': 'workspaces', 'nfs': {'server': '10.0.0.1', 'path': '/'}}]}}}
        self.app = {'metadata': {'uid': 'original-app', 'generation': 2, 'resourceVersion': '2'}, 'spec': copy.deepcopy(self.spec),
                    'status': {'observedGeneration': 2, 'updatedReplicas': 1, 'availableReplicas': 1}}
        self.pod = {'metadata': {'name': 'app-pod', 'uid': 'original-pod',
                                 'ownerReferences': [{'apiVersion': 'apps/v1', 'kind': 'ReplicaSet', 'name': 'app-rs', 'uid': 'original-rs', 'controller': True}]},
                    'spec': {'containers': [{'name': 'app'}]},
                    'status': {'containerStatuses': [{'name': 'app', 'ready': True, 'state': {'running': {}},
                                                       'containerID': 'containerd://original', 'imageID': self.image}]}}
        self.rs = {'metadata': {'uid': 'original-rs', 'ownerReferences': [
            {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'uid': 'original-app', 'controller': True}]}}
        desired = copy.deepcopy(self.spec)
        desired['replicas'] = 0
        self.plan = {'version': 'original-app-complete-tls-template.v1', 'operation': self.operation['operation'],
                     'original_uid': 'original-app', 'desired_spec': desired, 'images': self.images, 'configuration_enabled': False}
        self.pod_receipt = {'Pod': 'app-pod', 'PodUID': 'original-pod', 'ReplicaSetUID': 'original-rs',
                            'ContainerID': 'containerd://original', 'ImageID': self.image, 'CAFileSHA256': self.ca}
        self.write(self.run/'operation.json', self.operation)
        self.write(self.stage.directory/'new-image.plan.json', self.plan)
        self.result = {'version': 'operator-new-image-result.v1',
                       'state': 'actual_full_business_mysql_tls_template_and_same_release_rollout_verified',
                       'configuration_enabled': False, 'plan': self.pin(self.stage.directory/'new-image.plan.json'),
                       'images': self.images, 'app': {'Name': 'clawmanager-app', 'UID': 'original-app',
                                                     'SpecSHA256': d.digest(d.encoded(self.spec))},
                       'business_pods': [self.pod_receipt]}
        self.save_result()
        self.op.open = lambda: {'app_deployment_uid': 'original-app', 'app': copy.deepcopy(self.app)}
        self.op.deployment_stages = lambda: self.stage
        self.stage.get = self.get
        self.stage.kubectl = lambda *a, **kw: self.fail('read-only phase guard must never mutate Kubernetes')
        self.op.k = self.kube_read
        self.runtime = SimpleNamespace(verify_current=lambda op: self.events.append('runtime-readback') or
                                      {'native_qualified': False, 'backup_ready': False})
        self.stack.enter_context(patch.object(m, 'deployment_module', return_value=d))
        self.stack.enter_context(patch.object(m, 'business_runtime_module', return_value=self.runtime))
        self.stack.enter_context(patch.object(m, 'workspace_module', side_effect=AssertionError('no localization/native claim')))
        self.stack.enter_context(patch.object(m, 'early_preflight_module', side_effect=AssertionError('no early NFS prerequisite')))

    def write(self, path, value):
        path.write_bytes(d.encoded(value))
        path.chmod(0o600)

    def pin(self, path):
        return {'File': str(path), 'SHA256': m.sha(path)}

    def save_result(self):
        self.write(self.stage.directory/'new-image.result.json', self.result)

    def get(self, kind, name):
        self.events.append('get-'+kind)
        return copy.deepcopy({'deployment': self.app, 'replicaset': self.rs, 'pod': self.pod}[kind])

    def kube_read(self, *args):
        self.events.append(args[2])
        if args[2] == 'get':
            return json.dumps({'items': [self.pod]}).encode()
        self.assertEqual(args[2], 'exec')
        return (self.ca+'  /etc/clawmanager-business-mysql-ca/ca.crt\n').encode()

    def guard(self):
        return self.op.require_initial_runtime_qualification()

    def test_fresh_original_rollout_without_future_binding_checks_actual_app_and_runtime(self):
        result = self.guard()
        self.assertFalse((self.run/'final-rollout-binding.json').exists())
        self.assertFalse(result['native_qualified'])
        self.assertFalse(result['backup_ready'])
        self.assertIn('exec', self.events)
        self.assertIn('runtime-readback', self.events)

    def test_original_app_identity_template_image_and_actor_drift_refuse(self):
        mutations = [lambda: self.app['metadata'].update(uid='foreign'),
                     lambda: self.app['spec']['template']['spec']['volumes'][0]['nfs'].update(server='10.0.0.2'),
                     lambda: self.pod['status']['containerStatuses'][0].update(imageID='sha256:'+'f'*64),
                     lambda: self.pod['metadata'].update(uid='replacement'),
                     lambda: self.pod['status']['containerStatuses'][0].update(containerID='containerd://replacement'),
                     lambda: self.rs['metadata'].update(uid='replacement')]
        for mutate in mutations:
            app, pod, rs = copy.deepcopy((self.app, self.pod, self.rs))
            with self.subTest(mutation=mutate):
                mutate()
                with self.assertRaises((m.Stop, d.Refused)):
                    self.guard()
            self.app, self.pod, self.rs = app, pod, rs

    def test_stopped_or_unready_app_never_restarts_or_waits(self):
        with patch.object(d.time, 'sleep', side_effect=AssertionError('read-only must fail promptly')):
            self.app['spec']['replicas'] = 0
            with self.assertRaisesRegex(d.Refused, 'no_readonly_restart'):
                self.guard()
            self.app['spec']['replicas'] = 1
            self.app['status']['availableReplicas'] = 0
            with self.assertRaisesRegex(d.Refused, 'no_readonly_wait_or_restart'):
                self.guard()

    def test_existing_new_image_rollout_can_still_start_app_without_verify_only(self):
        self.app['spec']['replicas'] = 0
        def original_start(stage, argv, obj=None, **kwargs):
            self.assertEqual(stage, 'business-app-start')
            self.events.append('original-business-start')
            self.app['spec']['replicas'] = 1
        self.stage.kubectl = original_start
        app, pods = self.stage.business_rollout(self.images)
        self.assertEqual(app['spec']['replicas'], 1)
        self.assertEqual(pods, [self.pod_receipt])
        self.assertIn('original-business-start', self.events)

    def test_missing_or_tampered_actual_producer_receipt_refuses(self):
        path = self.stage.directory/'new-image.result.json'
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.guard()
        self.save_result()
        self.plan['operation'] = '4'*32
        self.write(self.stage.directory/'new-image.plan.json', self.plan)
        with self.assertRaisesRegex(m.Stop, 'producer_file_pin_changed'):
            self.guard()
        self.result['plan'] = self.pin(self.stage.directory/'new-image.plan.json')
        self.save_result()
        with self.assertRaisesRegex(m.Stop, 'same_original_disabled_app_plan'):
            self.guard()

    def test_wrong_ca_or_runtime_identity_refuses_without_qualification(self):
        self.ca = 'f'*64
        with self.assertRaisesRegex(d.Refused, 'actual_business_ca_file_readback'):
            self.guard()
        self.ca = 'c'*64
        self.runtime.verify_current = lambda op: (_ for _ in ()).throw(m.Stop('runtime_actor_changed'))
        with self.assertRaisesRegex(m.Stop, 'runtime_actor_changed'):
            self.guard()

    def test_existing_final_binding_uses_unchanged_full_gate_and_late_action_cannot_use_early_gate(self):
        (self.run/'final-rollout-binding.json').write_text('{}')
        self.op.require_current_runtime_qualification = lambda: (_ for _ in ()).throw(m.Stop('full_final_gate_refused'))
        with self.assertRaisesRegex(m.Stop, 'full_final_gate_refused'):
            self.guard()
        self.op.a.action = 'enable'
        with self.assertRaisesRegex(m.Stop, 'not_a_final_qualification'):
            self.guard()

    def main_entry(self, action, refuse=False):
        events = []
        class EarlyRefused(Exception):
            pass
        noop = lambda *a, **kw: None
        dummy = SimpleNamespace(ACTIONS=(), PREPARE=(), register_arguments=noop, EarlyPreflightRefused=EarlyRefused)
        producer = self.stage.directory/'model-source.json'
        self.write(producer, {'data_only': True})
        initial = SimpleNamespace(register_arguments=noop,
                                  bind_complete_source_arguments=lambda op: events.append('bind-source'),
                                  prepare_minio_options_arguments=lambda op: events.append('minio-options'),
                                  prepare_complete_source_arguments=lambda op: events.append('source-producer') or self.pin(producer),
                                  prepare_redis_source_arguments=lambda op, mode: events.append('redis-producer') or {'data_only': True})
        deployment = SimpleNamespace(register_arguments=noop, dispatch=lambda op, action: events.append('dispatch-'+action) or {'data_only': True})
        def early():
            events.append('early-gate')
            if refuse:
                raise m.Stop('early_actual_rollout_refused')
        self.op.require_initial_runtime_qualification = early
        self.op.require_current_runtime_qualification = lambda: events.append('full-gate') or (_ for _ in ()).throw(m.Stop('full_final_gate_refused'))
        self.op.prepare_relay_runtime_trust = lambda: events.append('relay')
        self.op.bind_writer_selection_argument = lambda: events.append('writer')
        def factory(args):
            self.op.a = args
            return self.op
        getters = ['owner_assembly_module', 'nonce_module', 'production_adoption_module', 'adoption_locations_module',
                   'minio_recovery_module', 'c1_inputs_module', 'c1_native_module', 'c1_authors_module', 'live_capacity_module',
                   'archive_inputs_module', 'minio_consent_module', 'enabled_publication_module', 'capture_mapping_module']
        with contextlib.ExitStack() as stack:
            for name in getters:
                stack.enter_context(patch.object(m, name, return_value=dummy))
            stack.enter_context(patch.object(m, 'early_preflight_module', return_value=dummy))
            stack.enter_context(patch.object(m, 'deployment_module', return_value=deployment))
            stack.enter_context(patch.object(m, 'business_runtime_module', return_value=SimpleNamespace(register_arguments=noop)))
            stack.enter_context(patch.object(m, 'initial_runtime_module', return_value=initial))
            stack.enter_context(patch.object(m, 'Operator', side_effect=factory))
            stack.enter_context(patch.object(m, 'fcntl', SimpleNamespace(flock=noop, LOCK_EX=1, LOCK_NB=2)))
            stack.enter_context(patch.object(m.os, 'geteuid', return_value=0, create=True))
            stack.enter_context(patch.object(m.os, 'umask', return_value=0))
            with contextlib.redirect_stdout(io.StringIO()):
                code = m.main([action, '--run-directory', str(self.run), '--release-directory', str(self.root)])
        return code, events

    def test_actual_main_first_install_entries_use_early_gate_before_any_producer(self):
        for action in ('host-observer', 'materials', 'initial-source-inputs', 'initial-redis-source'):
            with self.subTest(action=action):
                code, events = self.main_entry(action)
                self.assertEqual(code, 0)
                self.assertEqual(events[0], 'early-gate')
                self.assertNotIn('full-gate', events)

    def test_actual_main_early_refusal_prevents_all_producer_or_native_dispatch(self):
        for action in ('host-observer', 'materials', 'initial-source-inputs', 'initial-redis-source'):
            with self.subTest(action=action):
                code, events = self.main_entry(action, refuse=True)
                self.assertEqual(code, 3)
                self.assertEqual(events, ['early-gate'])

    def test_actual_main_material_signing_still_requires_full_final_gate(self):
        code, events = self.main_entry('materials-signing')
        self.assertEqual(code, 3)
        self.assertEqual(events, ['full-gate'])


if __name__ == '__main__':
    unittest.main()
