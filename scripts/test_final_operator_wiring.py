"""Route/custody regression sources for Root's isolated Linux execution."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('system-backup-zhanghui08-operator.py')
n = load('system-backup-operator-nonce.py')


class OperatorWiring(unittest.TestCase):
    def operator(self, directory):
        root = directory / 'release'
        root.mkdir()
        run = directory / 'run'
        run.mkdir()
        op = m.Operator(SimpleNamespace(release_directory=root, run_directory=run, copy_receipts_directory=directory/'actual-copy'))
        op.open = lambda: {'app_replicas': 1}
        op.kube = run / 'original.kubeconfig'
        return op

    def test_database_prepare_keeps_original_native_scope_and_never_calls_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            op = self.operator(Path(directory))
            events = []
            def invoke(stage, argv, **kwargs):
                events.append((stage, argv, kwargs))
                return {'state': 'actual-native-state', 'original_database_upgraded': False}, op.run/'receipt'
            op.invoke = invoke
            def forbidden(*args, **kwargs):
                raise AssertionError('SQL maintenance must not contact/migrate NFS or claim a native source proof')
            with patch.object(m, 'early_preflight_module', side_effect=forbidden), patch.object(m, 'workspace_module', side_effect=forbidden):
                result = op.db('prepare')
            self.assertEqual(len(events), 1)
            stage, argv, options = events[0]
            self.assertEqual(stage, 'db-prepare')
            self.assertEqual(argv[argv.index('--copy-receipts-directory')+1], op.a.copy_receipts_directory)
            self.assertEqual(argv[argv.index('--operation-directory')+1], op.run/'original199')
            self.assertEqual(argv[argv.index('--v3-archive')+1], op.root/m.COPY_NAME)
            self.assertEqual(argv[argv.index('--original-proof')+1], op.root/'bin/system-backup-legacy-upgrade177-proof')
            self.assertEqual(argv[argv.index('--original-proof-sha256')+1], m.PROOF_SHA)
            self.assertFalse(options['repeat'])
            self.assertEqual(options['env']['KUBECONFIG'], str(op.kube))
            self.assertEqual(result['action_scope'], 'original_database_maintenance_only')
            self.assertFalse(result['workspace_native_proof_produced'])
            self.assertFalse(result['backup_readiness_proven'])
            self.assertFalse(result['page_backup_completed'])

    def test_missing_actual_copy_receipts_never_sends_database_prepare(self):
        with tempfile.TemporaryDirectory() as directory:
            op = self.operator(Path(directory))
            op.a.copy_receipts_directory = None
            sent = []
            op.invoke = lambda *args, **kwargs: sent.append(args)
            with self.assertRaisesRegex(m.Stop, 'fresh_copy199_native_receipts_directory_required'):
                op.db('prepare')
            self.assertEqual(sent, [])

    def test_native_database_refusal_or_unknown_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            op = self.operator(Path(directory))
            sent = []
            def refused(stage, argv, **kwargs):
                sent.append((stage, argv))
                raise m.Stop('native-original-database-guard-unconfirmed')
            op.invoke = refused
            with self.assertRaisesRegex(m.Stop, 'native-original-database-guard-unconfirmed'):
                op.db('prepare')
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0][0], 'db-prepare')

    def test_original_operation_identity_refusal_prevents_all_database_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            op = self.operator(Path(directory))
            sent = []
            def refused():
                raise m.Stop('original-operation-identity-changed')
            op.open = refused
            op.invoke = lambda *args, **kwargs: sent.append(args)
            with self.assertRaisesRegex(m.Stop, 'original-operation-identity-changed'):
                op.db('prepare')
            self.assertEqual(sent, [])

    def test_workspace_guard_accepts_started_new_image_but_requires_original_release(self):
        with tempfile.TemporaryDirectory() as directory:
            op = self.operator(Path(directory))
            original = op.run/'original199'
            original.mkdir()
            with self.assertRaises(m.Stop):
                op.workspace_upgrade_released()
            for name in ('original-upgraded-readback.json', 'released.json', 'cleanup-completed.json'):
                (original/name).write_bytes(b'original-native-file')
            self.assertEqual(op.workspace_upgrade_released()['app_replicas'], 1)
            (original/'original-rollback-readback.json').write_bytes(b'rollback')
            with self.assertRaises(m.Stop):
                op.workspace_upgrade_released()

    def assert_runtime_refusal_prevents_dispatch(self, action):
        with tempfile.TemporaryDirectory() as directory:
            op = self.operator(Path(directory))
            events = []
            op.owner_common = lambda: events.append('owner-common') or []
            op.final_binding = lambda: events.append('binding') or {}
            op.invoke = lambda *a, **kw: events.append('native-send')
            def refused(actual):
                self.assertIs(actual, op)
                events.append('runtime-refused')
                raise m.Stop('actual-runtime-profile-refused')
            with patch.object(m.Operator, 'require_current_runtime_qualification', new=refused):
                with self.assertRaisesRegex(m.Stop, 'actual-runtime-profile-refused'):
                    (op.adoption if action == 'adopt' else op.composition)(action)
            self.assertEqual(events, ['runtime-refused'])

    def test_adoption_runtime_refusal_prevents_owner_or_native_send(self):
        self.assert_runtime_refusal_prevents_dispatch('adopt')

    def test_configuration_runtime_refusal_prevents_owner_or_native_send(self):
        self.assert_runtime_refusal_prevents_dispatch('composition')

    def test_exact_loader_retains_exception_type_and_rechecks_cached_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory)/'operator.py'
            source = Path(directory)/'model-exception.py'
            source.write_bytes(b'class OriginalRefused(Exception):\n    pass\n')
            sha = hashlib.sha256(source.read_bytes()).hexdigest()
            with patch.object(m, '__file__', str(entry)):
                first = m.exact_module(source.name, sha)
                second = m.exact_module(source.name, sha)
                self.assertIs(first.OriginalRefused, second.OriginalRefused)
                source.write_bytes(b'class Changed(Exception):\n    pass\n')
                with self.assertRaises(m.Stop):
                    m.exact_module(source.name, sha)
            m._EXACT_MODULES.pop(source.name, None)


class NonceWiring(unittest.TestCase):
    def issued(self):
        return {'MountDirectory': n.DIRECTORY, 'RelativePath': 'a'*64+'/1', 'Secret': 'original-controlled-secret',
                'Source': {'File': '/private/original-source.json', 'SHA256': 'b'*64},
                'Material': {'File': '/private/original-key', 'SHA256': 'c'*64},
                'PodVolume': {'name': 'original-owner-nonce-file', 'secret': {'secretName': 'original-controlled-secret', 'defaultMode': 256, 'items': [{'key': 'nonce', 'path': 'a'*64+'/1'}]}},
                'ContainerMount': {'name': 'original-owner-nonce-file', 'readOnly': True, 'mountPath': n.DIRECTORY}}

    def test_mount_requires_original_transport_and_inserts_before_host_creation(self):
        op = SimpleNamespace(source_helpers=lambda: m)
        pod = {'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532}, 'volumes': [],
               'containers': [{'name': 'controller'}, {'name': 'installation-owner'}]}
        with patch.object(n, 'material', return_value=self.issued()):
            n.mount_for_host(op, pod)
            self.assertEqual(pod['volumes'], [self.issued()['PodVolume']])
            self.assertTrue(all(c['volumeMounts'] == [self.issued()['ContainerMount']] for c in pod['containers']))
            with self.assertRaises(m.Stop):
                n.mount_for_host(op, pod)

    def test_mount_refuses_wrong_executing_security_profile(self):
        op = SimpleNamespace(source_helpers=lambda: m)
        pod = {'securityContext': {'runAsUser': 1000, 'runAsGroup': 65532, 'fsGroup': 65532}, 'volumes': [],
               'containers': [{'name': 'controller'}, {'name': 'installation-owner'}]}
        with patch.object(n, 'material', return_value=self.issued()):
            with self.assertRaises(m.Stop):
                n.mount_for_host(op, pod)
        self.assertEqual(pod['volumes'], [])

    def test_readability_checks_both_actual_containers_and_original_digest(self):
        calls = []
        path = n.DIRECTORY+'/'+self.issued()['RelativePath']
        def k(*args):
            calls.append(args)
            return ('c'*64+'  '+path+'\n').encode('ascii')
        op = SimpleNamespace(source_helpers=lambda: m, k=k)
        identity = {'Pod': 'actual-pod', 'PodUID': 'actual-uid'}
        stages = SimpleNamespace(op=op, check_host=lambda value: self.assertEqual(value, identity))
        with patch.object(n, 'material', return_value=self.issued()):
            result = n.verify_readable(stages, identity)
        self.assertEqual({args[args.index('-c')+1] for args in calls}, {'controller', 'installation-owner'})
        self.assertTrue(all('65532:65532' in args[args.index('-ec')+1] for args in calls))
        self.assertEqual(result['actual_host']['PodUID'], 'actual-uid')
        self.assertFalse(result['backup_ready'])

    def test_wrong_mounted_bytes_cannot_become_binding(self):
        op = SimpleNamespace(source_helpers=lambda: m, k=lambda *args: ('d'*64+'  '+n.DIRECTORY+'/'+self.issued()['RelativePath']+'\n').encode())
        stages = SimpleNamespace(op=op, check_host=lambda value: None)
        with patch.object(n, 'material', return_value=self.issued()):
            with self.assertRaises(m.Stop):
                n.verify_readable(stages, {'Pod': 'actual-pod'})


if __name__ == '__main__':
    unittest.main()
