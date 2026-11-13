import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('longhorn_loaded', Path(__file__).with_name('prepare-p2-longhorn-provider-loaded.py'))
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


class LoadedProviderLonghornTests(unittest.TestCase):
    def test_only_confirmed_same_source_native_failure_allows_successor(self):
        argv = ['/native', 'prepare-mount-materials', '--source-selection-sha256', P.SELECTION_SHA, '--output-directory', '/original/out']
        refusal = {'Status': 'original_mount_author_refused', 'Phase': 'native_writers'}
        self.assertEqual(P.confirmed_native_failure({'ExitCode': 1}, refusal, argv), Path('/original/out'))
        for case in ('success', 'unknown', 'phase', 'status', 'source'):
            with self.subTest(case=case):
                exit_record, error, args = {'ExitCode': 1}, dict(refusal), list(argv)
                if case == 'success': exit_record = {'ExitCode': 0}
                if case == 'unknown': exit_record = {}
                if case == 'phase': error['Phase'] = 'write_outputs'
                if case == 'status': error['Status'] = 'unknown'
                if case == 'source': args[3] = 'other-source'
                with self.assertRaises(ValueError): P.confirmed_native_failure(exit_record, error, args)

    def test_pool_history_repair_requires_exact_observed_step(self):
        argv = ['/native', 'prepare-mount-materials', '--source-selection-sha256', P.SELECTION_SHA, '--output-directory', '/original/out']
        failure = {'Status': 'original_mount_author_refused', 'Phase': 'native_writers', 'Step': 'native_runtime_pool_state',
                   'Kind': 'RuntimePod', 'Reason': 'validation'}
        P.confirmed_native_failure({'ExitCode': 1}, failure, argv, True)
        for field in ('Step', 'Kind', 'Reason'):
            with self.subTest(field=field):
                with self.assertRaises(ValueError): P.confirmed_native_failure({'ExitCode': 1}, {**failure, field: 'different'}, argv, True)

    def test_service_account_repair_requires_observed_instance_deployment_failure(self):
        argv = ['/native', 'prepare-mount-materials', '--source-selection-sha256', P.SELECTION_SHA, '--output-directory', '/original/out']
        failure = {'Status': 'original_mount_author_refused', 'Phase': 'native_writers', 'Step': 'native_instance_deployment',
                   'Kind': 'Deployment', 'Reason': 'validation', 'InstanceID': 1}
        self.assertEqual(P.confirmed_native_failure({'ExitCode': 1}, failure, argv, service_account=True), Path('/original/out'))
        for field, value in [('Step', 'native_instance_account'), ('Kind', 'Pod'), ('Reason', 'forbidden'), ('InstanceID', 2),
                             ('Phase', 'write_outputs'), ('Status', 'unknown')]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    P.confirmed_native_failure({'ExitCode': 1}, {**failure, field: value}, argv, service_account=True)
        with self.assertRaises(ValueError):
            P.confirmed_native_failure({'ExitCode': 0}, failure, argv, service_account=True)
        with self.assertRaises(ValueError):
            P.confirmed_native_failure({'ExitCode': 1}, failure, [x if x != P.SELECTION_SHA else 'other' for x in argv], service_account=True)

    def test_shared_protocol_repair_requires_exact_capability_refusal(self):
        argv = ['/native', 'prepare-mount-materials', '--source-selection-sha256', P.SELECTION_SHA, '--output-directory', '/original/out']
        failure = {'Status': 'original_mount_author_refused', 'Phase': 'native_writers', 'Step': 'native_agent_capabilities',
                   'Kind': 'RuntimeAgent', 'Reason': 'read_error', 'InstanceID': 1}
        P.confirmed_native_failure({'ExitCode': 1}, failure, argv, shared_protocol=True)
        for key, value in [('Step', 'native_shared_agent_capabilities'), ('Kind', 'Deployment'), ('Reason', 'validation'), ('InstanceID', 3), ('Phase', 'write_outputs')]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    P.confirmed_native_failure({'ExitCode': 1}, {**failure, key: value}, argv, shared_protocol=True)

    def fixture(self):
        ref = {'Namespace': 'ns', 'Deployment': 'controller', 'DeploymentUID': 'e4e27f27-8f02-40ab-8c62-09f2ffa3fafa',
               'Pod': 'new-pod', 'PodUID': P.POD_UID, 'ReplicaSet': 'new-rs', 'ReplicaSetUID': P.RS_UID,
               'ServiceAccount': 'sa', 'ServiceAccountUID': 'sa-uid'}
        done = {'Version': 'p2-formal-vault-loaded-source-reauthored.v1', 'SecretLoaded': True, 'MetadataTokenReissued': False,
                'GrantsIssued': False, 'BackupReady': False, 'Receipt': {'SHA256': P.RECEIPT_SHA},
                'Definition': {'SHA256': P.DEFINITION_SHA}, 'SourceSelection': {'SHA256': P.SELECTION_SHA}, 'Controller': ref}
        receipt = {'Version': 'original-initial-source-inputs-authored.v1', 'SourceSelection': done['SourceSelection'],
                   'GrantsIssued': False, 'BackupReady': False, 'Deployment': 'core-pin', 'MaterialsTemplate': 'material-pin'}
        selected = {'Controller': ref, 'Deployment': receipt['Deployment'], 'MaterialsTemplate': receipt['MaterialsTemplate']}
        core = {'provider_dependencies': [{'schema_version': 'formal-vault-provider-dependency.v1', 'workload': {'DeploymentUID': '3d254222-e5e3-491e-9556-ab74d400e074'}}],
                'database_workload': {'namespace': 'ns', 'name': 'mysql', 'uid': 'dcc73970-1bbe-4eb7-9ab6-5e9a4f4f19cd'},
                'platform_writers': [{'uid': 'business-app'}]}
        return done, receipt, selected, core

    def test_requires_observed_native_successor_and_closed_roles(self):
        args = self.fixture(); saved = copy.deepcopy(args)
        P.validate_parent(*args); self.assertEqual(args, saved)
        for case in ('pin', 'unloaded', 'granted', 'controller', 'database', 'provider', 'writer-controller', 'writer-provider', 'writer-database'):
            with self.subTest(case=case):
                done, receipt, selected, core = copy.deepcopy(self.fixture())
                if case == 'pin': done['Receipt']['SHA256'] = 'other'
                if case == 'unloaded': done['SecretLoaded'] = False
                if case == 'granted': receipt['GrantsIssued'] = True
                if case == 'controller': selected['Controller']['PodUID'] = 'stale'
                if case == 'database': core['database_workload']['uid'] = 'other'
                if case == 'provider': core['provider_dependencies'] = []
                if case == 'writer-controller': core['platform_writers'].append({'uid': selected['Controller']['DeploymentUID']})
                if case == 'writer-provider': core['platform_writers'].append({'uid': core['provider_dependencies'][0]['workload']['DeploymentUID']})
                if case == 'writer-database': core['platform_writers'].append({'uid': core['database_workload']['uid']})
                with self.assertRaises(ValueError): P.validate_parent(done, receipt, selected, core)

    def hold_fixture(self):
        core = self.fixture()[-1]
        observer = {k: 'pinned-'+k for k in ('CAFile', 'CASHA256', 'CertificateFile', 'CertificateSHA256', 'KeyFile', 'KeySHA256')}
        observer.update(Endpoints={'node': {'URL': 'https://original'}}, WholeNodeEndpoints={'node': 'whole'}, Nodes=['source'])
        core['runtime_sources'] = {'shared_runtime_observer': observer, 'runtime_test_scope': {'deferred': [4, 5, 6]}}
        pin = {'File': '/original/hold-materials.json', 'SHA256': 'pinned'}
        after = copy.deepcopy(core)
        after['runtime_sources']['longhorn_hold'] = {'Observer': {**observer, 'WholeNodeEndpoints': None, 'Nodes': None}, 'Materials': [pin]}
        return core, after, pin

    def test_accepts_only_native_longhorn_hold_addition(self):
        args = self.hold_fixture(); saved = copy.deepcopy(args)
        P.validate_core_successor(*args); self.assertEqual(args, saved)
        for case in ('scope', 'observer', 'material', 'provider', 'extra', 'existing'):
            with self.subTest(case=case):
                core, after, pin = self.hold_fixture()
                if case == 'scope': after['runtime_sources']['runtime_test_scope']['deferred'] = []
                if case == 'observer': after['runtime_sources']['longhorn_hold']['Observer']['CAFile'] = '/other'
                if case == 'material': after['runtime_sources']['longhorn_hold']['Materials'] = []
                if case == 'provider': after['provider_dependencies'] = []
                if case == 'extra': after['unexpected'] = True
                if case == 'existing': core['runtime_sources']['longhorn_hold'] = {'old': True}
                with self.assertRaises(ValueError): P.validate_core_successor(core, after, pin)

    def test_controller_readback_rejects_replacement_unready_and_spec_drift(self):
        selected = self.fixture()[2]; ref = selected['Controller']; desired = {'replicas': 1}
        objects = {'deployment': {'metadata': {'uid': ref['DeploymentUID'], 'generation': 5}, 'spec': desired,
                                 'status': {'observedGeneration': 5, 'readyReplicas': 1, 'updatedReplicas': 1}},
                   'pod': {'metadata': {'uid': ref['PodUID'], 'ownerReferences': [{'controller': True, 'kind': 'ReplicaSet', 'uid': ref['ReplicaSetUID']}]},
                           'status': {'phase': 'Running', 'containerStatuses': [{'ready': True}, {'ready': True}]}},
                   'replicaset': {'metadata': {'uid': ref['ReplicaSetUID'], 'ownerReferences': [{'controller': True, 'kind': 'Deployment', 'uid': ref['DeploymentUID']}]}},
                   'serviceaccount': {'metadata': {'uid': ref['ServiceAccountUID']}}}
        for case in ('valid', 'pod', 'rs-owner', 'account', 'unready', 'spec'):
            with self.subTest(case=case):
                values = copy.deepcopy(objects)
                if case == 'pod': values['pod']['metadata']['uid'] = 'replacement'
                if case == 'rs-owner': values['replicaset']['metadata']['ownerReferences'][0]['uid'] = 'other'
                if case == 'account': values['serviceaccount']['metadata']['uid'] = 'other'
                if case == 'unready': values['pod']['status']['containerStatuses'][0]['ready'] = False
                if case == 'spec': values['deployment']['spec']['replicas'] = 2
                site = SimpleNamespace(get=Mock(side_effect=lambda kind, name: values[kind]))
                loader = SimpleNamespace(validate_running_pod=Mock())
                if case == 'valid': self.assertEqual(P.current_controller(site, None, loader, selected, desired), values['pod'])
                else:
                    with self.assertRaises(ValueError): P.current_controller(site, None, loader, selected, desired)


if __name__ == '__main__':
    unittest.main()
