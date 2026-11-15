"""Real file/pin flow into the config author; native signing is not simulated."""
import copy
import datetime as dt
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load('system-backup-operator-deployment')
A = load('system-backup-initial-input-assembly')


class NativeFactsAssembly(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.now = dt.datetime.now(dt.timezone.utc)
        self.policy = self.write('policy.json', {'schema_version': 'system-backup-secret-capture-policy.v1',
            'registry_kind': 'secret_allowlist', 'registry_version': 'approved-secrets', 'namespace_scope': 'installation_namespace'})
        core = self.write('core.json', {'installation_id': 'installation_original', 'namespace': 'original-system', 'namespace_uid': 'namespace-uid'})
        material = self.write('material.json', {'Discovery': {'SecretPolicy': {'protocol': 'system-backup-secret-capture-policy.v1',
            'path': self.policy['File'], 'sha256': self.policy['SHA256']}}})
        self.parts = self.write('parts.json', {'SchemaVersion': 'system-backup-original-source-parts.v2', 'Installation': 'installation_original',
            'Version': 'parts-v1', 'Secrets': {'namespace': 'original-system', 'namespace_uid': 'namespace-uid'}})
        self.writers = self.write('writers.json', {'SchemaVersion': 'system-backup-original-source-writers.v2', 'Installation': 'installation_original',
            'Version': 'writers-v1', 'ApplicationScope': 'original-app'})
        self.redis = self.write('redis.json', {'SchemaVersion': 'system-backup-original-redis-sources.v1', 'Installation': 'installation_original',
            'Version': 'redis-v1', 'ApplicationScope': 'original-app'})
        self.selected = {'Version': 'original-source-registry-authoring-selection.v1', 'Deployment': core, 'MaterialsTemplate': material,
            'PartsFile': self.parts['File'], 'PartsVersion': 'parts-v1', 'SourceWritersFile': self.writers['File'], 'SourceWritersVersion': 'writers-v1',
            'RedisSourcesFile': self.redis['File'], 'RedisSourcesVersion': 'redis-v1', 'ApplicationScope': 'original-app',
            'NotBefore': (self.now - dt.timedelta(minutes=1)).isoformat(), 'Until': (self.now + dt.timedelta(minutes=20)).isoformat()}
        self.selection = self.write('selection.json', self.selected)
        self.receipt = {'Version': 'original-source-registry-facts-receipt.v1', 'SelectionSHA256': self.selection['SHA256'],
            'PartsRegistry': self.parts, 'SourceWritersRegistry': self.writers, 'NativeRegistries': {'RedisSources': self.redis, 'SecretAllowlist': self.policy}}

    def write(self, name, value):
        return M.write(self.root / name, M.encoded(value))

    def test_all_four_native_pins_become_config_refs(self):
        refs, pins = A.source_fact_selectors(M, self.receipt, self.selection, self.now)
        self.assertEqual(refs, {('parts', 'parts-v1', self.parts['SHA256']), ('source_writers', 'writers-v1', self.writers['SHA256']),
            ('redis_sources', 'redis-v1', self.redis['SHA256']), ('secret_allowlist', 'approved-secrets', self.policy['SHA256'])})
        self.assertEqual(len(pins), 7)

    def test_expired_success_is_not_reused(self):
        with self.assertRaisesRegex(M.Refused, 'source_facts_expired'):
            A.source_fact_selectors(M, self.receipt, self.selection, self.now + dt.timedelta(hours=1))

    def test_window_expires_while_reading_facts(self):
        moments = iter([self.now, self.now + dt.timedelta(hours=1)])
        class Clock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return next(moments)
        with patch.object(A.dt, 'datetime', Clock):
            with self.assertRaisesRegex(M.Refused, 'source_facts_expired_during_assembly'):
                A.source_fact_selectors(M, self.receipt, self.selection)

    def test_window_expires_before_config_author(self):
        stage = self.stage(True)
        moments = iter([self.now, self.now, self.now + dt.timedelta(hours=1)])
        class Clock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return next(moments)
        with patch.object(A.dt, 'datetime', Clock):
            with self.assertRaisesRegex(M.Refused, 'source_facts_expired_reconcile'):
                A.prepare_disabled_config(M, stage)
        self.assertEqual(self.calls, [])

    def test_foreign_selection_is_rejected(self):
        value = dict(self.receipt, SelectionSHA256='a' * 64)
        with self.assertRaisesRegex(M.Refused, 'same_native_source_facts_receipt'):
            A.source_fact_selectors(M, value, self.selection, self.now)

    def test_changed_fact_bytes_are_rejected(self):
        Path(self.redis['File']).write_bytes(b'{}')
        with self.assertRaisesRegex(M.Refused, 'producer_file_pin_changed'):
            A.source_fact_selectors(M, self.receipt, self.selection, self.now)

    def test_foreign_policy_is_rejected_even_with_valid_pin(self):
        value = copy.deepcopy(self.receipt)
        value['NativeRegistries']['SecretAllowlist'] = self.write('foreign-policy.json', {'schema_version': 'system-backup-secret-capture-policy.v1'})
        with self.assertRaisesRegex(M.Refused, 'same_original_secret_policy'):
            A.source_fact_selectors(M, value, self.selection, self.now)

    def stage(self, complete):
        directory = self.root / 'deployment'
        directory.mkdir()
        mirror = self.root / 'mirror'
        mirror.mkdir()
        M.write(directory / 'materials.result.json', M.encoded({'version': 'operator-materials-result.v1', 'host': {'PodUID': 'current'}, 'SourceSelection': self.selection}))
        M.write(directory / 'host-observer.result.json', M.encoded({'pvc_uids': {'staging': 'staging-uid'}}))
        self.write('facts-receipt.json', self.receipt)
        if complete:
            self.write('remaining-original-selectors.json', {
                'registries': [{'registry_kind': k, 'version': 'original-v1', 'sha256': 'a' * 64} for k in A.REGISTRY_KINDS
                    if k not in ('parts', 'source_writers', 'redis_sources', 'secret_allowlist')],
                'references': [{'purpose': k, 'version': 'original-v1', 'identity_hash': 'b' * 64} for k in A.REFERENCE_PURPOSES]})
        self.calls = []
        def call(label, argv):
            # Inspect the actual file passed to the native author. No test
            # receipt is used outside this mocked author boundary.
            self.calls.append((label, M.decode(M.read(argv[argv.index('--definition-file') + 1], argv[argv.index('--definition-sha256') + 1]))))
            output = self.write('native-config.json', {'fixture': True})
            return {'Version': 'original-disabled-config-authored.v1', 'AuthorityIssued': False, 'CapacityVerified': False, 'BackupReady': False, 'Config': output}, output
        return NS(a=NS(compose_source_registry_directory=self.root), directory=directory, run=self.root, prefix='original',
            runtime_mirror=lambda: mirror, check_host=lambda h: M.need(h == {'PodUID': 'current'}, 'host changed'),
            get=lambda *args: {'metadata': {'uid': 'staging-uid'}, 'status': {'phase': 'Bound', 'capacity': {'storage': '20Gi'}}},
            retain=lambda name, value: M.write(directory / name, M.encoded(value)), binary=lambda name: name, call=call)

    def test_complete_native_receipt_flows_into_config_author(self):
        result = A.prepare_disabled_config(M, self.stage(True))
        self.assertEqual(M.decode(M.pinned(result)), {'fixture': True})
        self.assertEqual(len(self.calls), 1)
        selection = self.calls[0][1]
        self.assertEqual(len(selection['Registries']), 9)
        self.assertEqual(len(selection['References']), 20)
        parts = next(x for x in selection['Registries'] if x['registry_kind'] == 'parts')
        self.assertEqual(parts['sha256'], self.parts['SHA256'])
        self.assertEqual(selection['StagingBytes'], 20 << 30)

    def test_missing_other_owners_does_not_invoke_config_author(self):
        stage = self.stage(False)
        with self.assertRaisesRegex(M.Refused, 'actual_unique_original_registry_required:failure_domains'):
            A.prepare_disabled_config(M, stage)
        self.assertEqual(self.calls, [])

    def test_changed_facts_during_capacity_check_refuse_before_author(self):
        stage = self.stage(True)
        original = stage.get
        def changed(*args):
            Path(self.redis['File']).write_bytes(b'{}')
            return original(*args)
        stage.get = changed
        with self.assertRaisesRegex(M.Refused, 'producer_file_pin_changed'):
            A.prepare_disabled_config(M, stage)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
