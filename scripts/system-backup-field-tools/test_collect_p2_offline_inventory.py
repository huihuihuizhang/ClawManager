import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('offline_inventory', Path(__file__).with_name('collect-p2-offline-inventory.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RedactedFieldExport(unittest.TestCase):
    def test_secret_and_configmap_bytes_never_enter_export(self):
        for kind in ('Secret', 'ConfigMap'):
            value = dict(kind=kind, metadata=dict(name='selected', annotations={'kubectl.kubernetes.io/last-applied-configuration':'private-value'}),
                         data={'password':'private-value'}, stringData={'token':'private-value'})
            raw = json.dumps(m.redact(value))
            self.assertNotIn('private-value', raw)
            self.assertIn('data_keys', raw)

    def test_nested_workload_hides_literal_credentials_and_shell_arguments(self):
        value = dict(spec=dict(template=dict(spec=dict(containers=[dict(name='app', env=[dict(name='API_KEY',value='private-key'),
            dict(name='SYSTEM_BACKUP_SQL_GATE_SCOPE',value='installation')], command=['/bin/sh','-c','export PASSWORD=private-key'],
            args=['--token','private-key'])]))))
        raw = json.dumps(m.redact(value))
        self.assertNotIn('private-key', raw)
        self.assertIn('installation', raw)
        self.assertIn('/bin/sh', raw)
        self.assertIn('argument_count', raw)

    def test_status_messages_and_private_annotations_are_removed_recursively(self):
        raw = json.dumps(m.redact(dict(items=[dict(status=dict(message='credential-in-error'),metadata=dict(annotations={'key':'credential-in-error'}))])))
        self.assertNotIn('credential-in-error', raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
