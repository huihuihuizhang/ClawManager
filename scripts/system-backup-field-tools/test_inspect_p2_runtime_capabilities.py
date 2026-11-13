import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('runtime_caps', Path(__file__).with_name('inspect-p2-runtime-capabilities.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)


class CapabilityDiagnosticTests(unittest.TestCase):
    def fixture(self):
        row = {'namespace': 'source', 'pod_uid': 'original-pod', 'port': 20000}
        caps = {'protocol': 'isolated-backup.v1', 'confirmation_scope': 'instance_pid_namespaces_and_mounts',
                'namespace': row['namespace'], 'pod_uid': row['pod_uid'], 'gateway_port': row['port'],
                'agent_epoch': '1'*32, 'slot': 'private-slot', 'supported': True, 'durable_reservation': True,
                'agent_restart_reconciliation': False, 'recovery_scope': 'original_operation_same_agent_epoch',
                'agent_restart_policy': 'quarantine_active_reservation'}
        return row, caps

    def test_supported_response_is_reported_without_raw_identity(self):
        row, caps = self.fixture()
        summary = R.capability_summary(json.dumps(caps).encode(), row)
        self.assertEqual(summary['MissingFields'], [])
        self.assertEqual(summary['UnknownFieldCount'], 0)
        self.assertTrue(all(v for v in summary.values() if type(v) is bool))
        text = json.dumps(summary)
        for secret in ('private-slot', 'original-pod', '1'*32):
            self.assertNotIn(secret, text)

    def test_unknown_fields_are_counted_without_disclosure(self):
        row, caps = self.fixture(); caps['private-field-name'] = 'private-value'
        summary = R.capability_summary(json.dumps(caps).encode(), row)
        self.assertEqual(summary['UnknownFieldCount'], 1)
        self.assertNotIn('private', json.dumps(summary))

    def test_wrong_types_identity_and_capabilities_remain_visible(self):
        row, caps = self.fixture()
        for field, value, check in [('protocol', 'old', 'ProtocolMatches'), ('supported', False, 'Supported'),
                ('durable_reservation', False, 'DurableReservation'), ('pod_uid', 'replacement', 'PodUIDMatches'),
                ('gateway_port', '20000', 'GatewayPortMatches'), ('gateway_port', True, 'TypesMatch'),
                ('agent_epoch', 'A'*32, 'EpochValid'), ('slot', '', 'SlotPresent'),
                ('agent_restart_reconciliation', True, 'RestartReconciliationFalse')]:
            with self.subTest(field=field):
                self.assertFalse(R.capability_summary(json.dumps({**caps, field: value}).encode(), row)[check])

    def test_malformed_and_duplicate_payloads_are_not_reported_as_valid(self):
        row, _ = self.fixture()
        for raw in (b'', b'{}{}', b'{"protocol":"a","protocol":"b"}', b'\xff'):
            self.assertEqual(R.capability_summary(raw, row), {'JSONValid': False})
        self.assertEqual(R.capability_summary(b'[]', row), {'JSONValid': True, 'Object': False})

    def test_missing_fields_are_reported(self):
        row, _ = self.fixture()
        summary = R.capability_summary(b'{}', row)
        self.assertIn('protocol', summary['MissingFields'])
        self.assertFalse(summary['Supported'])
        self.assertFalse(summary['EpochValid'])


if __name__ == '__main__':
    unittest.main()
