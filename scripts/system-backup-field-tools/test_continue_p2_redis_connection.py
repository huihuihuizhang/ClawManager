import copy
import importlib.util
from pathlib import Path
import unittest

file = Path(__file__).with_name('continue-p2-redis-connection.py')
spec = importlib.util.spec_from_file_location('field_redis_connection', file)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ActualRedisSourceSelection(unittest.TestCase):
    def setUp(self):
        self.ns = 'clawmanager-sbk-validation-system'
        self.service = {'metadata': {'name': 'clawmanager-team-redis', 'namespace': self.ns},
            'spec': {'clusterIP': '10.0.0.12', 'selector': {'app': 'original-redis'}, 'ports': [{'port': 6379}]}}

    def test_loaded_source_preserves_real_nondefault_database(self):
        service, database = m.redis_service([self.service], 'redis://private:never-print@clawmanager-team-redis.' + self.ns + '.svc:6379/7', self.ns)
        self.assertIs(service, self.service)
        self.assertEqual(database, 7)

    def test_missing_service_does_not_select_any_available_redis(self):
        with self.assertRaisesRegex(RuntimeError, 'one actual original Redis Service'):
            m.redis_service([self.service], 'redis://different-service:6379/0', self.ns)

    def test_shared_address_is_not_unique_service_identity(self):
        other = copy.deepcopy(self.service)
        other['metadata']['name'] = 'other-redis'
        with self.assertRaises(RuntimeError):
            m.redis_service([self.service, other], 'redis://10.0.0.12:6379/0', self.ns)

    def test_unknown_existing_tls_requires_its_existing_owner(self):
        with self.assertRaisesRegex(RuntimeError, 'actual existing plain Redis source'):
            m.redis_service([self.service], 'rediss://clawmanager-team-redis:6380/0', self.ns)

    def test_invalid_database_and_extra_transport_options_refused(self):
        for value in ['redis://clawmanager-team-redis/65536', 'redis://clawmanager-team-redis/not-a-db',
            'redis://clawmanager-team-redis/0?insecure=true', 'redis://clawmanager-team-redis/0#other']:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                m.redis_service([self.service], value, self.ns)

    def test_empty_selector_cannot_select_a_native_process(self):
        self.service['spec']['selector'] = {}
        with self.assertRaises(RuntimeError):
            m.redis_service([self.service], 'redis://clawmanager-team-redis:6379', self.ns)


if __name__ == '__main__':
    unittest.main(verbosity=2)
