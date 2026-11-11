import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

file = Path(__file__).with_name('settle-p2-redis-rwo-rollout.py')
spec = importlib.util.spec_from_file_location('field_redis_rwo_settle', file)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OriginalRWORollout(unittest.TestCase):
    def setUp(self):
        self.original = {'replicas': 1, 'strategy': {'type': 'RollingUpdate',
            'rollingUpdate': {'maxSurge': '25%', 'maxUnavailable': '25%'}},
            'template': {'spec': {'containers': [{'name': 'redis', 'image': 'original@sha256:fixed',
                'args': ['redis-server', '--appendonly', 'yes', '--tls-port', '6380']}],
                'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'actual-original-data'}}]}}}

    def test_temporary_strategy_preserves_exact_template_and_original(self):
        before = copy.deepcopy(self.original)
        selected = m.selected_recreate(self.original, before)
        self.assertEqual(selected['strategy'], {'type': 'Recreate'})
        self.assertEqual(selected['template'], before['template'])
        self.assertEqual(self.original, before)

    def test_native_spec_hash_preserves_typed_field_order_and_go_escaping(self):
        value = {'volumeName': 'original<&>', 'accessModes': ['ReadWriteOnce']}
        raw = b'{"volumeName":"original\\u003c\\u0026\\u003e","accessModes":["ReadWriteOnce"]}'
        self.assertEqual(m.go_api_spec_sha(value), hashlib.sha256(raw).hexdigest())
        self.assertNotEqual(m.go_api_spec_sha(value), m.go_api_spec_sha(dict(reversed(list(value.items())))))

    def test_foreign_image_args_or_volume_refuses_compensation(self):
        for mode in ['image', 'args', 'claim']:
            value = copy.deepcopy(self.original)
            if mode == 'claim':
                value['template']['spec']['volumes'][0]['persistentVolumeClaim']['claimName'] = 'other-data'
            else:
                value['template']['spec']['containers'][0][mode] = 'other'
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                m.selected_recreate(value, self.original)

    def test_multiple_replicas_or_different_strategy_refuses(self):
        for value in [dict(self.original, replicas=2), dict(self.original, strategy={'type': 'Recreate'})]:
            with self.assertRaises(RuntimeError):
                m.selected_recreate(value, value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
