import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('repair', Path(__file__).with_name('repair-p2-runtime-pool-recovery.py'))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


class RecoveryReadbackTests(unittest.TestCase):
    def setUp(self):
        self.row = dict(id=3, user=1, generation=9, binding_generation=9, instance_state='running',
                        binding_state='running', pool_state='ready', draining=0, workspace_match=1,
                        pid=55, port=20000, gateway='gw-3-9', heartbeat_age=1)
        self.gateway = dict(instance_id=3, user_id=1, generation=9, gateway_id='gw-3-9',
                            gateway_pid=55, gateway_port=20000, state='running')

    def test_running_sql_is_not_enough(self):
        for key, value in [('pool_state','unhealthy'), ('binding_generation',8), ('workspace_match',0),
                           ('heartbeat_age',90), ('pid',0), ('gateway','gw-3-8'), ('draining',1)]:
            with self.subTest(key=key):
                self.assertFalse(R.coherent(dict(self.row, **{key:value})))

    def test_complete_binding_and_gateway(self):
        self.assertTrue(R.coherent(self.row))
        self.assertTrue(R.gateway_matches(self.gateway, self.row))

    def test_agent_state_must_match_actual_binding(self):
        for key, value in [('generation',8), ('gateway_pid',50), ('user_id',2), ('instance_id',1),
                           ('gateway_port',20001), ('state','stopped')]:
            with self.subTest(key=key):
                self.assertFalse(R.gateway_matches(dict(self.gateway, **{key:value}), self.row))


if __name__ == '__main__':
    unittest.main()
