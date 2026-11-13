import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('wiring', Path(__file__).with_name('inspect-p2-app-backup-wiring.py'))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


class InstallerReadTests(unittest.TestCase):
    def setUp(self):
        self.connection = {'Endpoint': 'mysql+tls://db.example:3306', 'Database': 'app',
                           'ServerUUID': 'original-server', 'Account': 'participant@%'}
        self.operation = {'Address': 'db.example:3306', 'Database': 'app', 'ServerUUID': 'original-server',
                          'Accounts': [{'Role': 'control_sql', 'User': 'participant', 'Host': '%'},
                          {'Role': 'installer', 'User': 'installer', 'Host': '%', 'Password': 'private-fixture',
                           'Locked': False, 'Privileges': [{'Kind': 'table', 'Object': t, 'Verb': 'SELECT'} for t in W.TABLES]}]}

    def test_metadata_account_is_not_participant_observer(self):
        self.assertEqual(W.installer_credentials(self.operation, self.connection), ('installer', 'private-fixture', 'installer@%'))

    def test_wrong_database_server_or_address_refused(self):
        for key in ('Database', 'ServerUUID', 'Address'):
            with self.subTest(key=key):
                value = copy.deepcopy(self.operation)
                value[key] = 'different'
                with self.assertRaises(ValueError): W.installer_credentials(value, self.connection)

    def test_missing_or_ambiguous_role_refused(self):
        for roles in [self.operation['Accounts'][:1], self.operation['Accounts'] * 2]:
            value = dict(self.operation, Accounts=roles)
            with self.assertRaises(ValueError): W.installer_credentials(value, self.connection)

    def test_locked_root_wrong_privileges_and_line_break_refused(self):
        for change in ({'Locked': True}, {'User': 'root'}, {'Privileges': []},
                       {'User': 'participant'}, {'Password': 'private\nvalue'}):
            with self.subTest(change=list(change)):
                value = copy.deepcopy(self.operation)
                value['Accounts'][1].update(change)
                with self.assertRaises(ValueError): W.installer_credentials(value, self.connection)

    def test_observer_identity_mismatch_refused(self):
        value = dict(self.connection, Account='different@%')
        with self.assertRaises(ValueError): W.installer_credentials(self.operation, value)


if __name__ == '__main__':
    unittest.main()
