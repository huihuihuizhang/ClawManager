import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('roles', Path(__file__).with_name('repair-p2-source-roles.py'))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


class SourceRoleTests(unittest.TestCase):
    def fixture(self):
        roles = [{'Name': name, 'UID': name + '-uid', 'Role': role} for name, role in
                 [('controller', 'writer'), ('app', 'writer'), ('vault', 'provider-dependency'),
                  ('mysql', 'database'), ('agent', 'agent')]]
        refs = lambda names: [{'namespace': 'ns', 'name': n, 'uid': n + '-uid'} for n in names]
        original = {'Deployment': {'namespace': 'ns', 'controller_owner': 'controller-uid',
                    'platform_writers': refs(['controller', 'app', 'vault']),
                    'runtime_sources': {'deployments': refs(['agent'])}},
                    'Materials': {'Discovery': {'ControllerDeployment': 'controller', 'ControllerDeploymentUID': 'controller-uid'}},
                    'Until': 'unchanged', 'Connections': ['unchanged']}
        selected = {'Deployments': roles, 'PreAdoptionVaultDependencies': [{'Workload': {'Deployment': 'vault', 'DeploymentUID': 'vault-uid'}}]}
        controller = {'Namespace': 'ns', 'Deployment': 'controller', 'DeploymentUID': 'controller-uid'}
        return original, selected, controller

    def test_only_roles_change_without_mutating_parent(self):
        original, selected, controller = self.fixture()
        before = copy.deepcopy(original)
        successor = R.reconcile(original, selected, controller)
        self.assertEqual(original, before)
        self.assertEqual([w['name'] for w in successor['Deployment']['platform_writers']], ['app', 'vault'])
        self.assertEqual(successor['Deployment']['database_workload'], {'namespace': 'ns', 'name': 'mysql', 'uid': 'mysql-uid'})
        successor['Deployment'].pop('database_workload')
        successor['Deployment']['platform_writers'] = original['Deployment']['platform_writers']
        self.assertEqual(successor, original)

    def test_rejects_missing_unknown_duplicate_and_replaced_workloads(self):
        for fault in ['unknown', 'duplicate', 'missing', 'replaced-controller', 'replaced-database', 'agent', 'provider', 'issued-stage']:
            with self.subTest(fault=fault):
                original, selected, controller = self.fixture()
                if fault == 'unknown': selected['Deployments'].append({'Name': 'x', 'UID': 'x-uid', 'Role': 'unknown'})
                if fault == 'duplicate': selected['Deployments'].append(selected['Deployments'][0])
                if fault == 'missing': original['Deployment']['platform_writers'].pop()
                if fault == 'replaced-controller': controller['DeploymentUID'] = 'other'
                if fault == 'replaced-database': selected['Deployments'][3]['UID'] = 'controller-uid'
                if fault == 'agent': original['Deployment']['runtime_sources']['deployments'] = []
                if fault == 'provider': selected['PreAdoptionVaultDependencies'][0]['Workload']['DeploymentUID'] = 'other'
                if fault == 'issued-stage': original['Deployment']['provider_dependencies'] = ['existing']
                with self.assertRaises(ValueError): R.reconcile(original, selected, controller)


if __name__ == '__main__':
    unittest.main()
