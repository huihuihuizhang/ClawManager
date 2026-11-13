import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('renew',Path(__file__).with_name('renew-p2-runtime-scope-nov13.py'))
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)

class ScopeRenewalTests(unittest.TestCase):
    def fixture(self):
        scope={'Version':'explicit-running-tenant-runtime-test-scope.v3','InstallationID':'installation','ServerUUID':'server',
            'Database':'business','NamespaceUID':'namespace','Deferred':[{'ID':n,'Generation':1} for n in [4,5,6]],'OriginalInstancesSHA256':'old'}
        original={'Deployment':{'runtime_sources':{'runtime_test_scope':scope}},'Other':'preserve'}
        data={'RuntimeTestScope':dict(copy.deepcopy(scope),OriginalInstancesSHA256='new'),
            'Instances':[{'ID':n,'Status':'running' if n in [1,2,3,7,8] else 'error'} for n in range(1,9)]}
        return original,data

    def test_only_scope_changes_and_parent_preserved(self):
        original,data=self.fixture();before=copy.deepcopy(original)
        result=R.replace_scope(original,data)
        self.assertEqual(original,before)
        self.assertEqual(result['Other'],'preserve')
        self.assertEqual(result['Deployment']['runtime_sources']['runtime_test_scope'],data['RuntimeTestScope'])

    def test_identity_and_deferred_changes_refused(self):
        for key in ['Version','InstallationID','ServerUUID','Database','NamespaceUID','Deferred']:
            original,data=self.fixture();data['RuntimeTestScope'][key]='changed'
            with self.assertRaises(ValueError):R.replace_scope(original,data)

    def test_new_instance_or_running_roster_change_refused(self):
        for case in range(3):
            original,data=self.fixture()
            if case==0:data['Instances'].append({'ID':9,'Status':'running'})
            if case==1:data['Instances'][0]['Status']='error'
            if case==2:data['RuntimeTestScope']['OriginalInstancesSHA256']='old'
            with self.assertRaises(ValueError):R.replace_scope(original,data)

if __name__=='__main__':unittest.main()
