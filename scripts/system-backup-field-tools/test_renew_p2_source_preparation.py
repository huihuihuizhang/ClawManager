import copy
import datetime as dt
import importlib.util
from pathlib import Path, PurePosixPath
import unittest

spec = importlib.util.spec_from_file_location('renew',Path(__file__).with_name('renew-p2-source-preparation.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)

class RenewalTests(unittest.TestCase):
    def test_window_capped_by_each_real_dependency(self):
        now = dt.datetime(2026,11,12,10,tzinfo=dt.timezone.utc)
        later = now+dt.timedelta(hours=24)
        self.assertEqual(R.preparation_window(now,later,later,later)[1],now+dt.timedelta(hours=8))
        for i in range(3):
            limits = [later]*3; limits[i] = now+dt.timedelta(hours=2)
            self.assertEqual(R.preparation_window(now,*limits)[1],limits[i])
        with self.assertRaises(ValueError): R.preparation_window(now,now,later,later)

    def fixture(self):
        old = {'Purpose':'source_api','Endpoint':'https://original','Account':'uid','Credential':{'File':'/old.jwt','SHA256':'old'}}
        new = copy.deepcopy(old); new['Credential'] = {'File':'/new.jwt','SHA256':'new'}
        definition = {'Version':'original-initial-source-author-inputs.v1','Connections':[old],
            'Deployment':{'profile_file':'/old/execution-profile.json','capture_modules':{'path':'/old/capture-materials.json'}},
            'Materials':{'DeploymentConfigSHA256':'','CaptureGrantSHA256':'','Discovery':{
                'SourceAPI':{'token_file':'/old.jwt'},'SourceAPITokenSHA256':'old'}},'Other':{'preserve':True}}
        now = dt.datetime(2026,11,12,10,tzinfo=dt.timezone.utc)
        return definition,old,new,PurePosixPath('/old'),PurePosixPath('/new'),now,now+dt.timedelta(hours=8)

    def test_successor_preserves_old_material_and_unrelated_fields(self):
        args = self.fixture(); before = copy.deepcopy(args)
        out = R.successor_definition(*args)
        self.assertEqual(args,before)
        self.assertEqual(out['Other'],args[0]['Other'])
        self.assertEqual(out['Deployment']['profile_file'],'/new/execution-profile.json')
        self.assertEqual(out['Materials']['Discovery']['SourceAPITokenSHA256'],'new')

    def test_identity_change_or_already_issued_template_refused(self):
        for case in range(4):
            args = self.fixture()
            if case == 0: args[2]['Account'] = 'foreign'
            if case == 1: args[2]['Credential'] = args[1]['Credential']
            if case == 2: args[0]['Materials']['CaptureGrantSHA256'] = 'issued'
            if case == 3: args[0]['Deployment']['profile_file'] = '/other/profile'
            with self.assertRaises(ValueError): R.successor_definition(*args)

if __name__ == '__main__': unittest.main()
