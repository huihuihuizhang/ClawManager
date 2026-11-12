import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('longhorn',Path(__file__).with_name('prepare-p2-longhorn-source.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)

class LonghornPreparationTests(unittest.TestCase):
    def classes(self):
        return ({'metadata':{'name':'sbk-validation-longhorn-local','uid':'f28ccd84-5689-4c56-a25c-5ba1b1d2e24e'},
                 'driver':'driver.longhorn.io','deletionPolicy':'Delete','parameters':{'type':'snap'}},
                {'metadata':{'name':'longhorn','uid':'9086f7e9-1213-485e-9ec2-3e5de93f908a'},
                 'provisioner':'driver.longhorn.io','parameters':{'fsType':'ext4'},'volumeBindingMode':'Immediate','reclaimPolicy':'Delete'})

    def test_only_actual_selected_classes(self):
        args = self.classes(); before = copy.deepcopy(args)
        out = R.storage_selection(*args)
        self.assertEqual(args,before)
        self.assertEqual(out['Layouts'],[])
        self.assertTrue(out['AuthorLonghornHold'])
        for case in range(4):
            s,c = self.classes()
            if case == 0: s['metadata']['uid'] = 'replaced'
            if case == 1: s['parameters']['type'] = 'bak'
            if case == 2: c['parameters']['fsType'] = 'xfs'
            if case == 3: c['provisioner'] = 'foreign'
            with self.assertRaises(ValueError): R.storage_selection(s,c)

    def test_successor_preserves_window_and_connection_binding(self):
        parent = {'Deployment':{'SHA256':'old'},'MaterialsTemplate':{'SHA256':'old'},'Until':'unchanged','Connections':['original']}
        receipt = {'Version':'original-instance-mount-materials-receipt.v1','Deployment':{'SHA256':'new'},'MaterialsTemplate':{'SHA256':'new-material'}}
        selected = dict(parent,Deployment=receipt['Deployment'],MaterialsTemplate=receipt['MaterialsTemplate'])
        material = {'DeploymentConfigSHA256':'new'}
        R.validate_successor(parent,selected,receipt,material)
        for key,value in [('Until','extended'),('Connections',['other']),('Deployment',{'SHA256':'old'})]:
            with self.assertRaises(ValueError): R.validate_successor(parent,dict(selected,**{key:value}),receipt,material)
        with self.assertRaises(ValueError): R.validate_successor(parent,selected,receipt,{'DeploymentConfigSHA256':'old'})

if __name__ == '__main__': unittest.main()
