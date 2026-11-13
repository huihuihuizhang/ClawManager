import copy
import importlib.util
from pathlib import Path
import unittest
import json
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('longhorn',Path(__file__).with_name('prepare-p2-longhorn-source.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)

class LonghornPreparationTests(unittest.TestCase):
    def release_pod(self):
        name = 'sbk-app-tls-release-4e4c205c283a0486'
        return {'metadata':{'name':name,'namespace':'clawmanager-sbk-validation-system',
            'uid':'b1c9882d-4017-4f5b-90a7-69bcbad8732e','resourceVersion':'123'},
            'spec':{'containers':[{'name':'release','image':'10.130.14.23:5000/clawmanager@sha256:ae64fd8a1c0fd825c44722107894a0d60ce428e0daf5a66e9b2064d5b3c4335e'}],
                    'volumes':[{'persistentVolumeClaim':{'claimName':name}}]},
            'status':{'phase':'Succeeded','containerStatuses':[{'name':'release','state':{'terminated':{'exitCode':0}}}]}}

    def test_release_cleanup_refuses_changed_or_live_pod(self):
        R.release_pod_identity(self.release_pod())
        for case in range(7):
            pod = self.release_pod()
            if case == 0: pod['metadata']['uid'] = 'replacement'
            if case == 1: pod['metadata']['ownerReferences'] = [{'uid':'owner'}]
            if case == 2: pod['status']['phase'] = 'Running'
            if case == 3: pod['spec']['containers'][0]['image'] = 'other'
            if case == 4: pod['status']['containerStatuses'][0]['state']['terminated']['exitCode'] = 1
            if case == 5: pod['spec']['volumes'][0]['persistentVolumeClaim']['claimName'] = 'other'
            if case == 6: pod['metadata']['deletionTimestamp'] = 'now'
            with self.assertRaises(ValueError): R.release_pod_identity(pod)

    def test_cleanup_only_deletes_pod_with_uid_and_version_preconditions(self):
        pod = self.release_pod(); site, assembly, records = Mock(), Mock(), Mock()
        records.__truediv__ = Mock(return_value=Mock())
        records.__truediv__.return_value.exists.return_value = False
        site.call.side_effect = [json.dumps(pod).encode(),b'{}',b'',b'']
        site.get.return_value = {'metadata':{'uid':'retained-pvc'},'spec':{'volumeName':'retained-pv'}}
        R.cleanup_release_pod(site,records,assembly)
        delete = site.call.call_args_list[1]
        self.assertEqual(delete.args[0][0],'delete')
        self.assertEqual(delete.args[1]['preconditions'],{'uid':pod['metadata']['uid'],'resourceVersion':'123'})
        self.assertTrue(delete.args[0][2].endswith('/pods/'+pod['metadata']['name']))
        self.assertEqual(site.get.call_count,2)
        self.assertTrue(all(c.args[0]=='pvc' for c in site.get.call_args_list))

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
