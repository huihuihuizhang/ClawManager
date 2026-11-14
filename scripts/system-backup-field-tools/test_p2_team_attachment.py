import importlib.util
import unittest
import copy
import json
from unittest.mock import MagicMock
from pathlib import Path

path=Path(__file__).with_name('prepare-p2-team-attachment.py')
spec=importlib.util.spec_from_file_location('attachment',path)
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class AttachmentTest(unittest.TestCase):
    def test_full_master_does_not_block_node1_with_two_slots(self):
        node={'metadata':{'name':'node1'},'status':{'allocatable':{'pods':'110'}}}
        pods=[{'spec':{'nodeName':n},'status':{'phase':'Running'}} for n,count in [('k8s-master',110),('node1',108)] for _ in range(count)]
        M.check_attachment_capacity(node,pods)
        pods.append({'spec':{'nodeName':'node1'},'status':{'phase':'Running'}})
        with self.assertRaisesRegex(ValueError,'node1 Pod capacity'):M.check_attachment_capacity(node,pods)
    def test_terminal_pods_do_not_consume_attachment_capacity(self):
        node={'metadata':{'name':'node1'},'status':{'allocatable':{'pods':'2'}}}
        M.check_attachment_capacity(node,[{'spec':{'nodeName':'node1'},'status':{'phase':s}} for s in ('Succeeded','Failed')])
        node['metadata']['name']='k8s-master'
        with self.assertRaisesRegex(ValueError,'exact attachment node'):M.check_attachment_capacity(node,[])
    def test_manifest_is_read_only_and_has_no_identity_token(self):
        p=M.manifest()['spec']; c=p['containers'][0]
        self.assertFalse(p['automountServiceAccountToken'])
        self.assertTrue(p['volumes'][0]['persistentVolumeClaim']['readOnly'])
        self.assertTrue(c['volumeMounts'][0]['readOnly'])
        self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(c['securityContext']['capabilities'],{'drop':['ALL']})
        self.assertNotIn('initContainers',p)
        self.assertNotIn('securityContext',p) # no fsGroup permission rewrite
        self.assertIn('@sha256:',c['image'])
    def test_admission_rejects_injected_sidecar(self):
        actual=M.manifest(); actual["spec"]["containers"].append(dict(actual["spec"]["containers"][0]))
        with self.assertRaises(ValueError): M.check_admission(actual,M.manifest())
    def test_admission_rejects_token(self):
        actual=M.manifest(); actual["spec"]["automountServiceAccountToken"]=True
        with self.assertRaises(ValueError): M.check_admission(actual,M.manifest())
    def test_admission_accepts_exact_manifest(self): M.check_admission(M.manifest(),M.manifest())
    def test_paginated_census_refuses_before_mutation(self):
        with self.assertRaises(ValueError): M.complete_items({'metadata':{'continue':'next'},'items':[]})
        with self.assertRaises(ValueError): M.complete_items({'metadata':{}})
        self.assertEqual(M.complete_items({'metadata':{},'items':[]}),[])
    def test_recorded_attachment_rejects_replacement_and_foreign_coordinates(self):
        original=M.manifest();original['metadata']['uid']='original'
        M.check_recorded_attachment(copy.deepcopy(original),original)
        for key,value in [('uid','replaced'),('namespace','other'),('name','other')]:
            current=copy.deepcopy(original);current['metadata'][key]=value
            with self.assertRaises(ValueError): M.check_recorded_attachment(current,original)
    def test_recorded_attachment_rejects_new_owner_or_finalizer(self):
        original=M.manifest();original['metadata']['uid']='original'
        for key,value in [('ownerReferences',[{'uid':'foreign'}]),('finalizers',['foreign'])]:
            current=copy.deepcopy(original);current['metadata'][key]=value
            with self.assertRaises(ValueError): M.check_recorded_attachment(current,original)
    def test_recorded_attachment_rejects_same_spec_with_writable_volume(self):
        original=M.manifest();original['metadata']['uid']='original'
        original['spec']['volumes'][0]['persistentVolumeClaim']['readOnly']=False
        with self.assertRaises(ValueError): M.check_recorded_attachment(copy.deepcopy(original),original)
    def test_rollback_rejects_success_and_unknown_native_outcome(self):
        for complete,sent,exited,code in [(True,True,True,1),(False,True,False,1),(False,True,True,0)]:
            paths={}
            for name,exists in [('completed.json',complete),('native.sent.private.json',sent),('native.exit.json',exited)]:
                f=MagicMock();f.exists.return_value=exists;paths[name]=f
            paths['native.exit.json'].read_bytes.return_value=json.dumps({'ExitCode':code}).encode()
            journal=MagicMock();journal.__truediv__.side_effect=paths.__getitem__
            A=MagicMock();A.decode.side_effect=json.loads
            with self.assertRaises(ValueError): M.rollback_native_output(journal,A)
    def test_rollback_allows_pre_native_failure(self):
        f=MagicMock();f.exists.return_value=False
        journal=MagicMock();journal.__truediv__.return_value=f
        M.rollback_native_output(journal,MagicMock())
    def binding(self):
        return ({'metadata':{'uid':'ns','labels':{'app':'clawreef','managed-by':'clawreef','user-id':'1'}}},
                {'metadata':{'uid':M.PVC_UID},'spec':{'volumeName':M.PV,'accessModes':['ReadWriteMany']},'status':{'phase':'Bound'}},
                {'metadata':{'uid':M.PV_UID},'spec':{'claimRef':{'name':M.CLAIM,'namespace':M.NS,'uid':M.PVC_UID},'csi':{'driver':'driver.longhorn.io','volumeHandle':M.PV}}})
    def test_exact_binding(self): M.check_binding(*self.binding())
    def test_replaced_claim(self):
        ns,pvc,pv=self.binding();pvc['metadata']['uid']='replacement'
        with self.assertRaises(ValueError): M.check_binding(ns,pvc,pv)
    def test_other_namespace(self):
        ns,pvc,pv=self.binding();pv['spec']['claimRef']['namespace']='other'
        with self.assertRaises(ValueError): M.check_binding(ns,pvc,pv)
    def test_other_handle(self):
        ns,pvc,pv=self.binding();pv['spec']['csi']['volumeHandle']='other'
        with self.assertRaises(ValueError): M.check_binding(ns,pvc,pv)
    def test_rwo_refused(self):
        ns,pvc,pv=self.binding();pvc['spec']['accessModes']=['ReadWriteOnce']
        with self.assertRaises(ValueError): M.check_binding(ns,pvc,pv)
if __name__=='__main__': unittest.main()
