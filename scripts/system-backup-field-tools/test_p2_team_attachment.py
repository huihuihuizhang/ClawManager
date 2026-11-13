import importlib.util
import unittest
from pathlib import Path

path=Path(__file__).with_name('prepare-p2-team-attachment.py')
spec=importlib.util.spec_from_file_location('attachment',path)
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class AttachmentTest(unittest.TestCase):
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
