import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest

HERE=Path(__file__).parent
def load(name):
    s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class CleanupTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.A=load('assemble-p2-installation-candidate');self.T=load('prepare-p2-team-attachment');self.M=load('retire-p2-team-attachment')
        self.journal=self.root/'longhorn-source-20261114-team-attachment';self.journal.mkdir()
        self.pod=self.T.manifest();self.pod['metadata'].update(uid='attachment-uid',resourceVersion='1');self.original=copy.deepcopy(self.pod)
        self.A.retain(self.journal/'team-attachment.created.private.json',self.original)
        selected=self.A.retain(self.root/'source.json',{'source':'real fixture'})
        receipt=self.A.retain(self.root/'receipt.json',{'SourceSelection':selected})
        self.A.retain(self.journal/'completed.json',{'Receipt':receipt,'SourceSelection':selected})
        r=self.A.retain(self.root/'recovery.json',{'TaskID':'task-7','Evidence':'simulated operator-reviewed original output'})
        d=self.A.retain(self.root/'retirement.json',{'TaskID':'task-7','Evidence':'simulated operator-reviewed original output'})
        self.args=NS(task_id='task-7',confirm_business_restored=True,confirm_source_disabled=True,recovery_evidence_file=r['File'],recovery_evidence_sha256=r['SHA256'],source_retirement_evidence_file=d['File'],source_retirement_evidence_sha256=d['SHA256'])
        self.dep={'metadata':{'uid':self.A.CONTROLLER_UID},'spec':{'replicas':0,'selector':{'matchLabels':{'app':'controller'}}}}
        self.controller_pods=[];self.extra=[];self.deleted=[];self.fail_after_delete=False
        self.ns={'metadata':{'uid':'tenant','labels':{'app':'clawreef','managed-by':'clawreef','user-id':'1'}}}
        self.pvc={'metadata':{'uid':self.T.PVC_UID},'spec':{'volumeName':self.T.PV,'accessModes':['ReadWriteMany']},'status':{'phase':'Bound'}}
        self.pv={'metadata':{'uid':self.T.PV_UID},'spec':{'claimRef':{'name':self.T.CLAIM,'namespace':self.T.NS,'uid':self.T.PVC_UID},'csi':{'driver':'driver.longhorn.io','volumeHandle':self.T.PV}}}
        self.L=NS(Site=lambda *args:self)
    def get(self,kind,name):self.assertEqual(kind,'deployment');return self.dep
    def call(self,args):
        if args[:2]==['get','pods']:return self.A.encode({'items':self.controller_pods})
        path=args[-1]
        if path.endswith('/pods'):return self.A.encode({'items':([self.pod] if self.pod else [])+self.extra})
        if '/persistentvolumeclaims/' in path:return self.A.encode(self.pvc)
        if '/persistentvolumes/' in path:return self.A.encode(self.pv)
        return self.A.encode(self.ns)
    def send(self,label,args,body):
        self.A.need(not (self.journal/(label+'.sent.private.json')).exists(),'already sent')
        self.A.retain(self.journal/(label+'.sent.private.json'),{'Argv':args,'InputSHA256':self.A.sha(body)})
        self.deleted.append(json.loads(body));self.pod=None
        if self.fail_after_delete:raise TimeoutError('lost deletion response')
    def run_cleanup(self):
        with contextlib.redirect_stdout(io.StringIO()):self.M.cleanup(self.A,self.L,self.T,self.journal,self.args)
    def test_uid_guard_delete_preserves_pvc_and_replay(self):
        self.run_cleanup();self.run_cleanup();self.assertEqual(len(self.deleted),1)
        self.assertEqual(self.deleted[0]['preconditions'],{'uid':'attachment-uid','resourceVersion':'1'})
        self.assertTrue((self.journal/'team-attachment.retired.json').exists())
        self.assertEqual(self.pvc['metadata']['uid'],self.T.PVC_UID)
    def test_lost_delete_response_reconciles_absence(self):
        self.fail_after_delete=True
        with self.assertRaises(TimeoutError):self.run_cleanup()
        self.fail_after_delete=False;self.run_cleanup();self.assertEqual(len(self.deleted),1)
    def test_replaced_pod_refused(self):
        self.pod['metadata']['uid']='replacement'
        with self.assertRaises(ValueError):self.run_cleanup()
        self.assertFalse(self.deleted)
    def test_controller_still_running_refused(self):
        self.dep['spec']['replicas']=1
        with self.assertRaisesRegex(ValueError,'scaled to zero'):self.run_cleanup()
        self.assertFalse(self.deleted)
    def test_controller_terminating_pod_refused(self):
        self.controller_pods=[{'metadata':{'deletionTimestamp':'now'}}]
        with self.assertRaisesRegex(ValueError,'Pods still present'):self.run_cleanup()
        self.assertFalse(self.deleted)
    def test_confirmation_and_evidence_required(self):
        self.args.confirm_business_restored=False
        with self.assertRaises(ValueError):self.run_cleanup()
        self.args.confirm_business_restored=True;self.args.recovery_evidence_sha256='0'*64
        with self.assertRaises(ValueError):self.run_cleanup()
        self.assertFalse(self.deleted)
    def test_old_attempt_cannot_delete_new_attempt_attachment(self):
        (self.root/(self.journal.name+'-2')).mkdir()
        with self.assertRaisesRegex(ValueError,'newer source attempt'):self.run_cleanup()
        self.assertFalse(self.deleted)
    def test_absence_without_deletion_record_refused(self):
        self.pod=None
        with self.assertRaisesRegex(ValueError,'without this cleanup journal'):self.run_cleanup()
    def test_pvc_replacement_refused_before_delete(self):
        self.pvc['metadata']['uid']='replacement'
        with self.assertRaises(ValueError):self.run_cleanup()
        self.assertFalse(self.deleted)

if __name__=='__main__':unittest.main()
