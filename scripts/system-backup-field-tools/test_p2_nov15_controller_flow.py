"""Offline orchestration only; fake API replies are never field evidence."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class ControllerFlowTest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.a=load('assemble-p2-installation-candidate');self.m=load('load-p2-nov15-controller');self.m.__file__=str(self.root/'load-p2-nov15-controller.py')
        self.events=[];self.sends=[];self.unknown=False
        self.old={'template':{'spec':{'containers':[{'image':'old'}]}}};self.desired={'template':{'spec':{'containers':[{'image':'new'}]}}}
        self.current={'metadata':{'name':'controller','uid':'uid','resourceVersion':'1'},'spec':copy.deepcopy(self.old)}
        self.secret={'metadata':{'name':'provider'}};self.controller={'Deployment':'controller','DeploymentUID':'uid','Pod':'new'}
        self.build={'SourceRevision':'revision','Binaries':{'tool':{'SHA256':'tool-sha'}}};self.save(self.root/'BUILD_RECEIPT.json',self.build)
        prior=self.root/'p2-team-credential-renewal-20261115';(prior/'mint').mkdir(parents=True)
        self.save(prior/'loaded.json',{'Controller':self.controller});self.save(prior/'delivery-plan.private.json',{'DesiredSpec':self.save(self.root/'old.json',self.old),'Secret':self.save(self.root/'secret.json',self.secret)})
        token=self.save(self.root/'token',b'token');native={'TokenFile':token['File'],'TokenSHA256':token['SHA256']};self.token_sha=token['SHA256']
        self.save(prior/'mint/native.receipt.private.json',{'Observer':self.save(self.root/'observer.json',native),'Workload':{}})
        parent=self.root/'parent';parent.mkdir();self.save(parent/'completed.json',{'Definition':self.save(self.root/'definition.json',{})})
        self.site=NS(get=lambda kind,name:copy.deepcopy(self.current if kind=='deployment' else self.secret),call=self.call,send=self.send)
        c=NS(ROOT=self.root,renewed_credentials=lambda a:[{'NotAfter':'2099-01-01T00:00:00Z'}],approved_secret_scope=Mock(),controller_ref=lambda *a:(self.controller,{}))
        self.l=NS(Site=lambda *a:self.site,verify_secret=Mock(),verify_metadata=lambda *a:self.events.append('credentials'),MOUNT='/provider')
        self.q=NS(linked_release=Mock(),registry_and_space=lambda *a:self.events.append('registry-space'))
        self.o=NS(TOOLS=('tool',),build_image=Mock(side_effect=self.build_image))
        p=NS(rotation_delivery=lambda *a:(self.secret,self.desired,[{}, {'value':'1'}, {}, {'value':self.desired}],'observer-sha'))
        modules=dict(zip(('assemble-p2-installation-candidate','continue-p2-nov14','load-p2-formal-vault','p2-nov14-delivery','p2-vault-local-forward','preflight-p2-team-continuation','build-p2-controller-overlay','resume-p2-recovered-source','resume-p2-tenant-team-source'),(self.a,c,self.l,p,NS(),self.q,self.o,NS(),NS(PARENT=parent))))
        self.m.load=lambda n:modules[n]
        self.m.renew_relay=Mock()
    def save(self,p,v):return self.a.retain(p,v)
    def build_image(self,*args):
        self.assertEqual(self.events[-2:],['credentials','registry-space']);self.events.append('image')
        return {'SourceRevision':'revision','Binaries':self.build['Binaries'],'Image':'new'}
    def call(self,argv,*args,**kwargs):
        if '--dry-run=server' in argv:return json.dumps({'spec':self.desired}).encode()
        if argv[0]=='get':return json.dumps(self.secret).encode()
        if argv[0]=='exec':
            path=argv[-1]
            if 'sha256sum' in argv:return ('tool-sha  '+path).encode()
            digest='observer-sha' if path.endswith('observer.json') else self.token_sha
            return ('600 65532\n'+digest+'  '+path+'\n').encode()
        return b''
    def send(self,label,*args):
        self.sends.append(label);self.current['spec']=copy.deepcopy(self.desired)
        if self.unknown:self.unknown=False;raise ValueError('response unknown')
        return b''
    def run_flow(self):
        with patch.dict('sys.modules',{'fcntl':NS(flock=lambda *a:None,LOCK_EX=1,LOCK_NB=2)}),redirect_stdout(io.StringIO()):self.m.run()
    def test_full_flow_and_replay_read_back_existing_delivery(self):
        self.run_flow();self.assertEqual(self.sends,['controller-update'])
        self.m.renew_relay.assert_called_once()
        journal=self.root/'controller-secret-scope-20261115';self.assertTrue((journal/'loaded.json').exists());self.assertTrue((journal/'mint/native.receipt.private.json').exists())
        self.run_flow();self.assertEqual(self.sends,['controller-update'])
    def test_unknown_patch_result_resumes_by_actual_spec_without_repatch(self):
        self.unknown=True
        with self.assertRaisesRegex(ValueError,'response unknown'):self.run_flow()
        self.run_flow();self.assertEqual(self.sends,['controller-update'])
    def test_credential_failure_prevents_image_and_deployment(self):
        self.l.verify_metadata=Mock(side_effect=ValueError('expired'))
        with self.assertRaisesRegex(ValueError,'expired'):self.run_flow()
        self.o.build_image.assert_not_called();self.assertEqual(self.sends,[])

if __name__=='__main__':unittest.main()
