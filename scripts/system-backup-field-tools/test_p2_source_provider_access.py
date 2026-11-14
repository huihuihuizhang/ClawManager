import base64
import copy
import importlib.util
from pathlib import Path
import unittest

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

class ProviderTransportTest(unittest.TestCase):
    def setUp(self):
        self.M=load('p2-source-provider-access');self.A=load('assemble-p2-installation-candidate')
        self.token=b'existing-metadata-only-token'
        self.observer={'Endpoint':'https://vault.'+self.A.NS+'.svc:8200','IdentityMode':'metadata-only','TokenFile':self.M.MOUNT+'/token','TokenSHA256':self.A.sha(self.token)}
        self.raw=self.A.encode(self.observer)
        self.dep={'workload':{'Service':'vault'},'observer':{'File':self.M.MOUNT+'/observer.json','SHA256':self.A.sha(self.raw)}}
        self.secret={'immutable':True,'data':{'observer.json':base64.b64encode(self.raw).decode(),'token':base64.b64encode(self.token).decode()}}
    def test_exact_materials_preserve_original_endpoint_and_bytes(self):
        original=copy.deepcopy((self.dep,self.secret))
        self.assertEqual(self.M.inputs(self.A,self.dep,self.secret),(self.observer,self.raw,self.token))
        self.assertEqual((self.dep,self.secret),original)
    def test_scope_identity_token_and_endpoint_drift_refused(self):
        for fault in ('path','digest','token','mutable','foreign-service','plaintext'):
            with self.subTest(fault=fault):
                dep,secret=copy.deepcopy((self.dep,self.secret))
                if fault=='path':dep['observer']['File']='/tmp/foreign'
                if fault=='digest':dep['observer']['SHA256']='0'*64
                if fault=='token':secret['data']['token']=base64.b64encode(b'changed').decode()
                if fault=='mutable':secret['immutable']=False
                if fault=='foreign-service':dep['workload']['Service']='foreign'
                if fault=='plaintext':
                    raw=self.A.encode(dict(self.observer,Endpoint='http://vault.'+self.A.NS+'.svc:8200'));secret['data']['observer.json']=base64.b64encode(raw).decode();dep['observer']['SHA256']=self.A.sha(raw)
                with self.assertRaises(ValueError):self.M.inputs(self.A,dep,secret)
    def test_hosts_override_is_private_and_conflicts_refused(self):
        raw=b'127.0.0.1 localhost\n';host='vault.'+self.A.NS+'.svc'
        changed=self.M.hosts_file(self.A,raw,host)
        self.assertEqual(raw,b'127.0.0.1 localhost\n');self.assertTrue(changed.startswith(raw))
        with self.assertRaises(ValueError):self.M.hosts_file(self.A,changed,host)
    def test_command_retains_literal_argv_and_readonly_mounts(self):
        argv=['/tool','arg with space','$(not-a-shell-command)']
        result=self.M.command(Path('/private/files'),Path('/private/hosts'),argv)
        self.assertEqual(result[-3:],argv);self.assertEqual(result[:4],['unshare','--mount','--propagation','private'])
        self.assertEqual(result[7].count('remount,bind,ro'),2)

if __name__=='__main__':unittest.main()
