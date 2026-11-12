import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('rotation',Path(__file__).with_name('rotate-p2-runtime-certificates.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RotationBoundaries(unittest.TestCase):
    def runtime(self):
        name='hermes-runtime';uid,image=m.IMAGES[name]
        spec={'replicas':1,'strategy':{'type':'Recreate'},'template':{'spec':{'containers':[{'name':'runtime','image':image,
            'command':['/preserved-launcher'],'args':['--preserved'],'env':[{'name':'RUNTIME_AGENT_TLS_CERT_FILE','value':'/run/clawmanager-agent-tls/tls.crt'},
            {'name':'RUNTIME_AGENT_TLS_KEY_FILE','value':'/run/clawmanager-agent-tls/tls.key'},{'name':'BACKEND_SETTING','value':'serve'},{'name':'EMPTY','value':''}],
            'volumeMounts':[{'name':'tls','mountPath':'/run/clawmanager-agent-tls','readOnly':True}]}],
            'volumes':[{'name':'tls','secret':{'secretName':'old-secret','defaultMode':256}}]}}}
        return {'metadata':{'name':name,'uid':uid,'generation':7,'resourceVersion':'7'},'spec':spec},{'DeploymentUID':uid,'DeploymentGeneration':7,'SecretName':'new-secret'}

    def test_runtime_changes_only_existing_secret_and_keeps_repaired_image(self):
        d,t=self.runtime();before=copy.deepcopy(d)
        desired=m.runtime_spec(d,t)
        self.assertEqual(d,before)
        expected=copy.deepcopy(d['spec']);expected['template']['spec']['volumes'][0]['secret']['secretName']='new-secret'
        self.assertEqual(desired,expected)

    def test_generation_uid_and_image_drift_are_not_repaired_by_guessing(self):
        for fault in ['generation','uid','image']:
            d,t=self.runtime()
            if fault=='image':d['spec']['template']['spec']['containers'][0]['image']='wrong/old-hermes:tag'
            else:d['metadata'][fault]='changed'
            with self.subTest(fault=fault),self.assertRaises(ValueError):m.runtime_spec(d,t)

    def test_app_preserves_business_settings_and_changes_only_ca_references(self):
        spec={'replicas':2,'template':{'spec':{'containers':[{'name':'clawmanager-app','image':'10.130.14.23:5000/clawmanager@sha256:322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca',
            'env':[{'name':'RUNTIME_AGENT_CA_FILE','value':'/run/clawmanager-agent-ca/ca.pem'},{'name':'RUNTIME_AGENT_CA_SHA256','value':m.OLD_CA},
                   {'name':'DATABASE_CREDENTIAL','valueFrom':{'secretKeyRef':{'name':'unchanged','key':'password'}}}],
            'volumeMounts':[{'name':'ca','mountPath':'/run/clawmanager-agent-ca','readOnly':True}]}],
            'volumes':[{'name':'ca','configMap':{'name':'old-ca','items':[{'key':'ca.pem','path':'ca.pem'}]}}]}}}
        before=copy.deepcopy(spec);desired,name=m.app_spec(spec,m.NEW_CA)
        expected=copy.deepcopy(spec);expected['template']['spec']['containers'][0]['env'][1]['value']=m.NEW_CA
        expected['template']['spec']['volumes'][0]['configMap']['name']=name
        self.assertEqual(desired,expected);self.assertEqual(spec,before)

    def test_only_empty_literal_env_admission_difference_is_normalized(self):
        self.assertEqual(m.semantic({'env':[{'name':'X','value':''}]}),m.semantic({'env':[{'name':'X'}]}))
        self.assertNotEqual(m.semantic({'env':[{'name':'X'}]}),m.semantic({'env':[{'name':'X','valueFrom':{'fieldRef':{'fieldPath':'metadata.name'}}}]}))

    def test_unknown_patch_cannot_be_sent_again(self):
        scratch=Path(os.environ['P2_TEST_DIRECTORY']);self.assertEqual(scratch.drive.lower(),'d:')
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            site=m.Site(Path(directory));d,t=self.runtime();desired=m.runtime_spec(d,t);calls=[]
            site.get=lambda *args:copy.deepcopy(d)
            def lost(args,body=None):
                calls.append(args);raise subprocess.TimeoutExpired(args,1)
            site.call=lost
            with self.assertRaises(subprocess.TimeoutExpired):site.patch('runtime',d['metadata']['name'],d['spec'],desired,t['DeploymentUID'])
            with self.assertRaisesRegex(ValueError,'never resend'):site.patch('runtime',d['metadata']['name'],d['spec'],desired,t['DeploymentUID'])
            self.assertEqual(len(calls),1)

if __name__=='__main__':unittest.main()
