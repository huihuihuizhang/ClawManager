import importlib.util
from pathlib import Path
from unittest.mock import Mock
import unittest
import tempfile
import json
import copy

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class SourcePolicyPreflightTest(unittest.TestCase):
    def test_approved_intent_selects_exact_names_without_observed_secrets(self):
        c=load('continue-p2-nov14');a=load('assemble-p2-installation-candidate')
        entries=[('application','clawmanager-secrets','Opaque','application_secret'),('gate-control','sbk-app-gate-control-95392e58','Opaque','application_secret'),('minio-tls','sbk-minio-first-tls-a10011353367ae32','Opaque','tls_credentials'),('runtime-hermes-tls','sbk-renew-20261114-b60bb176cc0ca9dc','kubernetes.io/tls','tls_credentials'),('runtime-openclaw-tls','sbk-renew-20261114-8f4a86e00c90bed6','kubernetes.io/tls','tls_credentials'),('secret-broker-tls','clawmanager-secret-broker-tls','kubernetes.io/tls','tls_credentials')]
        policy={'schema_version':'system-backup-secret-capture-policy.v1','registry_version':'p2-business-secrets-20261115.v1','registry_kind':'secret_allowlist','namespace_scope':'installation_namespace','capture_mode':'encrypted_full_object','entries':[{'entry_id':i,'secret_name':n,'required':True,'expected_type':t,'purpose':p} for i,n,t,p in entries]}
        with tempfile.TemporaryDirectory() as directory:
            c.ROOT=Path(directory).resolve();path=c.ROOT/'secret-policy-20261115/business-secrets.policy.json';path.parent.mkdir();path.write_bytes(json.dumps(policy,sort_keys=True,separators=(',',':')).encode())
            original={'Materials':{'Discovery':{},'ResourceTypes':[{'Group':'apps','LabelSelector':'','Part':'deployment_resources','Resource':'deployments','Version':'v1'},{'Group':'','LabelSelector':'','Part':'secret_bundle','Resource':'secrets','Version':'v1'}]}}
            before=copy.deepcopy(original);result=c.approved_secret_scope(a,original)
            self.assertEqual(original,before)
            self.assertEqual(result['Materials']['ResourceTypes'][0],original['Materials']['ResourceTypes'][0])
            self.assertEqual([v['FieldSelector'] for v in result['Materials']['ResourceTypes'][1:]],['metadata.name='+n for _,n,_,_ in entries])
            self.assertEqual(result['Materials']['Discovery']['SecretPolicy']['sha256'],'72360a4b05df37b8ca685e9d964fab64beaf7dae1e07786775f6902db4df6d59')
            path.write_bytes(path.read_bytes()+b' ')
            with self.assertRaises(ValueError):c.approved_secret_scope(a,original)

    def test_missing_intent_stops_before_token_or_native_calls(self):
        c=load('continue-p2-nov14');a=load('assemble-p2-installation-candidate');site=Mock();native=Mock()
        for discovery in ({},{'SecretPolicy':{'protocol':'wrong','path':'private','sha256':'wrong'}}):
            with self.assertRaisesRegex(ValueError,'explicit original Secret backup policy'):
                c.refresh(A=a,L=None,H=None,R=native,N=None,D=None,F=None,T=None,site=site,package=None,parent=None,
                          original={'RedisSourcesVersion':'actual-v1','Materials':{'Discovery':discovery}},selected=None,
                          fresh=None,pod=None,desired=None,secret=None,plan=None,minted=None,observer=None,agent=None)
        self.assertEqual(site.mock_calls,[]);self.assertEqual(native.mock_calls,[])

if __name__=='__main__':unittest.main()
