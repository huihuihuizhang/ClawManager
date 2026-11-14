import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import io
import tarfile
import tempfile
from unittest.mock import patch

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('p2-nov14-delivery');O=load('build-p2-controller-overlay')
class DeliveryTest(unittest.TestCase):
    def setUp(self):
        self.old={'IdentityMode':'metadata-only','TokenFile':'old','TokenSHA256':P.sha(b'old'),'ObserverPolicy':'meta','Endpoint':'https://vault','CAPEM':'ca'}
        raw=P.encoded(self.old)
        self.secret={'immutable':True,'metadata':{'name':'old'},'data':{'observer.json':base64.b64encode(raw).decode(),'token':base64.b64encode(b'old').decode()}}
        self.native={**self.old,'TokenFile':'new','TokenSHA256':P.sha(b'new')}
        self.dep={'metadata':{'namespace':'ns','uid':'uid','resourceVersion':'7'},'spec':{'replicas':1,'template':{'spec':{'volumes':[{'name':'provider-dependency-input','secret':{'secretName':'old'}},{'name':'other','emptyDir':{}}],
            'initContainers':[{'name':'provider-dependency-install','image':'old','command':['/usr/local/bin/system-backup-source-registries'],'args':['install-provider-files','--observer-sha256',P.sha(raw),'--token-sha256',self.old['TokenSHA256']]}],
            'containers':[{'name':'controller','image':'old','env':[{'name':'ENABLED','value':'false'}]},{'name':'installation-owner','image':'old'}]}}}}
        self.image='10.130.14.23:5000/clawmanager@sha256:'+'a'*64
    def run_plan(self):return P.rotation_delivery(self.dep,self.secret,self.native,b'new',self.image)
    def test_guards_and_preserves_execution_flags(self):
        original=copy.deepcopy(self.dep);secret,spec,patch,digest=self.run_plan()
        self.assertEqual(self.dep,original);self.assertEqual([p['path'] for p in patch],['/metadata/uid','/metadata/resourceVersion','/spec','/spec'])
        self.assertEqual(spec['template']['spec']['containers'][0]['env'],original['spec']['template']['spec']['containers'][0]['env'])
        self.assertEqual(spec['template']['spec']['volumes'][1],original['spec']['template']['spec']['volumes'][1])
        self.assertEqual(json.loads(base64.b64decode(secret['data']['observer.json']))['TokenFile'],P.MOUNT+'/token')
    def test_wrong_token(self):
        self.native['TokenSHA256']='bad'
        with self.assertRaises(ValueError):self.run_plan()
    def test_endpoint_change(self):
        self.native['Endpoint']='https://other'
        with self.assertRaises(ValueError):self.run_plan()
    def test_mutable_image(self):
        self.image='10.130.14.23:5000/clawmanager:latest'
        with self.assertRaises(ValueError):self.run_plan()
    def test_wrong_secret_mount(self):
        self.dep['spec']['template']['spec']['volumes'][0]['secret']['secretName']='other'
        with self.assertRaises(ValueError):self.run_plan()
    def test_injected_container(self):
        self.dep['spec']['template']['spec']['containers'].append({'name':'other'})
        with self.assertRaises(ValueError):self.run_plan()
    def test_initializer_drift(self):
        self.dep['spec']['template']['spec']['initContainers'][0]['args'].append('other')
        with self.assertRaises(ValueError):self.run_plan()
    def test_overlay_preserves_runtime_and_records_layer(self):
        config={'os':'linux','architecture':'amd64','config':{'User':'65532','Entrypoint':['/app/server'],'Env':['A=B']},'rootfs':{'type':'layers','diff_ids':['sha256:old']}}
        manifest={'schemaVersion':2,'layers':[{'digest':'sha256:old'}]};original=copy.deepcopy(config)
        cfg,doc=O.overlay_metadata(manifest,config,'a'*64,100);cfg=json.loads(cfg);doc=json.loads(doc)
        self.assertEqual(config,original);self.assertEqual(cfg['config'],original['config']);self.assertEqual(cfg['rootfs']['diff_ids'][-1],'sha256:'+'a'*64)
        self.assertEqual(doc['layers'][-1]['size'],100);self.assertEqual(doc['config']['digest'],'sha256:'+O.sha(O.canonical(cfg)))
    def test_wrong_platform_or_layer_count(self):
        for config in ({'os':'linux','architecture':'arm64'},{'os':'linux','architecture':'amd64','rootfs':{'diff_ids':[]}}):
            with self.assertRaises(ValueError):O.overlay_metadata({'layers':[{}]},config,'a'*64,100)
class OCIRoundTripTest(unittest.TestCase):
    def test_real_archive_digest_chain_and_corrupt_base_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); layer=root/'tools.tar';layer.write_bytes(b'layer')
            cfg=O.canonical({'os':'linux','architecture':'amd64','config':{'User':'65532'},'rootfs':{'diff_ids':[]}})
            manifest=O.canonical({'schemaVersion':2,'config':O.descriptor(cfg,'application/vnd.oci.image.config.v1+json'),'layers':[]})
            desc=O.descriptor(manifest,'application/vnd.oci.image.manifest.v1+json')
            files={'index.json':O.canonical({'schemaVersion':2,'manifests':[desc]}),'blobs/sha256/'+O.sha(manifest):manifest,'blobs/sha256/'+O.sha(cfg):cfg}
            base=root/'base.tar'
            with tarfile.open(base,'w') as archive:
                for name,data in files.items():
                    item=tarfile.TarInfo(name);item.size=len(data);archive.addfile(item,io.BytesIO(data))
            with patch.object(O,'BASE','registry/base@'+desc['digest']):
                digest=O.build_overlay(base,layer,root/'out.tar','registry/new:test')
                with tarfile.open(root/'out.tar') as archive:
                    index=json.load(archive.extractfile('index.json'))
                    self.assertEqual(index['manifests'][0]['digest'],'sha256:'+digest)
                    actual=json.load(archive.extractfile('blobs/sha256/'+digest))
                    self.assertEqual(archive.extractfile('blobs/sha256/'+actual['layers'][-1]['digest'][7:]).read(),b'layer')
            with patch.object(O,'BASE','registry/base@sha256:'+'0'*64):
                with self.assertRaises(ValueError):O.build_overlay(base,layer,root/'bad.tar','registry/new:test')

if __name__=='__main__':unittest.main()
