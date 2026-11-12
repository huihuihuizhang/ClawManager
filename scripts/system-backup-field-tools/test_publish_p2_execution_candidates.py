import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

spec=importlib.util.spec_from_file_location('p2_publish',Path(__file__).with_name('publish-p2-execution-candidates.py'))
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

class ExecutionCandidate(unittest.TestCase):
 def fixture(self,kind):
  binary=bytearray((1<<20)+1);binary[:6]=b'\x7fELF\x02\x01';binary[18:20]=b'\x3e\x00';binary=bytes(binary)
  filename=P.PROFILES[kind][3]
  receipt={'Version':'p2-execution-binaries-build.v1','SourceRevision':P.REVISION,'BackendTree':'a'*40,'Platform':'linux/amd64','Binaries':{filename:{'SHA256':P.sha(binary),'Bytes':len(binary)}}}
  config={'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':['sha256:'+'1'*64]},'history':[{'created_by':'original'}],
          'config':{'Labels':None,'Entrypoint':['/backup-worker'] if kind=='worker' else ['dumb-init','--'],'Cmd':['original'],'Env':['ORIGINAL=value'],'User':'65532','WorkingDir':'/app'}}
  manifest={'schemaVersion':2,'mediaType':'application/vnd.docker.distribution.manifest.v2+json','config':{'mediaType':'application/vnd.docker.container.image.v1+json','digest':'sha256:'+'2'*64,'size':1},'layers':[{'digest':'sha256:'+'1'*64,'size':100,'mediaType':'application/vnd.docker.image.rootfs.diff.tar.gzip'}]}
  return binary,receipt,config,manifest
 def test_only_selected_binary_layer_and_provenance_change(self):
  for kind in P.PROFILES:
   binary,receipt,config,manifest=self.fixture(kind);old=copy.deepcopy((config,manifest))
   layer,raw,newmanifest=P.candidate(kind,manifest,config,binary,receipt)
   c=json.loads(raw);m=json.loads(newmanifest)
   self.assertEqual((config,manifest),old)
   for key in ['Env','Cmd','Entrypoint','User','WorkingDir']:self.assertEqual(c['config'][key],config['config'][key])
   self.assertEqual(m['layers'][:-1],manifest['layers'])
   self.assertEqual(m['config']['digest'],'sha256:'+P.sha(raw))
   self.assertEqual(c['rootfs']['diff_ids'][-1],'sha256:'+P.sha(gzip.decompress(layer)))
   self.assertEqual(c['config']['Labels']['org.opencontainers.image.revision'],P.REVISION)
   with tarfile.open(fileobj=io.BytesIO(gzip.decompress(layer))) as tar:
    members=tar.getmembers();self.assertEqual(len(members),1)
    self.assertEqual(members[0].name,P.PROFILES[kind][4]);self.assertEqual(members[0].mode,0o555)
    self.assertEqual(tar.extractfile(members[0]).read(),binary)
 def test_receipt_must_match_actual_binary_and_fixed_revision(self):
  binary,receipt,config,manifest=self.fixture('app')
  receipt['SourceRevision']='f'*40
  with self.assertRaisesRegex(ValueError,'build receipt'):P.candidate('app',manifest,config,binary,receipt)
  receipt['SourceRevision']=P.REVISION
  with self.assertRaisesRegex(ValueError,'build receipt'):P.candidate('app',manifest,config,binary+b'x',receipt)
 def test_worker_entrypoint_and_architecture_cannot_drift(self):
  binary,receipt,config,manifest=self.fixture('worker');config['config']['Entrypoint']=['/unexpected']
  with self.assertRaisesRegex(ValueError,'entrypoint'):P.candidate('worker',manifest,config,binary,receipt)
  config['config']['Entrypoint']=['/backup-worker'];config['architecture']='arm64'
  with self.assertRaisesRegex(ValueError,'platform'):P.candidate('worker',manifest,config,binary,receipt)
 def test_registry_target_is_limited_to_two_installation_repositories(self):
  with self.assertRaisesRegex(ValueError,'repositories only'):P.Registry('unrelated')
  client=P.Registry('clawmanager')
  with self.assertRaisesRegex(ValueError,'target changed'):client.call('PUT','http://example.invalid/v2/clawmanager/blobs/x',b'x')
  with self.assertRaisesRegex(ValueError,'target changed'):client.call('PUT','/v2/other/blobs/x',b'x')

if __name__=='__main__':unittest.main()
