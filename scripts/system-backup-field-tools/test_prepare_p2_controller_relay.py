"""Pure controller DATA checks, not an installed runtime/issued key simulation."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent
def load(name):
 s=importlib.util.spec_from_file_location(name,ROOT/name);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('prepare-p2-controller-relay.py');A=load('assemble-p2-installation-candidate.py')
class ControllerRelayInputs(unittest.TestCase):
 def fixture(self):
  return {'metadata':{'name':P.CONTROLLER,'namespace':P.NS,'uid':P.UID,'resourceVersion':'fixture-rv'},'spec':{'replicas':1,'selector':{'matchLabels':{'original':'controller'}},'template':{'spec':{'containers':[
   {'name':'controller','image':P.OLD,'env':[{'name':'SYSTEM_BACKUP_ENABLED','value':'false'},{'name':'SYSTEM_BACKUP_EXECUTION_PROTOCOL','value':'public-v1'}],'command':['/bin/sh','-ec','f=/run/system-backup/runtime/controller.env; while test ! -f "$f.ready"; do sleep 1; done; exec /usr/local/bin/system-backup-v2-controller'],
    'volumeMounts':[{'name':'inputs','mountPath':'/run/system-backup','readOnly':True}]},
   {'name':'installation-owner','image':P.OLD,'command':['sh','-ec','sleep infinity'],'volumeMounts':[{'name':'inputs','mountPath':'/run/system-backup'}]}],
   'volumes':[{'name':'inputs','persistentVolumeClaim':{'claimName':'original-inputs'}}]}}}}
 def binary(self):return {'File':'/run/system-backup/bin/system-backup-v2-controller','SHA256':'a'*64}
 def test_only_images_and_waiting_executable_change(self):
  d=self.fixture();old=copy.deepcopy(d);wanted=P.controller_desired(d,self.binary(),A)
  self.assertEqual(d,old)
  cs=wanted['template']['spec']['containers']
  self.assertEqual([c['image'] for c in cs],[P.APP,P.APP])
  self.assertIn('sha256sum /run/system-backup/bin/system-backup-v2-controller',cs[0]['command'][2])
  self.assertIn('while test ! -f "$f.ready"',cs[0]['command'][2])
  for i,c in enumerate(cs):c['image']=d['spec']['template']['spec']['containers'][i]['image']
  cs[0]['command']=d['spec']['template']['spec']['containers'][0]['command']
  self.assertEqual(wanted,d['spec'])
 def test_enabled_foreign_or_changed_controller_refuses(self):
  for case in ['enabled','uid','image','container']:
   d=self.fixture()
   if case=='enabled':d['spec']['template']['spec']['containers'][0]['env'][0]['value']='true'
   elif case=='uid':d['metadata']['uid']='different'
   elif case=='image':d['spec']['template']['spec']['containers'][1]['image']='foreign'
   else:d['spec']['template']['spec']['containers'].append({'name':'extra','image':P.OLD})
   with self.assertRaises(ValueError):P.controller_desired(d,self.binary(),A)
 def test_unguarded_entrypoint_and_wrong_binary_path_refuse(self):
  d=self.fixture();d['spec']['template']['spec']['containers'][0]['command']=['/usr/local/bin/system-backup-v2-controller']
  with self.assertRaises(ValueError):P.controller_desired(d,self.binary(),A)
  bad=self.binary();bad['File']='/tmp/unbound-controller'
  with self.assertRaises(ValueError):P.controller_desired(self.fixture(),bad,A)
if __name__=='__main__':unittest.main()
