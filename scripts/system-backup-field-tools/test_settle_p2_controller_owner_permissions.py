"""Pure permission successor guards; no mounted-volume or native success claim."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('owner_permissions',ROOT/'settle-p2-controller-owner-permissions.py')
P=importlib.util.module_from_spec(s);s.loader.exec_module(P)

class OwnerPermissionSettlement(unittest.TestCase):
 def fixture(self):
  owner='umask 077; for d in /run/system-backup/runtime /run/installation-owner-private/installer; do if test ! -e "$d"; then mkdir -m 700 "$d"; fi; test ! -L "$d"; test "$(stat -c %u:%a "$d")" = 65532:700; done; while :; do sleep 3600; done'
  return {'replicas':1,'strategy':{'type':'Recreate'},'template':{'spec':{
   'securityContext':{'fsGroup':65532,'runAsGroup':65532,'runAsNonRoot':True,'runAsUser':65532,'seccompProfile':{'type':'RuntimeDefault'}},
   'containers':[{'name':'controller','image':P.APP,'env':[{'name':'SYSTEM_BACKUP_ENABLED','value':'false'}],
    'command':['/bin/sh','-ec','f=/run/system-backup/runtime/controller.env; while test ! -f "$f.ready"; do sleep 2; done; exec /run/system-backup/bin/system-backup-v2-controller']},
    {'name':'installation-owner','image':P.APP,'command':['/bin/sh','-ec',owner],
     'volumeMounts':[{'name':'inputs','mountPath':'/run/system-backup'},{'name':'private','mountPath':'/run/installation-owner-private'}]}],
   'volumes':[{'name':'private','persistentVolumeClaim':{'claimName':'original-private'}}]}}}
 def test_only_owner_mode_guard_and_mount_permission_policy_change(self):
  original=self.fixture();before=copy.deepcopy(original);wanted=P.desired_spec(original)
  self.assertEqual(original,before)
  pod=wanted['template']['spec'];self.assertEqual(pod['securityContext'].pop('fsGroupChangePolicy'),'OnRootMismatch')
  command=pod['containers'][1]['command'][2]
  self.assertIn('2770) chmod 700 "$d"',command)
  self.assertIn('test "$(stat -c %u:%g "$d")" = 65532:65532',command)
  self.assertIn('test ! -L "$d"',command)
  self.assertNotIn('chmod -R',command);self.assertNotIn('chown',command)
  pod['containers'][1]['command']=original['template']['spec']['containers'][1]['command']
  self.assertEqual(wanted,original)
 def test_foreign_owner_command_or_mount_refuses(self):
  for case in ['command','mount','subpath','readonly']:
   spec=self.fixture();owner=spec['template']['spec']['containers'][1]
   if case=='command':owner['command'][2]+='; echo changed'
   elif case=='mount':owner['volumeMounts'][1]['mountPath']='/different'
   elif case=='subpath':owner['volumeMounts'][1]['subPath']='different'
   else:owner['volumeMounts'][1]['readOnly']=True
   with self.assertRaises(ValueError):P.desired_spec(spec)
 def test_enabled_root_or_foreign_image_refuses(self):
  for case in ['enabled','root','image','policy']:
   spec=self.fixture();pod=spec['template']['spec']
   if case=='enabled':pod['containers'][0]['env'][0]['value']='true'
   elif case=='root':pod['securityContext']['runAsUser']=0
   elif case=='image':pod['containers'][1]['image']='foreign'
   else:pod['securityContext']['fsGroupChangePolicy']='Always'
   with self.assertRaises(ValueError):P.desired_spec(spec)
 def test_successor_proof_is_bound_to_original_plan_and_derived_spec(self):
  plan={'Desired':self.fixture()};selected={'File':'/fixture-only/original-plan.json','SHA256':'a'*64}
  wanted=P.desired_spec(plan['Desired'])
  completed={'Version':'p2-controller-owner-permissions.v1','ControllerUID':P.UID,'OriginalControllerPlan':selected,
   'SourceSpecSHA256':P.sha(P.encode(plan['Desired'])),'DesiredSpecSHA256':P.sha(P.encode(wanted)),
   'ControllerEnabled':False,'BackupReady':False}
  self.assertEqual(P.reconciled_spec(plan,completed,selected),wanted)
  for case in ['plan','spec','enabled']:
   value=copy.deepcopy(completed)
   if case=='plan':value['OriginalControllerPlan']['SHA256']='b'*64
   elif case=='spec':value['DesiredSpecSHA256']='c'*64
   else:value['ControllerEnabled']=True
   with self.assertRaises(ValueError):P.reconciled_spec(plan,value,selected)

if __name__=='__main__':unittest.main()
