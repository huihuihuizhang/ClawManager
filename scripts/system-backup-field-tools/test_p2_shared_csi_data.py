"""Pure CSI source DATA guards; no host-path, native hold or execution proof."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

p=Path(__file__).resolve().parent.parent/'system-backup-initial-complete-inputs.py'
s=importlib.util.spec_from_file_location('csi_source_data',p);H=importlib.util.module_from_spec(s);s.loader.exec_module(H)
def need(ok,why):
 if not ok:raise ValueError(why)

class SharedCSIData(unittest.TestCase):
 def fixture(self):
  row={'Namespace':'system','Pod':'agent','PodUID':'pod-uid','Node':'node','NodeUID':'node-uid','VolumeName':'data',
   'ClaimName':'workspaces','ClaimUID':'claim-uid','PVName':'pv','PVUID':'pv-uid','Handle':'csi-handle',
   'Mounts':[{'Container':'runtime','MountPath':'/workspaces','SubPath':''}]}
  data={'Namespace':'system','NodeUIDs':{'node':'node-uid'},'SharedNodes':None,'SharedRuntimeVolumes':[row]}
  writer={'SharedRuntimeVolumes':[copy.deepcopy(row)],'SharedRuntimeAgents':[{'Namespace':'system','Pod':'agent','PodUID':'pod-uid'}]}
  objects={('pod','agent'):{'metadata':{'namespace':'system','uid':'pod-uid'},'spec':{'nodeName':'node','volumes':[
   {'name':'data','persistentVolumeClaim':{'claimName':'workspaces'}}],'containers':[{'name':'runtime','volumeMounts':[{'name':'data','mountPath':'/workspaces'}]}]}},
   ('pvc','workspaces'):{'metadata':{'uid':'claim-uid'},'spec':{'volumeName':'pv'}},
   ('pv','pv'):{'metadata':{'uid':'pv-uid'},'spec':{'claimRef':{'uid':'claim-uid'},'csi':{'driver':'driver.longhorn.io','volumeHandle':'csi-handle','fsType':'ext4'}}},
   ('node','node'):{'metadata':{'uid':'node-uid'}}}
  return data,writer,objects
 def call(self,data,writer,objects):return H.shared_storage_coordinates(SimpleNamespace(need=need),SimpleNamespace(get=lambda k,n:objects[(k,n)]),data,writer)
 def test_csi_rows_do_not_become_host_paths(self):
  d,w,o=self.fixture();original=copy.deepcopy((d,w,o))
  self.assertEqual(self.call(d,w,o),[]);self.assertEqual((d,w,o),original)
 def test_missing_blocked_or_partial_agent_coverage_refuses(self):
  for case in ['missing','blocked','agent','selection','duplicate']:
   d,w,o=self.fixture()
   if case=='missing':d['SharedRuntimeVolumes']=[]
   elif case=='blocked':d['BlockedSharedStorage']=[{'Reason':'unsupported'}]
   elif case=='agent':w['SharedRuntimeAgents'].append({'Namespace':'system','Pod':'other','PodUID':'other'})
   elif case=='selection':w['SharedRuntimeVolumes'][0]['PVUID']='other'
   else:d['SharedRuntimeVolumes']*=2;w['SharedRuntimeVolumes']*=2
   with self.assertRaises(ValueError):self.call(d,w,o)
 def test_changed_node_pv_driver_handle_and_mount_refuse(self):
  for case in ['node','pv','driver','handle','mount']:
   d,w,o=self.fixture()
   if case=='node':o[('pod','agent')]['spec']['nodeName']='different'
   elif case=='pv':o[('pv','pv')]['metadata']['uid']='different'
   elif case=='driver':o[('pv','pv')]['spec']['csi']['driver']='different'
   elif case=='handle':o[('pv','pv')]['spec']['csi']['volumeHandle']='different'
   else:o[('pod','agent')]['spec']['containers'][0]['volumeMounts'][0]['subPath']='different'
   with self.assertRaises(ValueError):self.call(d,w,o)
 def test_existing_host_path_data_is_preserved(self):
  d,w,o=self.fixture();d['SharedNodes']=[{'Name':'node','UID':'node-uid','Paths':['/observed-host-root']}]
  self.assertEqual(self.call(d,w,o),d['SharedNodes'])

if __name__=='__main__':unittest.main()
