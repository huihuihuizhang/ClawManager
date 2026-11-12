"""Pure deployment/config DATA guards; never starts a workload or accepts a task."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('p2_app_image',Path(__file__).with_name('activate-p2-app-execution-image.py'))
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class AppImageGuards(unittest.TestCase):
 def setUp(self):
  self.inits=[{'name':'wait-secret-broker','image':P.INIT_IMAGE,'command':['/bin/sh','-ceu'],'args':['fixture readonly broker wait'],'volumeMounts':[{'name':'secret-broker-ca','mountPath':'/var/run/secrets/clawmanager-secret-broker-ca','readOnly':True}]},
              {'name':'verify-sbk-app-backend','image':P.INIT_IMAGE,'command':['/bin/sh','-ec','fixture old ELF checksum'],'volumeMounts':[{'name':'sbk-app-backend-release','mountPath':'/release','readOnly':True}]}]
  pins={c['name']:tuple(P.hashlib.sha256(json.dumps(c.get(k,[]),separators=(',',':')).encode()).hexdigest() for k in ['command','args']) for c in self.inits}
  p=patch.object(P,'INIT_PINS',pins);p.start();self.addCleanup(p.stop)
 def fixture(self):
  return {'metadata':{'uid':P.UID,'name':'clawmanager-app','namespace':P.NS},'spec':{'replicas':2,'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':'25%','maxUnavailable':'25%'}},'selector':{'matchLabels':{'app':'clawmanager-app'}},'template':{'metadata':{'labels':{'app':'clawmanager-app'}},'spec':{'serviceAccountName':'original-app','initContainers':copy.deepcopy(self.inits),'volumes':[{'name':'original-ca','configMap':{'name':'original-map'}},{'name':'business','persistentVolumeClaim':{'claimName':'original-business'}},{'name':'sbk-app-backend-release','persistentVolumeClaim':{'claimName':'retained-release'}}],'containers':[{'name':'clawmanager-app','image':P.OLD,'env':[{'name':'RUNTIME_AGENT_CA_SHA256','value':P.CA},{'name':'PRESERVED','valueFrom':{'secretKeyRef':{'name':'original','key':'original'}}}],'volumeMounts':[{'name':'original-ca','mountPath':'/original','readOnly':True},{'name':'business','mountPath':'/workspaces'},{'name':'sbk-app-backend-release','mountPath':'/usr/local/bin/clawreef-server','readOnly':True,'subPath':'clawreef-server'}],'resources':{'limits':{'memory':'512Mi'}}}]}}}}
 def test_only_image_and_old_binary_overlay_change_and_input_is_untouched(self):
  original=self.fixture();saved=copy.deepcopy(original);new=P.desired(original)
  self.assertEqual(original,saved)
  oldpod=original['spec']['template']['spec'];pod=new['template']['spec']
  self.assertEqual(pod['initContainers'],oldpod['initContainers'][:1])
  self.assertNotIn('sbk-app-backend-release',[x['name'] for x in pod['volumes']])
  self.assertNotIn('sbk-app-backend-release',[x['name'] for x in pod['containers'][0]['volumeMounts']])
  pod['volumes']=oldpod['volumes'];pod['initContainers']=oldpod['initContainers'];pod['containers'][0]['volumeMounts']=oldpod['containers'][0]['volumeMounts']
  new['template']['spec']['containers'][0]['image']=P.OLD
  self.assertEqual(new,original['spec'])
 def test_foreign_deployment_stale_ca_or_extra_container_refuses(self):
  for mode in ['uid','ca','container','init']:
   d=self.fixture()
   if mode=='uid':d['metadata']['uid']='different'
   elif mode=='ca':d['spec']['template']['spec']['containers'][0]['env'][0]['value']='stale'
   elif mode=='container':d['spec']['template']['spec']['containers'].append({'name':'extra'})
   else:d['spec']['template']['spec']['initContainers'].append({'name':'unexpected'})
   with self.assertRaises(ValueError):P.desired(d)
 def test_changed_initializer_bytes_or_binary_mount_are_not_accepted(self):
  d=self.fixture();d['spec']['template']['spec']['initContainers'][0]['args']=['changed']
  with self.assertRaisesRegex(ValueError,'initializer bytes'):P.desired(d)
  d=self.fixture();d['spec']['template']['spec']['containers'][0]['volumeMounts'][-1]['subPath']='unexpected'
  with self.assertRaisesRegex(ValueError,'file overlay'):P.desired(d)
 def test_config_protocol_does_not_accept_unselected_log_output_or_claims(self):
  data={'Version':'original-application-config-coordinates.v1','WorkspaceRoot':'/fixture','RuntimeQualified':False,'BackupReady':False}
  raw=json.dumps(data).encode()
  self.assertEqual(P.config_data(b'Loading k8s config from: /fixture\n'+raw),data)
  with self.assertRaises(ValueError):P.config_data(b'unexpected log\n'+raw)
  data['BackupReady']=True
  with self.assertRaises(ValueError):P.config_data(json.dumps(data).encode())
 def test_local_config_probe_omits_dependency_init_but_production_keeps_it(self):
  wanted=P.desired(self.fixture());saved=copy.deepcopy(wanted)
  probe=P.app_local_probe_spec(wanted)
  self.assertEqual(wanted,saved)
  self.assertEqual([c['name'] for c in wanted['template']['spec']['initContainers']],['wait-secret-broker'])
  self.assertNotIn('initContainers',probe)
  self.assertTrue(all(m['readOnly'] for m in probe['containers'][0]['volumeMounts']))
  self.assertIn('--system-backup-source-config-data',probe['containers'][0]['command'][-1])
  self.assertIn(P.APP_ELF,probe['containers'][0]['command'][-1])
 def test_unstarted_probe_is_not_reported_as_wrong_image(self):
  p={'status':{'phase':'Pending','containerStatuses':[{'imageID':'','state':{'waiting':{'reason':'PodInitializing'}}}]}}
  with self.assertRaisesRegex(ValueError,'startup incomplete'):P.completed_probe_state(p,P.APP)
  p['status']={'phase':'Succeeded','containerStatuses':[{'imageID':'other','state':{'terminated':{'exitCode':0}}}]}
  with self.assertRaisesRegex(ValueError,'different image'):P.completed_probe_state(p,P.APP)
  p['status']['containerStatuses'][0]['imageID']=P.APP
  self.assertEqual(P.completed_probe_state(p,P.APP)['state']['terminated']['exitCode'],0)
 def test_only_retained_known_broker_wait_attempt_can_continue(self):
  old={'metadata':{'uid':'original-probe','name':'sbk-p2-execution-app-eca964d4'},'spec':{'containers':[{'image':P.APP}]},
       'status':{'phase':'Pending','initContainerStatuses':[{'name':'wait-secret-broker','state':{'running':{}}}],
                 'containerStatuses':[{'imageID':'','state':{'waiting':{'reason':'PodInitializing'}}}]}}
  P.known_pre_entry_probe(old,{'metadata':{'uid':'original-probe'}})
  with self.assertRaises(ValueError):P.known_pre_entry_probe(old,{'metadata':{'uid':'replaced'}})
  old['status']['phase']='Running'
  with self.assertRaises(ValueError):P.known_pre_entry_probe(old,{'metadata':{'uid':'original-probe'}})
if __name__=='__main__':unittest.main()
