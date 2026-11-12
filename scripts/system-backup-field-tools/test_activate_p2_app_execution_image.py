"""Pure deployment/config DATA guards; never starts a workload or accepts a task."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('p2_app_image',Path(__file__).with_name('activate-p2-app-execution-image.py'))
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class AppImageGuards(unittest.TestCase):
 def fixture(self):
  return {'metadata':{'uid':P.UID,'name':'clawmanager-app','namespace':P.NS},'spec':{'replicas':2,'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':'25%','maxUnavailable':'25%'}},'selector':{'matchLabels':{'app':'clawmanager-app'}},'template':{'metadata':{'labels':{'app':'clawmanager-app'}},'spec':{'serviceAccountName':'original-app','volumes':[{'name':'original-ca','configMap':{'name':'original-map'}}],'containers':[{'name':'clawmanager-app','image':P.OLD,'env':[{'name':'RUNTIME_AGENT_CA_SHA256','value':P.CA},{'name':'PRESERVED','valueFrom':{'secretKeyRef':{'name':'original','key':'original'}}}],'volumeMounts':[{'name':'original-ca','mountPath':'/original','readOnly':True}],'args':['original'],'resources':{'limits':{'memory':'512Mi'}}}]}}}}
 def test_exactly_one_image_changes_and_input_is_untouched(self):
  original=self.fixture();saved=copy.deepcopy(original);new=P.desired(original)
  self.assertEqual(original,saved)
  new['template']['spec']['containers'][0]['image']=P.OLD
  self.assertEqual(new,original['spec'])
 def test_foreign_deployment_stale_ca_or_extra_container_refuses(self):
  for mode in ['uid','ca','container','init']:
   d=self.fixture()
   if mode=='uid':d['metadata']['uid']='different'
   elif mode=='ca':d['spec']['template']['spec']['containers'][0]['env'][0]['value']='stale'
   elif mode=='container':d['spec']['template']['spec']['containers'].append({'name':'extra'})
   else:d['spec']['template']['spec']['initContainers']=[{'name':'unexpected'}]
   with self.assertRaises(ValueError):P.desired(d)
 def test_config_protocol_does_not_accept_unselected_log_output_or_claims(self):
  data={'Version':'original-application-config-coordinates.v1','WorkspaceRoot':'/fixture','RuntimeQualified':False,'BackupReady':False}
  raw=json.dumps(data).encode()
  self.assertEqual(P.config_data(b'Loading k8s config from: /fixture\n'+raw),data)
  with self.assertRaises(ValueError):P.config_data(b'unexpected log\n'+raw)
  data['BackupReady']=True
  with self.assertRaises(ValueError):P.config_data(json.dumps(data).encode())
if __name__=='__main__':unittest.main()
