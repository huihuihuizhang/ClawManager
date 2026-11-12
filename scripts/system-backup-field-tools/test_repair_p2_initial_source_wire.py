"""Exact API TLS wire correction; no native author or credential output."""
import copy
import importlib.util
from pathlib import Path
import unittest

s=importlib.util.spec_from_file_location('initial_source_wire',Path(__file__).with_name('repair-p2-initial-source-wire.py'))
P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
class InitialWireCorrection(unittest.TestCase):
 def fixture(self):
  api={'connection':{'Endpoint':'https://fixture-only','CA':{'File':'/fixture/ca.pem','SHA256':'a'*64},'Credential':{'File':'/fixture/api.jwt'}}}
  value={'Version':'original-initial-source-author-inputs.v1','Deployment':{'fixture':'unchanged-core'},'Materials':{'Discovery':{
   'SourceAPI':{'Server':'https://fixture-only','CAFile':'/fixture/ca.pem','CASHA256':'a'*64,'TokenFile':'/fixture/api.jwt'},'Issuer':'fixture-only'},'Operations':{'fixture':'unchanged'}},
   'Connections':[{'fixture':'unchanged'}],'NotBefore':'original-before','Until':'original-until'}
  return value,api
 def test_only_wire_names_and_explicit_preparation_window_change(self):
  old,api=self.fixture();original=copy.deepcopy(old)
  new=P.corrected_definition(old,api,'new-before','new-until')
  self.assertEqual(old,original)
  self.assertEqual(new['Materials']['Discovery']['SourceAPI'],{'server':'https://fixture-only','ca_file':'/fixture/ca.pem','ca_sha256':'a'*64,'token_file':'/fixture/api.jwt'})
  new['Materials']['Discovery']['SourceAPI']=old['Materials']['Discovery']['SourceAPI']
  new['NotBefore']=old['NotBefore'];new['Until']=old['Until']
  self.assertEqual(new,old)
 def test_changed_endpoint_credential_ca_or_extra_field_refuses(self):
  for case in ['endpoint','credential','ca','extra','already_lowercase']:
   old,api=self.fixture();mapping=old['Materials']['Discovery']['SourceAPI']
   if case=='endpoint':mapping['Server']='https://different'
   elif case=='credential':mapping['TokenFile']='/fixture/foreign-token'
   elif case=='ca':mapping['CASHA256']='b'*64
   elif case=='extra':mapping['extra']='unreviewed'
   else:old['Materials']['Discovery']['SourceAPI']={'server':'https://fixture-only'}
   with self.assertRaises(ValueError):P.corrected_definition(old,api,'before','until')

if __name__=='__main__':unittest.main()
