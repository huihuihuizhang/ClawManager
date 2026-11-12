"""Pure source DATA refusal checks; these never simulate native owner success."""
import copy
import datetime
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent
def load(name):
 s=importlib.util.spec_from_file_location(name,ROOT/name);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('refresh-p2-source-inputs.py');C=load('prepare-p2-configuration-data.py')

class SourceInputChecks(unittest.TestCase):
 def loaded(self):
  token=b'fixture-credential-only-0123456789abcdef'
  return [[b'installation',token,b'/workspaces',P.CA_SHA.encode()] for _ in range(2)],[[b'',token,b'/workspaces',b''] for _ in range(2)]
 def test_requires_full_matching_loaded_cohort(self):
  apps,runtimes=self.loaded()
  self.assertEqual(P.coherent_loaded(apps,runtimes)[:2],('installation','/workspaces'))
  for variant in ['token','ca','scope','workspace','missing']:
   a,r=copy.deepcopy((apps,runtimes))
   if variant=='token':r[0][1]=b'a-different-fixture-token-0123456789'
   elif variant=='ca':a[0][3]=b'old-ca'
   elif variant=='scope':a[1][0]=b'foreign-installation'
   elif variant=='workspace':r[0][2]=b'/other'
   else:a.pop()
   with self.assertRaises(ValueError):P.coherent_loaded(a,r)
 def test_refuses_old_foreign_uncompleted_or_expired_ca(self):
  ca={'File':'/fixture-only/ca.pem','SHA256':P.CA_SHA}
  tls={'Version':'original-shared-agent-tls-materials.v1','Namespace':P.NS,'NamespaceUID':P.NSUID,'CA':ca,
   'NotBefore':'2026-11-12T00:42:13Z','NotAfter':'2026-11-13T00:43:13Z'}
  rotation={'Version':'p2-runtime-certificate-rotation.v1','CA':ca,'NotAfter':tls['NotAfter'],'ImagesPreserved':True}
  now=datetime.datetime(2026,11,12,3,tzinfo=datetime.timezone.utc)
  self.assertEqual(P.current_ca(tls,rotation,now),ca)
  for variant in ['old','foreign','uncompleted','expiry']:
   t,r=copy.deepcopy((tls,rotation));moment=now
   if variant=='old':t['CA']['SHA256']='c'*64
   elif variant=='foreign':t['NamespaceUID']='foreign'
   elif variant=='uncompleted':r['ImagesPreserved']=False
   else:moment+=datetime.timedelta(days=2)
   with self.assertRaises(ValueError):P.current_ca(t,r,moment)
 def test_consumes_real_base_or_successor_pin_without_relabelling(self):
  pin={'File':'/fixture-only/selection.json','SHA256':'a'*64}
  receipt={'Version':'original-writer-selection-materials.v1','State':'actual_original_complete_base_selection_materialized_no_hold','SourceCount':8,'Selection':pin}
  original=copy.deepcopy(receipt)
  self.assertEqual(C.writer_selection_pin(receipt),pin);self.assertEqual(receipt,original)
  self.assertEqual(C.writer_selection_pin({'WriterSelection':pin}),pin)
  for variant in ['partial','count']:
   r=copy.deepcopy(receipt)
   if variant=='partial':r['State']='unconfirmed'
   else:r['SourceCount']=7
   with self.assertRaises((ValueError,RuntimeError)):C.writer_selection_pin(r)

if __name__=='__main__':unittest.main()
