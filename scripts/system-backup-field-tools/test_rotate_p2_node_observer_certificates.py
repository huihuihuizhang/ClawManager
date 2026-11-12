"""Pure renewal-plan checks; no Node service, native owner or hold simulated."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('p2_node_renewal',Path(__file__).with_name('rotate-p2-node-observer-certificates.py'))
N=importlib.util.module_from_spec(spec);spec.loader.exec_module(N)

class NodeRenewalPlan(unittest.TestCase):
 def unit(self,kind,changed=False):
  args=['/usr/local/libexec/sbk-d4f51b83b57e/'+N.BINARIES[kind][0],'--node','node1','--listen','10.130.35.23:19443','--client-ca','/fixed/observer-ca.pem']
  if kind in ['whole','shared']:
   prefix='--shared-' if kind=='whole' else '--'
   for runtime in ['hermes','openclaw']:args += [prefix+runtime+'-agent-elf-sha256',N.AGENTS[runtime] if changed else 'a'*64]
   args += ['--shared-owner-directory' if kind=='whole' else '--owner-directory','/original/owner']
  return ('[Unit]\nDescription=Original observer\n[Service]\nExecStart='+' '.join(args)+'\nUser=root\n').encode()
 def test_only_both_current_agent_expectations_may_change(self):
  for kind in N.BINARIES:N.compare_unit(self.unit(kind),self.unit(kind,True),kind)
  old=self.unit('shared');new=self.unit('shared',True).replace(N.AGENTS['hermes'].encode(),b'b'*64)
  with self.assertRaisesRegex(ValueError,'current Agent'):N.compare_unit(old,new,'shared')
 def test_binary_endpoint_durable_path_and_service_options_are_preserved(self):
  old=self.unit('shared');new=self.unit('shared',True)
  for before,after in [(b'10.130.35.23:19443',b'10.130.35.23:19444'),(b'/original/owner',b'/new/owner'),(b'User=root',b'User=nobody'),(b'/usr/local/libexec',b'/other/libexec')]:
   with self.assertRaises(ValueError):N.compare_unit(old,new.replace(before,after),'shared')
 def test_flat_payload_rejects_duplicates_links_and_traversal(self):
  for names,link in [(['ok','ok'],False),(['../escape'],False),(['..'],False),(['link'],True)]:
   raw=io.BytesIO()
   with tarfile.open(fileobj=raw,mode='w') as t:
    for name in names:
     m=tarfile.TarInfo(name);m.size=1
     if link:m.type=tarfile.SYMTYPE;m.linkname='/outside';m.size=0
     t.addfile(m,None if link else io.BytesIO(b'x'))
   with self.assertRaises(ValueError):N.tar_files(raw.getvalue(),1024)
 def test_payload_contains_no_binaries_and_keeps_original_durable_location(self):
  node='node1';ca=b'fixture new CA';old_ca='a'*64
  files={'observer-ca.pem':ca};eps=[];old=[]
  for kind,(binary,digest) in N.BINARIES.items():
   # Only hash comparison is replaced for this renderer fixture, never exported.
   files[binary]=('fixture '+binary).encode()
   files[N.unit_name(kind)]=self.unit(kind,True)
   for name in [kind+'-server.pem',kind+'-server-key.pem']:files[name]=b'fixture certificate data'
   if kind!='shared':files[kind+'-anchor.key']=b'fixture anchor'
   eps.append({'Kind':kind});old.append({'Node':node,'Kind':kind,'Certificate':{'SHA256':'b'*64},'PrivateKey':{'SHA256':'c'*64},'AnchorKey':{'SHA256':'d'*64}})
  files['node-receipt.json']=json.dumps({'Version':'original-observer-host-bundle.v1','Node':node,'NodeUID':N.NODES[node],'MachineID':'fixture-machine','BootID':'fixture-boot','Endpoints':eps}).encode()
  mapped={kind:(binary,N.sha(files[binary])) for kind,(binary,digest) in N.BINARIES.items()}
  with patch.object(N,'BINARIES',mapped),patch.object(N,'OLD_CA',old_ca),patch.object(N,'NEW_CA',N.sha(ca)):
   raw=N.payload(node,files,{'CA':{'SHA256':old_ca},'Endpoints':old},{'CA':{'SHA256':N.sha(ca)}},'fixture-until')
  extracted=N.tar_files(raw,262144);plan=json.loads(extracted['rotation-plan.json'])
  self.assertFalse(any(binary in extracted for binary,digest in mapped.values()))
  self.assertEqual(plan['OwnerDirectory'],str(N.STORE/('node-'+N.sha(N.NODES[node].encode())[:24])))
  self.assertFalse(plan['BackupReady'])
  self.assertEqual(plan['Files'][N.unit_name('shared')]['OldSHA256'],N.OLD_UNITS[node]['shared'])

if __name__=='__main__':unittest.main()
