#!/usr/bin/env python3
"""Run the existing Vault provider observation phases, without IAM or a hold."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
AUTHOR=Path('/root/sbk/p2-redis-8bbf4c61/system-backup-original-maintenance')
AUTHOR_SHA='a947551a16fae050a00975ada5421b453baefd3340bcd1dffd8fa24bd861d20e'
HELPER=Path('/root/sbk/p2-runtime-cert-rotation-fcc26a0a/rotate-p2-runtime-certificates.py')
HELPER_SHA='ab1539c5e06c8c237e8516d9985b162fbec3216570abb5ebec1902df47f7052c'
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main(directory):
 os.umask(0o077);A=load('vault_dependency_assembly',directory/'assemble-p2-installation-candidate.py')
 A.need(os.name=='posix','Linux operator required')
 r=ROOT/'vault-dependency';r.mkdir(mode=0o700,exist_ok=True)
 A.need(r.resolve(strict=True)==r and r.stat().st_mode&0o077==0,'original private Vault dependency records required')
 print('P2_VAULT_DEPENDENCY_RECORDS',r,flush=True)
 A.need(hashlib.sha256(AUTHOR.read_bytes()).hexdigest()==AUTHOR_SHA and hashlib.sha256(HELPER.read_bytes()).hexdigest()==HELPER_SHA,'original provider owner and API helper required')
 m=load('vault_dependency_api',HELPER);site=m.Site(r)
 writer_receipt=json.loads((ROOT/'current-source-inputs/writer-selection.receipt.private.json').read_bytes())
 writer=writer_receipt['Selection'];A.read(writer)
 completed=json.loads((ROOT/'initial-source-author/completed.json').read_bytes());A.read(completed['Receipt'])
 old=json.loads((ROOT/'observer.sent.private.json').read_bytes())['Argv'];common=old[1:old.index('--definition-file')]
 pairs=dict(zip(common[::2],common[1::2]));plan=json.loads(Path(pairs['--plan-file']).read_bytes())
 controller=json.loads((ROOT/'controller-relay/controller-current.private.json').read_bytes())
 actual=site.get('pod',controller['metadata']['name']);A.need(actual['metadata']['uid']==controller['metadata']['uid'],'current prepared controller changed')
 report=json.loads((ROOT/'vault-owner/public-report.json').read_bytes());A.need(report['status']=='completed' and report['jwt_smoke_passed'] is True and report['persistence_restart_verified'] is True,'completed original Vault owner required')
 endpoints=[('vault',report['endpoint']),('minio',A.obj(A.KNOWN['MinIO'])['Connection']['Endpoint']),('redis',A.obj(A.KNOWN['Redis'])['Connection']['Endpoint'])]
 D=load('vault_dependency_dns',directory/'p2-source-dns.py')
 def save(p,v):return A.retain(p,v)
 dns=D.SourceDNS(site,r,actual,endpoints,save);dns.probe()
 mirror=Path(json.loads((ROOT/'runtime-mirror.location.json').read_bytes())['Directory'])
 fragments=load('vault_original_data_fragments',directory/'system-backup-initial-provider-fragments.py')
 bridge=SimpleNamespace(need=A.need,decode=A.decode,pinned=A.read,read=lambda p:Path(p).read_bytes(),pin=lambda p:{'File':str(p),'SHA256':hashlib.sha256(Path(p).read_bytes()).hexdigest()},write=A.retain,encoded=A.encode)
 stages=SimpleNamespace(common=lambda:(common,{},plan,{}),get=site.get,runtime_mirror=lambda:mirror)
 owner=ROOT/'vault-owner'
 options=fragments.vault_options_fragment(bridge,stages,bridge.pin(owner/'state.json'),bridge.pin(owner/'public-report.json'),bridge.pin(owner/'ca.pem'),bridge.pin(owner/'init-material.json'))
 A.retain(r/'provider-options.private.json',options)
 last=None
 for phase in ['apply','query','finalize']:
  receipt=r/(phase+'.receipt.private.json')
  if receipt.exists():value=json.loads(receipt.read_bytes())
  else:
   sent=r/(phase+'.sent.private.json');A.need(not sent.exists(),'original provider '+phase+' outcome unknown; retain outputs, never resend')
   out=mirror/('initial-vault-provider-'+phase);out.mkdir(mode=0o700,exist_ok=True)
   A.need(list(out.iterdir())==[],'partial original provider outputs retained')
   argv=[str(AUTHOR),'--mode','provider-materials',*common,'--selection-file',writer['File'],'--selection-sha256',writer['SHA256'],'--output-directory',str(out)]
   for key,flag in [('Deployment','deployment'),('Service','service'),('Claim','claim'),('DataMountPath','data-mount'),('Endpoint','endpoint'),('ClusterID','cluster-id'),('TransitMount','transit-mount'),('KeyName','key-name'),('KeyVersion','key-version'),('JWTMount','jwt-mount')]:argv+=['--provider-'+flag,options[key]]
   for key,flag in [('CA','ca'),('OwnerToken','owner-token')]:argv+=['--provider-'+flag+'-file',options[key]['File'],'--provider-'+flag+'-sha256',options[key]['SHA256']]
   A.retain(sent,{'Argv':argv,'WriterSelection':writer,'ProcessDNSInputs':bridge.pin(r/'source-dns.inputs.json')})
   with (r/(phase+'.stdout.private')).open('xb') as stdout,(r/(phase+'.stderr.private')).open('xb') as stderr:
    p=dns.run(argv,stdout=stdout,stderr=stderr,timeout=180)
   A.retain(r/(phase+'.exit.json'),{'ExitCode':p.returncode})
   A.need(p.returncode==0,'original provider '+phase+' refused; retain private logs and same records')
   raw=(r/(phase+'.stdout.private')).read_bytes();value=json.loads(raw);A.retain(receipt,raw)
  A.need(value['Version']=='pre-adoption-vault-materials.v1' and value['State']=='actual_installed_dependency_inputs_only_no_adoption_or_task_authority','actual original provider observation required')
  for key in ['InstalledObserver','WriterSelection']:A.read(value[key])
  last=value;print('P2_VAULT_PROVIDER_STAGE',phase,value['State'],flush=True)
 result={'Version':'p2-vault-dependency-observed.v1','Receipt':bridge.pin(r/'finalize.receipt.private.json'),
  'WriterSelection':last['WriterSelection'],'InstalledObserver':last['InstalledObserver'],'IAMMutated':False,'NativeHoldClaim':False,'BackupReady':False}
 A.retain(r/'completed.json',result)
 print('P2_VAULT_PROVIDER_DEPENDENCY_READY_NO_HOLD',json.dumps(result),flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool-directory',type=Path,required=True);a=p.parse_args()
 try:main(a.tool_directory)
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:raise SystemExit('P2_VAULT_DEPENDENCY_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
