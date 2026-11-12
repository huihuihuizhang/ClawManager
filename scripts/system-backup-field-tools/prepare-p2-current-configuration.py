#!/usr/bin/env python3
"""Compile the current original producers and invoke only initial source author."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import traceback
from types import SimpleNamespace

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NATIVE=Path('/root/sbk/p2-native-execution-eca964d4')

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main(directory,resume_csi_data=False):
 os.umask(0o077)
 A=load('current_configuration_assembly',directory/'assemble-p2-installation-candidate.py')
 G=load('current_configuration_data',directory/'prepare-p2-configuration-data.py')
 A.need(os.name=='posix','Linux operator required')
 r=ROOT/'initial-source-author';r.mkdir(mode=0o700,exist_ok=True)
 A.need(r.resolve(strict=True)==r and r.stat().st_mode&0o077==0,'original private initial source records required')
 print('P2_INITIAL_SOURCE_RECORDS',r,flush=True)
 current=ROOT/'current-source-inputs'
 completed=json.loads((current/'completed.json').read_bytes())
 A.need(completed['Version']=='p2-current-source-inputs.v1' and completed['SourceCount']==8 and completed['TenantProRetained'] is True,
  'completed current source inventory required')
 for key in ['CoordinatesReceipt','WriterReceipt','RawIndex','SourceConfig']:A.read(completed[key])
 native_receipt=r/'initial-source.receipt.private.json';sent=r/'initial-source.sent.private.json'
 def validate(value):
  A.need(value['Version']=='original-initial-source-inputs-authored.v1','actual original initial source author receipt required')
  for key in ['Deployment','MaterialsTemplate','ExecutionProfile','SourceSelection']:A.read(value[key])
  return value
 if native_receipt.exists():
  validate(json.loads(native_receipt.read_bytes()))
  print('P2_INITIAL_SOURCE_INPUTS_ALREADY_AUTHORED_NO_HOLD',r,flush=True);return
 A.need(not sent.exists(),'initial source author send unknown; retain its outputs, never resend')
 mirror=Path(json.loads((ROOT/'runtime-mirror.location.json').read_bytes())['Directory'])
 compiled_dir=r/'configuration-data';compiled_dir.mkdir(mode=0o700,exist_ok=True)
 pairs={'raw_index':completed['RawIndex'],'coordinates_receipt':completed['CoordinatesReceipt'],'writer_receipt':completed['WriterReceipt'],
  'relay_receipt':G.local_pin(ROOT/'controller-relay/relay-pki.receipt.private.json'),
  'observer_receipt':G.local_pin(ROOT/'observer-host-renewal/observer-receipt.canonical.private.json'),
  'app_image_data':G.local_pin(ROOT/'execution-image-candidates/app/image-data.json'),
  'worker_image_data':G.local_pin(ROOT/'execution-image-candidates/worker/image-data.json'),
  'runtime_agent_tls':G.local_pin(ROOT/'runtime-agent.receipt.private.json'),
  'runtime_agent_rotation':G.local_pin(ROOT/'runtime-rotation/completed.json')}
 args=SimpleNamespace(output_directory=compiled_dir)
 for name in ['raw_index','coordinates_receipt','writer_receipt','relay_receipt','observer_receipt','app_image_data','worker_image_data',
  'runtime_agent_tls','runtime_agent_rotation','source_api','runtime_issuers']:
  value=pairs.get(name,{})
  setattr(args,name+'_file',value.get('File'));setattr(args,name+'_sha256',value.get('SHA256'))
 if resume_csi_data:
  old_pin=G.local_pin(compiled_dir/'ready-producers.json');old=A.obj(old_pin)
  A.need(old['CompleteInputsHelper']['SHA256']=='c3c26a71f18dddff3315045b0c8e1849302e641bee49374759010b37d79f8d06' and
   not (compiled_dir/'configuration-data.json').exists() and not (compiled_dir/'assembly-inputs.json').exists() and
   not (r/'initial-source.inputs.json').exists(),'known pre-author CSI DATA refusal required')
  native_out=mirror/'initial-source-inputs'
  A.need(not native_out.exists() or list(native_out.iterdir())==[],'native partial outputs prevent DATA continuation')
  A.need(old['Coordinates']==A.obj(completed['CoordinatesReceipt'])['Coordinates'] and
   old['WriterSelection']==A.obj(completed['WriterReceipt'])['Selection'],'same original current coordinate/selection pins required')
  for key,name in [('RelayPKI','relay_receipt'),('ObserverReceipt','observer_receipt'),('AppImage','app_image_data'),
   ('WorkerImage','worker_image_data'),('RuntimeAgentTLS','runtime_agent_tls'),('RuntimeAgentRotation','runtime_agent_rotation')]:
   A.need(old[key]==pairs[name],'original selected DATA producer changed')
  successor=compiled_dir/'ready-producers.csi-successor.json'
  if successor.exists():
   ready=G.local_pin(successor);updated=A.obj(ready)
   A.need({k:v for k,v in updated.items() if k not in ['CompleteInputsHelper','ProviderTopologyHelper']}==
    {k:v for k,v in old.items() if k not in ['CompleteInputsHelper','ProviderTopologyHelper']},'retained CSI DATA producer selection changed')
   for key,name in [('CompleteInputsHelper','system-backup-initial-complete-inputs.py'),('ProviderTopologyHelper','system-backup-initial-provider-topology.py')]:
    A.read(updated[key]);A.need(updated[key]['SHA256']==G.ORIGINAL_HELPERS[name],'retained reviewed DATA helper changed')
  else:
   updated=dict(old)
   for key,name in [('CompleteInputsHelper','system-backup-initial-complete-inputs.py'),('ProviderTopologyHelper','system-backup-initial-provider-topology.py')]:
    selected_helper=G.local_pin(directory/name)
    A.need(selected_helper['SHA256']==G.ORIGINAL_HELPERS[name],'reviewed DATA helper bytes required')
    updated[key]=selected_helper
   ready=A.retain(successor,updated)
  A.retain(r/'csi-data-continuation.json',{'Version':'p2-pre-author-csi-data-continuation.v1','Original':old_pin,'Successor':ready,
   'NativeAuthorPreviouslySent':False,'ExecutionWindowPreserved':True,'BackupReady':False})
  print('P2_CSI_DATA_CONTINUATION_NO_NATIVE_REPLAY',flush=True)
 else:ready=G.prepare_index(args)
 result=G.compile_data(A.obj(ready),compiled_dir,mirror)
 definition=A.assemble(A.obj(result['AssemblyInputs']),datetime.datetime.now(datetime.timezone.utc))
 selected=A.retain(r/'initial-source.inputs.json',definition)
 A.retain(r/'configuration-data.result.json',result)
 out=Path(result['NativeOutputDirectory']);out.mkdir(mode=0o700,exist_ok=True)
 A.need(out.resolve(strict=True)==out and out.stat().st_mode&0o077==0 and list(out.iterdir())==[],
  'original empty native initial source output directory required; retain partial outputs')
 print('P2_CURRENT_CONFIGURATION_DATA_ASSEMBLED',json.dumps(selected),flush=True)
 common=json.loads((ROOT/'observer.sent.private.json').read_bytes())['Argv'];common=common[1:common.index('--definition-file')]
 binary=NATIVE/'system-backup-first-install-materials';build=json.loads((NATIVE/'BUILD_RECEIPT.json').read_bytes())
 A.need(build['SourceRevision']=='eca964d42b96c31cb381531889a39c23a366ffab' and
  hashlib.sha256(binary.read_bytes()).hexdigest()==build['Binaries'][binary.name]['SHA256'],'actual fixed-source initial source author executable changed')
 argv=[str(binary),'author-initial-source-inputs',*common,'--definition-file',selected['File'],
  '--definition-sha256',selected['SHA256'],'--output-directory',str(out)]
 A.retain(sent,{'Argv':argv,'Definition':selected,'ReadyProducers':ready})
 with (r/'initial-source.stdout.private').open('xb') as stdout,(r/'initial-source.stderr.private').open('xb') as stderr:
  p=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=180)
 A.need(p.returncode==0,'original initial source author refused; retain same intent and private outputs')
 raw=(r/'initial-source.stdout.private').read_bytes();value=validate(json.loads(raw));A.retain(native_receipt,raw)
 print('P2_INITIAL_SOURCE_INPUTS_AUTHORED_NO_HOLD',json.dumps(value),flush=True)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool-directory',type=Path,required=True);p.add_argument('--resume-csi-data',action='store_true');a=p.parse_args()
 try:main(a.tool_directory,a.resume_csi_data)
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:
  if isinstance(e,KeyError):
   key=e.args[0] if e.args else None
   if isinstance(key,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_./-]{0,100}',key):print('P2_CONFIGURATION_MISSING_FIELD',key,flush=True)
  for frame in traceback.extract_tb(e.__traceback__):
   print('P2_CONFIGURATION_ERROR_LOCATION',Path(frame.filename).name,frame.lineno,frame.name,flush=True)
  raise SystemExit('P2_CURRENT_CONFIGURATION_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
