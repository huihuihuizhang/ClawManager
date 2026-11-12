#!/usr/bin/env python3
"""Correct this proven pre-write ResourceSourceMount decode refusal only."""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
ORIGINAL_SHA='8394d48a963862bb0693cdc96b4884b06c8b5d9d1eccd0d4b4a14aef7c68cc55'
INSPECT=Path('/root/sbk/p2-initial-inspect-a1bb043d/system-backup-initial-source-inspect')
INSPECT_SHA='a0ba1ce445c11de9561073d12a2a30296797ee826f2f1a9a2eb028c4623c88ed'
AUTHOR_SHA='9421fa13fe984bf279c036467d34d8815912addcb318ab962be5a38f7754dced'

def need(ok,why):
 if not ok:raise ValueError(why)
def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(p):return {'File':str(p),'SHA256':hashlib.sha256(p.read_bytes()).hexdigest()}
def save(p,v):
 raw=v if isinstance(v,bytes) else encode(v)
 if p.exists():need(not p.is_symlink() and p.read_bytes()==raw,'original wire correction record changed')
 else:
  with p.open('xb') as f:os.chmod(p,0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 return pin(p)

def corrected_definition(original,api,before,until):
 need(original['Version']=='original-initial-source-author-inputs.v1','original initial source input version required')
 connection=api['connection']
 expected={'Server':connection['Endpoint'],'CAFile':connection['CA']['File'],'CASHA256':connection['CA']['SHA256'],'TokenFile':connection['Credential']['File']}
 need(original['Materials']['Discovery']['SourceAPI']==expected,'exact original source API credential/TLS mapping required')
 wanted=copy.deepcopy(original)
 wanted['Materials']['Discovery']['SourceAPI']={new:expected[old] for old,new in
  [('Server','server'),('CAFile','ca_file'),('CASHA256','ca_sha256'),('TokenFile','token_file')]}
 wanted['NotBefore']=before;wanted['Until']=until
 return wanted

def main(directory):
 os.umask(0o077);need(os.name=='posix','Linux operator required')
 s=importlib.util.spec_from_file_location('wire_repair_assembly',directory/'assemble-p2-installation-candidate.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A)
 parent=ROOT/'initial-source-author';r=parent/'resource-api-wire-correction';r.mkdir(mode=0o700,exist_ok=True)
 need(r.resolve(strict=True)==r and r.stat().st_mode&0o077==0,'original private wire correction records required')
 old_sent=parent/'initial-source.sent.private.json';intent=json.loads(old_sent.read_bytes());old_pin=intent['Definition']
 need(old_pin['SHA256']==ORIGINAL_SHA,'same original refused initial definition required')
 original=A.obj(old_pin);argv=intent['Argv'];out=Path(argv[argv.index('--output-directory')+1])
 need(out==Path('/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-inputs'),'original output coordinates required')
 need(pin(INSPECT)['SHA256']==INSPECT_SHA and pin(Path(argv[0]))['SHA256']==AUTHOR_SHA,'original diagnostic and author ELF bytes required')
 need((parent/'initial-source.stdout.private').read_bytes()==(parent/'initial-source.stderr.private').read_bytes()==b'',
  'original zero-log refusal required')
 completed=r/'completed.json'
 if completed.exists():
  v=json.loads(completed.read_bytes());A.read(v['Receipt'])
  print('P2_INITIAL_SOURCE_INPUTS_ALREADY_AUTHORED_NO_HOLD',r,flush=True);return
 need(not (r/'native-author.sent.private.json').exists(),'corrected native author send unknown; preserve and reconcile its outputs')
 need(out.is_dir() and list(out.iterdir())==[],'original pre-write refusal requires no native output or partial material')
 def inspect(label,selected):
  args=[str(INSPECT),'--definition-file',selected['File'],'--definition-sha256',selected['SHA256'],'--output-directory',str(out)]
  p=subprocess.run(args,capture_output=True,timeout=35)
  save(r/(label+'.stdout.private'),p.stdout);save(r/(label+'.stderr.private'),p.stderr)
  need(p.returncode==0,'read-only native definition inspection unconfirmed')
  value=json.loads(p.stdout);need(value['Version']=='original-initial-source-definition-inspection.v1' and value['NativeAuthorCalled'] is False and value['BackupReady'] is False,'read-only original inspector required')
  return value
 refused=inspect('original-definition-inspection',old_pin)
 need(refused['Stage']=='materials_decode' and refused['Field']=='CAFile' and refused['DefinitionDecoded'] and
  refused['DeploymentValid'] and refused['ProfileValid'] and refused['OutputPathsMatch'] and not refused['MaterialsDecoded'],
  'confirmed original ResourceSourceMount pre-write decode refusal required')
 api=A.obj(A.KNOWN['SourceAPI']);A.read(api['connection']['CA']);A.read(api['connection']['Credential'])
 window_file=r/'preparation-window.json'
 if window_file.exists():window=json.loads(window_file.read_bytes())
 else:
  now=datetime.datetime.now(datetime.timezone.utc)
  moment=lambda v:datetime.datetime.fromisoformat(v.replace('Z','+00:00'))
  observer=json.loads((ROOT/'observer.receipt.private.json').read_bytes());agent=json.loads((ROOT/'runtime-agent.receipt.private.json').read_bytes())
  until=min(now+datetime.timedelta(hours=1),datetime.datetime.fromtimestamp(api['token_expires_unix'],datetime.timezone.utc),moment(observer['NotAfter']),moment(agent['NotAfter']))
  need(until>now+datetime.timedelta(minutes=5),'genuine source API/certificate renewal required before a new preparation window')
  window={'NotBefore':(now-datetime.timedelta(seconds=5)).isoformat().replace('+00:00','Z'),'Until':until.isoformat().replace('+00:00','Z')}
  save(window_file,window)
 need(datetime.datetime.now(datetime.timezone.utc)<datetime.datetime.fromisoformat(window['Until'].replace('Z','+00:00')),'retained corrected preparation window expired')
 wanted=corrected_definition(original,api,window['NotBefore'],window['Until'])
 selected=save(r/'initial-source.inputs.json',wanted)
 check=inspect('corrected-definition-inspection',selected)
 print('P2_CORRECTED_INITIAL_DEFINITION_INSPECTION',json.dumps(check),flush=True)
 need(all(check[k] is True for k in ['DefinitionDecoded','DeploymentValid','ProfileValid','OutputPathsMatch','MaterialsDecoded','MaterialsValid']),
  'corrected definition still refused by native shape inspection; no corrected author sent')
 save(r/'lineage.json',{'Version':'p2-proven-prewrite-source-api-wire-correction.v1','OriginalIntent':pin(old_sent),'OriginalDefinition':old_pin,
  'Definition':selected,'SourceAPI':A.KNOWN['SourceAPI'],'CoreUnchanged':wanted['Deployment']==original['Deployment'],
  'OriginalPreparationWindow':{'NotBefore':original['NotBefore'],'Until':original['Until']},'PreparationWindow':window,'GrantsExtended':False,'BackupReady':False})
 corrected=list(argv);corrected[corrected.index('--definition-file')+1]=selected['File'];corrected[corrected.index('--definition-sha256')+1]=selected['SHA256']
 need(list(out.iterdir())==[],'native outputs changed before corrected author dispatch')
 save(r/'native-author.sent.private.json',{'Argv':corrected,'OriginalRefusedIntent':pin(old_sent),'Definition':selected,'ReadOnlyInspection':pin(r/'corrected-definition-inspection.stdout.private')})
 with (r/'native-author.stdout.private').open('xb') as stdout,(r/'native-author.stderr.private').open('xb') as stderr:
  p=subprocess.run(corrected,stdout=stdout,stderr=stderr,timeout=180)
 save(r/'native-author.exit.json',{'ExitCode':p.returncode})
 need(p.returncode==0,'corrected original author refused; retain same intent and partial outputs; exit '+str(p.returncode))
 raw=(r/'native-author.stdout.private').read_bytes();v=json.loads(raw)
 need(v['Version']=='original-initial-source-inputs-authored.v1','actual original initial source receipt required')
 for key in ['Deployment','MaterialsTemplate','ExecutionProfile','SourceSelection']:A.read(v[key])
 receipt=save(r/'native-author.receipt.private.json',raw)
 save(parent/'initial-source.receipt.private.json',raw)
 value={'Version':'p2-initial-source-wire-correction-completed.v1','Receipt':receipt,'Definition':selected,'OriginalRefusedIntent':pin(old_sent),
  'AuthorIntent':pin(r/'native-author.sent.private.json'),'NativeHoldClaim':False,'BackupReady':False}
 save(completed,value);save(parent/'completed.json',value)
 print('P2_INITIAL_SOURCE_INPUTS_AUTHORED_NO_HOLD',json.dumps(v),flush=True)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool-directory',type=Path,required=True);a=p.parse_args()
 try:main(a.tool_directory)
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:raise SystemExit('P2_INITIAL_SOURCE_WIRE_CORRECTION_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
