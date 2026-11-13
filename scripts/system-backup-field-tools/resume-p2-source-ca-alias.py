#!/usr/bin/env python3
"""Reauthor the retained November source after correcting CA path aliases."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
    os.umask(0o077)
    R=load('renew-p2-source-preparation');A=load('assemble-p2-installation-candidate')
    R.need(os.name=='posix','Linux operator required')
    parent=R.ROOT/'source-preparation-20261113'
    R.need(json.loads((parent/'author.exit.json').read_bytes())=={'ExitCode':1} and not (parent/'completed.json').exists(),'confirmed failed parent required')
    intent=json.loads((parent/'author.sent.private.json').read_bytes())
    original=A.obj(intent['Definition'])
    definition,_,_=R.november_trust(A,original)
    R.need(definition!=original,'certificate alias correction absent')
    api=A.obj(intent['SourceAPI'])
    A.read(api['connection']['Credential'])
    R.need(dt.datetime.now(dt.timezone.utc)<R.moment(definition['Until'])-dt.timedelta(minutes=5),'existing source window expired')
    r=R.ROOT/'source-preparation-20261113-ca-alias';r.mkdir(mode=0o700,exist_ok=True)
    R.need(r.resolve()==r and r.stat().st_mode&0o077==0 and not (r/'author.sent.private.json').exists(),'private unsent successor required')
    old=intent['Argv']
    R.need(old[:2]==[str(R.BIN),'author-initial-source-inputs'],'original native author required')
    old_out=Path(old[old.index('--output-directory')+1])
    selected=json.loads((old_out/'source-selection.json').read_bytes())
    for key in ('PartsFile','SourceWritersFile','RedisSourcesFile'):
        R.need(not selected.get(key) or not Path(selected[key]).exists(),'source facts already exist')
    out=old_out.parent/'initial-source-20261113-ca-alias';out.mkdir(mode=0o700,exist_ok=True)
    R.need(out.resolve()==out and out.stat().st_mode&0o077==0 and not list(out.iterdir()),'new empty output required')
    core=definition['Deployment']
    R.need(core['profile_file']==str(old_out/'execution-profile.json') and core['capture_modules']['path']==str(old_out/'capture-materials.json'),'parent output paths differ')
    core['profile_file']=str(out/'execution-profile.json');core['capture_modules']['path']=str(out/'capture-materials.json')
    agent=definition['RuntimeAgent'];A.read(agent['CA'])
    R.need(agent['CA']['File']==core['runtime_sources']['agent_ca_file'] and agent['CA']['SHA256']==core['runtime_sources']['agent_ca_sha256'],'agent pin mismatch')
    A.read({'File':str(R.BIN),'SHA256':R.BIN_SHA},128<<20)
    pin=A.retain(r/'definition.private.json',definition);argv=list(old)
    for flag,value in [('--definition-file',pin['File']),('--definition-sha256',pin['SHA256']),('--output-directory',str(out))]:argv[argv.index(flag)+1]=value
    A.retain(r/'author.sent.private.json',{'Argv':argv,'Definition':pin,'ParentDefinition':intent['Definition'],'SourceAPI':intent['SourceAPI']})
    with (r/'stdout.private').open('xb') as stdout,(r/'stderr.private').open('xb') as stderr:
        result=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=180)
    A.retain(r/'exit.json',{'ExitCode':result.returncode})
    R.need(result.returncode==0,'native author refused; retain successor outputs')
    raw=(r/'stdout.private').read_bytes();receipt=json.loads(raw)
    R.need(receipt['Version']=='original-initial-source-inputs-authored.v1' and receipt['GrantsIssued'] is False and receipt['BackupReady'] is False,'native unissued receipt required')
    for key in ('Deployment','MaterialsTemplate','ExecutionProfile','SourceSelection'):A.read(receipt[key])
    done={'Version':'p2-source-ca-alias-reauthored.v1','Receipt':A.retain(r/'receipt.private.json',raw),'SourceSelection':receipt['SourceSelection'],
          'SourceAPI':intent['SourceAPI'],'VaultWriterSelection':intent['VaultWriterSelection'],'Until':definition['Until'],'TokenReissued':False,'GrantsIssued':False,'BackupReady':False}
    A.retain(r/'completed.json',done)
    print('P2_SOURCE_CA_ALIAS_REAUTHORED_NO_HOLD',json.dumps(done),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_SOURCE_CA_ALIAS_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
