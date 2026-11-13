#!/usr/bin/env python3
"""Refresh unsigned scope through the original coordinate/source owners."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess

def need(ok, why):
    if not ok: raise ValueError(why)

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def replace_scope(original, coordinates):
    value=copy.deepcopy(original)
    old=value['Deployment']['runtime_sources']['runtime_test_scope']; new=coordinates['RuntimeTestScope']
    need(all(new[k]==old[k] for k in ('Version','InstallationID','ServerUUID','Database','NamespaceUID','Deferred')),
         'original scope identity or deferred rows changed')
    need(new['Version']=='explicit-running-tenant-runtime-test-scope.v3' and
         [r['ID'] for r in new['Deferred']]==[4,5,6] and
         [r['ID'] for r in coordinates['Instances']]==list(range(1,9)) and
         [r['ID'] for r in coordinates['Instances'] if r['Status']=='running']==[1,2,3,7,8],
         'approved runtime roster changed')
    need(new['OriginalInstancesSHA256']!=old['OriginalInstancesSHA256'],'scope refresh not required')
    value['Deployment']['runtime_sources']['runtime_test_scope']=copy.deepcopy(new)
    return value

def main():
    os.umask(0o077);need(os.name=='posix','Linux operator required')
    R=load('renew-p2-source-preparation');A=load('assemble-p2-installation-candidate')
    parent=R.ROOT/'source-preparation-20261113-ca-alias'
    done=json.loads((parent/'completed.json').read_bytes())
    need(done['Receipt']['SHA256']=='b6c38df3fc7cf42f461c7bdd693bda6eefe9ed22ba09bf913e9df10f676b10c8','observed source receipt required')
    receipt=A.obj(done['Receipt']);selected=A.obj(receipt['SourceSelection'])
    need(receipt['GrantsIssued'] is False and receipt['BackupReady'] is False,'unsigned source required')
    for k in ('PartsFile','SourceWritersFile','RedisSourcesFile'):
        need(not selected.get(k) or not Path(selected[k]).exists(),'source facts already exist')
    intent=json.loads((parent/'author.sent.private.json').read_bytes());original=A.obj(intent['Definition'])
    need(dt.datetime.now(dt.timezone.utc)<R.moment(original['Until'])-dt.timedelta(minutes=10),'source window insufficient')
    old=intent['Argv'];need(old[:2]==[str(R.BIN),'author-initial-source-inputs'],'original source invocation required')
    common=old[2:old.index('--definition-file')]
    r=R.ROOT/'source-preparation-20261113-runtime-scope';r.mkdir(mode=0o700,exist_ok=True)
    need(r.resolve()==r and r.stat().st_mode&0o077==0,'private successor journal required')
    def once(label,argv):
        saved=r/(label+'.receipt.private.json');marker=r/(label+'.sent.private.json')
        if saved.exists(): return json.loads(saved.read_bytes())
        need(not marker.exists(),'native '+label+' already sent; reconcile retained output')
        A.retain(marker,{'Argv':argv})
        with (r/(label+'.stdout.private')).open('xb') as stdout,(r/(label+'.stderr.private')).open('xb') as stderr:
            p=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=180)
        A.retain(r/(label+'.exit.json'),{'ExitCode':p.returncode})
        need(p.returncode==0,'native '+label+' refused; retain partial outputs')
        raw=(r/(label+'.stdout.private')).read_bytes();value=json.loads(raw);A.retain(saved,raw);return value
    native=Path('/root/sbk/p2-native-execution-eca964d4')
    build=json.loads((native/'BUILD_RECEIPT.json').read_bytes());binary=native/'system-backup-first-install-materials'
    need(build['SourceRevision']=='eca964d42b96c31cb381531889a39c23a366ffab','reviewed coordinate author required')
    A.read({'File':str(binary),'SHA256':build['Binaries'][binary.name]['SHA256']},128<<20)
    coordout=r/'coordinates';coordout.mkdir(mode=0o700,exist_ok=True)
    coordinates=once('coordinates',[str(binary),'author-initial-source-coordinates',*common,
        '--running-only-runtime-test','1,2,3,7,8:4,5,6','--output-directory',str(coordout)])
    need(coordinates['Version']=='original-initial-source-data-authored.v1' and coordinates['InstanceCount']==8 and
         coordinates['WriterQualified'] is False and coordinates['BackupReady'] is False,'native unsigned coordinates required')
    data=A.obj(coordinates['Coordinates']);A.read(coordinates['KubernetesSnapshot'])
    definition=replace_scope(original,data)
    out=Path(receipt['SourceSelection']['File']).parent.parent/'initial-source-20261113-runtime-scope'
    out.mkdir(mode=0o700,exist_ok=True)
    need(out.resolve()==out and out.stat().st_mode&0o077==0,'private native output required')
    if not (r/'author.sent.private.json').exists():need(not list(out.iterdir()),'new empty output required')
    oldout=Path(receipt['SourceSelection']['File']).parent
    core=definition['Deployment']
    need(core['profile_file']==str(oldout/'execution-profile.json') and core['capture_modules']['path']==str(oldout/'capture-materials.json'),'parent output paths differ')
    core['profile_file']=str(out/'execution-profile.json');core['capture_modules']['path']=str(out/'capture-materials.json')
    pin=A.retain(r/'definition.private.json',definition)
    A.read({'File':str(R.BIN),'SHA256':R.BIN_SHA},128<<20)
    result=once('author',[str(R.BIN),'author-initial-source-inputs',*common,'--definition-file',pin['File'],
        '--definition-sha256',pin['SHA256'],'--output-directory',str(out)])
    need(result['Version']=='original-initial-source-inputs-authored.v1' and result['GrantsIssued'] is False and result['BackupReady'] is False,'native unissued source required')
    for k in ('Deployment','MaterialsTemplate','ExecutionProfile','SourceSelection'):A.read(result[k])
    complete={'Version':'p2-runtime-scope-source-reauthored.v1','Receipt':A.retain(r/'receipt.private.json',(r/'author.receipt.private.json').read_bytes()),
        'Definition':pin,'Coordinates':coordinates['Coordinates'],'SourceSelection':result['SourceSelection'],'SourceAPI':done['SourceAPI'],
        'VaultWriterSelection':done['VaultWriterSelection'],'Until':definition['Until'],'DeferredIDs':[4,5,6],
        'TokenReissued':False,'GrantsIssued':False,'BackupReady':False}
    A.retain(r/'completed.json',complete)
    print('P2_RUNTIME_SCOPE_SOURCE_REAUTHORED_NO_HOLD',json.dumps(complete),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_RUNTIME_SCOPE_SOURCE_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
