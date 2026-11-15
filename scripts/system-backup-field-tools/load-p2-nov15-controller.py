#!/usr/bin/env python3
"""Load this site's approved Secret-selection controller before source signing."""
import copy
import datetime as dt
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def renew_relay(A,C,R,journal,fresh):
    relay=journal/'relay';relay.mkdir(mode=0o700,exist_ok=True)
    previous=C.ROOT/'controller-relay-renewal-20261115'
    old=A.decode((previous/'relay-pki.inputs.json').read_bytes())
    path=relay/'inputs.json'
    if path.exists():
        inputs=A.decode(path.read_bytes());A.need(inputs['ControllerPod']==fresh['Pod'] and inputs['ControllerDeployment']==fresh['Deployment'],'relay controller changed; query original operation')
    else:
        inputs=copy.deepcopy(old);inputs.update(ControllerPod=fresh['Pod'],ControllerDeployment=fresh['Deployment'],OutputDirectory=str(C.MIRROR/'relay-pki-20261115-secret-controller'),Until=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=6)).isoformat().replace('+00:00','Z'))
        A.retain(path,inputs)
    out=Path(inputs['OutputDirectory'])
    if not out.exists():out.mkdir(mode=0o700)
    pin={'File':str(path),'SHA256':A.sha(path.read_bytes())}
    argv=A.decode((previous/'relay-pki.sent.private.json').read_bytes())['Argv']
    argv[argv.index('--inputs-file')+1]=pin['File'];argv[argv.index('--inputs-sha256')+1]=pin['SHA256']
    runner=SimpleNamespace(run=lambda args,**kwargs:subprocess.run(args,stdin=subprocess.DEVNULL,**kwargs))
    label='native'
    if (relay/'native.sent.private.json').exists() and not (relay/'native.receipt.private.json').exists():
        argv[argv.index('--mode')+1]='query';label='query'
    value=R.once(A,runner,relay,label,argv)
    A.need(value['Version']=='original-relay-pki-result.v1' and value['State']=='original_relay_pki_material_issued_service_tls_not_yet_verified' and value['DeploymentUID']==fresh['DeploymentUID'],'relay receipt differs')
    receipt=relay/(label+'.receipt.private.json')
    result={'Receipt':{'File':str(receipt),'SHA256':A.sha(receipt.read_bytes())}}
    A.retain(relay/'completed.json',result)
    print('P2_NOV15_CONTROLLER_RELAY_CONFIRMED',json.dumps(result),flush=True)

def run():
    os.umask(0o077)
    A,C,L,P,F,Q,O,R,T=[load(n) for n in ('assemble-p2-installation-candidate','continue-p2-nov14','load-p2-formal-vault','p2-nov14-delivery','p2-vault-local-forward','preflight-p2-team-continuation','build-p2-controller-overlay','resume-p2-recovered-source','resume-p2-tenant-team-source')]
    package=Path(__file__).resolve().parent;build=A.decode((package/'BUILD_RECEIPT.json').read_bytes())
    Q.linked_release(A,package,build,O.TOOLS)
    prior=C.ROOT/'p2-team-credential-renewal-20261115';journal=C.ROOT/'controller-secret-scope-20261115';journal.mkdir(mode=0o700,exist_ok=True)
    api=journal/'api';api.mkdir(mode=0o700,exist_ok=True);site=L.Site(api,A)
    previous=A.decode((prior/'loaded.json').read_bytes());old_plan=A.decode((prior/'delivery-plan.private.json').read_bytes());old_spec=A.obj(old_plan['DesiredSpec']);old_secret=A.obj(old_plan['Secret'])
    saved=journal/'delivery-plan.private.json'
    allowed=old_spec if not saved.exists() else A.obj(A.decode(saved.read_bytes())['DesiredSpec'])
    current=site.get('deployment',previous['Controller']['Deployment'])
    A.need(current['metadata']['uid']==previous['Controller']['DeploymentUID'] and current['spec'] in (old_spec,allowed),'controller drift before image work')
    L.verify_secret(site.get('secret',old_secret['metadata']['name']),old_secret)
    minted=A.decode((prior/'mint/native.receipt.private.json').read_bytes());native=A.obj(minted['Observer']);token=A.read({'File':native['TokenFile'],'SHA256':native['TokenSHA256']})
    until=dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=45)
    for certificate in C.renewed_credentials(A):A.need(dt.datetime.fromisoformat(certificate['NotAfter'].replace('Z','+00:00'))>until,'renew runtime certificates before image work')
    parent=A.decode((T.PARENT/'completed.json').read_bytes());C.approved_secret_scope(A,A.obj(parent['Definition']))
    L.verify_metadata(A,F,site,journal,native,token,minted['Workload'],until)
    Q.registry_and_space(A,O,package,build)
    print('P2_NOV15_CONTROLLER_PREFLIGHT_PASSED',flush=True)
    import fcntl
    image_dir=journal/'image-work';image_dir.mkdir(mode=0o700,exist_ok=True)
    with (image_dir/'build.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        image=O.build_image(package,image_dir)
    A.need(image['SourceRevision']==build['SourceRevision'] and image['Binaries']==build['Binaries'],'image inputs changed')
    if not saved.exists():
        current=site.get('deployment',previous['Controller']['Deployment']);A.need(current['spec']==old_spec,'controller changed during image build')
        secret,desired,patch,digest=P.rotation_delivery(current,old_secret,native,token,image['Image'])
        A.retain(saved,{'Secret':A.retain(journal/'secret.private.json',secret),'DesiredSpec':A.retain(journal/'desired-spec.private.json',desired),'Patch':patch,'ObserverSHA256':digest})
    plan=A.decode(saved.read_bytes());secret=A.obj(plan['Secret']);desired=A.obj(plan['DesiredSpec'])
    A.need(all(c['image']==image['Image'] for c in desired['template']['spec']['containers']),'saved image differs')
    current=site.get('deployment',previous['Controller']['Deployment'])
    A.need(current['metadata']['uid']==previous['Controller']['DeploymentUID'] and not current['metadata'].get('deletionTimestamp'),'controller replaced')
    if current['spec']!=desired:
        A.need(current['spec']==old_spec,'controller changed before delivery')
        patch=copy.deepcopy(plan['Patch']);patch[1]['value']=current['metadata']['resourceVersion']
        dry=A.decode(site.call(['patch','deployment',current['metadata']['name'],'--dry-run=server','--type=json','--patch-file=/dev/stdin','-o','json'],json.dumps(patch).encode()))
        A.need(dry['spec']==desired,'admission changed intended controller spec')
        existing=site.call(['get','secret',secret['metadata']['name'],'--ignore-not-found','-o','json'])
        if not existing.strip():site.send('secret-create',['create','-f','-','-o','json'],json.dumps(secret).encode())
        L.verify_secret(site.get('secret',secret['metadata']['name']),secret)
        site.send('controller-update',['patch','deployment',current['metadata']['name'],'--type=json','--patch-file=/dev/stdin','-o','json'],json.dumps(patch).encode())
    site.call(['rollout','status','deployment/'+previous['Controller']['Deployment'],'--timeout=180s'],timeout=210)
    fresh,pod=C.controller_ref(A,site,L,previous,desired)
    for name in O.TOOLS:
        actual=site.call(['exec',fresh['Pod'],'-c','controller','--','sha256sum','/usr/local/bin/'+name]).decode().split()
        A.need(actual==[build['Binaries'][name]['SHA256'],'/usr/local/bin/'+name],'running tool differs')
    for name,digest in [('observer.json',plan['ObserverSHA256']),('token',native['TokenSHA256'])]:
        path=L.MOUNT+'/'+name
        actual=site.call(['exec',fresh['Pod'],'-c','controller','--','sh','-ec','test -f "$1"; test ! -L "$1"; stat -c "%a %u" "$1"; sha256sum "$1"','readback',path]).decode().splitlines()
        A.need(actual==['600 65532',digest+'  '+path],'loaded provider material differs')
    mint=journal/'mint';mint.mkdir(mode=0o700,exist_ok=True);A.retain(mint/'native.receipt.private.json',(prior/'mint/native.receipt.private.json').read_bytes())
    result={'Controller':fresh,'Image':image['Image'],'BackupReady':False}
    A.retain(journal/'loaded.json',result);print('P2_NOV15_SECRET_CONTROLLER_LOADED',json.dumps(result),flush=True)
    renew_relay(A,C,R,journal,fresh)

if __name__=='__main__':
    try:run()
    except Exception as e:raise SystemExit('P2_CONTROLLER_LOAD_UNCONFIRMED '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
