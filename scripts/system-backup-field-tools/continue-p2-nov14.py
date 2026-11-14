#!/usr/bin/env python3
"""One P2 continuation: reissue metadata identity, deploy exact tools, refresh source."""
import argparse
import base64
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
JOURNAL=ROOT/'p2-team-continuation-20261114'
MIRROR=Path('/run/system-backup/runtime/p2-renew-1048e373bfe0')
def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def controller_ref(A,site,L,selected,desired):
    ref=copy.deepcopy(selected['Controller']);dep=site.get('deployment',ref['Deployment'])
    A.need(dep['metadata']['uid']==ref['DeploymentUID'] and dep['spec']==desired and not dep['metadata'].get('deletionTimestamp') and
           dep['status'].get('observedGeneration')==dep['metadata']['generation'] and dep['status'].get('readyReplicas')==dep['status'].get('updatedReplicas')==desired.get('replicas')==1,'controller rollout unconfirmed')
    selector=','.join(k+'='+v for k,v in desired['selector']['matchLabels'].items())
    listing=A.decode(site.call(['get','pods','-l',selector,'-o','json']))
    A.need(not listing.get('metadata',{}).get('continue'),'partial controller Pod census')
    pods=[p for p in listing['items'] if not p['metadata'].get('deletionTimestamp')];A.need(len(pods)==1,'one settled controller required');pod=pods[0]
    parents=[o for o in pod['metadata'].get('ownerReferences',[]) if o.get('controller')]
    A.need(len(parents)==1 and parents[0]['kind']=='ReplicaSet','controller Pod owner changed')
    rs=site.get('replicaset',parents[0]['name']);owners=[o for o in rs['metadata'].get('ownerReferences',[]) if o.get('controller')]
    A.need(rs['metadata']['uid']==parents[0]['uid'] and not rs['metadata'].get('deletionTimestamp') and
           [(o['kind'],o['uid']) for o in owners]==[('Deployment',ref['DeploymentUID'])],'controller owner chain changed')
    L.validate_running_pod(desired,pod)
    A.need(pod['status']['phase']=='Running' and len(pod['status'].get('containerStatuses',[]))==2 and all(c.get('ready') for c in pod['status']['containerStatuses']) and
           site.get('serviceaccount',ref['ServiceAccount'])['metadata']['uid']==ref['ServiceAccountUID'],'controller identity/readiness changed')
    ref.update(Pod=pod['metadata']['name'],PodUID=pod['metadata']['uid'],ReplicaSet=rs['metadata']['name'],ReplicaSetUID=rs['metadata']['uid'])
    return ref,pod

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image-receipt',required=True);parser.add_argument('--image-sha256',required=True);args=parser.parse_args()
    os.umask(0o077)
    A,L,H,R,N,D,F,T,P=[load(n) for n in ('assemble-p2-installation-candidate','load-p2-formal-vault','prepare-p2-longhorn-provider-loaded','resume-p2-recovered-source','renew-p2-source-preparation','p2-source-dns','p2-vault-local-forward','resume-p2-tenant-team-source','p2-nov14-delivery')]
    package=Path(__file__).resolve().parent; build=A.decode((package/'BUILD_RECEIPT.json').read_bytes())
    A.need(build['SourceRevision']==(package/'SOURCE_REVISION').read_text().strip(),'package revision mismatch')
    for name in ('system-backup-source-registries','system-backup-first-install-materials','system-backup-v2-controller'):
        A.read({'File':str(package/name),'SHA256':build['Binaries'][name]['SHA256']},256<<20)
    image=A.obj({'File':args.image_receipt,'SHA256':args.image_sha256})
    A.need(image['Version']=='p2-controller-image.v1' and image['SourceRevision']==build['SourceRevision'] and image['Binaries']==build['Binaries'],'image/binary revision mismatch')
    # The already confirmed, unsigned recovered source remains the source of business scope.
    parent=A.decode((T.PARENT/'completed.json').read_bytes())
    A.need(parent['Receipt']['SHA256']==T.RECEIPT_SHA and parent['Definition']['SHA256']==T.DEFINITION_SHA and parent['SourceSelection']['SHA256']==T.SELECTION_SHA and parent['GrantsIssued'] is False,'recovered parent differs')
    original=A.obj(parent['Definition']);selected=A.obj(parent['SourceSelection']);A.read(parent['Receipt'])
    for k in ('PartsFile','SourceWritersFile','RedisSourcesFile'):A.need(not selected.get(k) or not Path(selected[k]).exists(),'parent source facts already issued')
    observer=A.obj({'File':str(ROOT/'renewal-20261113/observer/receipt.private.json'),'SHA256':'c0d69a9d9d1254a40993fb5516ed936325f265a74b0dde4b3823ea52fdd010f5'})
    agent=A.obj({'File':str(ROOT/'renewal-20261113/runtime-unique/runtime-agent.receipt.private.json'),'SHA256':'1d61b1d11b3427fd46d9d2eab3bd04f19daf74ae3a674a9f2275269c1810f149'})
    now=dt.datetime.now(dt.timezone.utc);before,until=T.window(now,now+dt.timedelta(hours=8),N.moment(observer['NotAfter']),N.moment(agent['NotAfter']),30)
    JOURNAL.mkdir(mode=0o700,exist_ok=True);A.need(JOURNAL.resolve()==JOURNAL and JOURNAL.stat().st_mode&0o077==0,'private continuation journal required')
    print('P2_NOV14_RECORDS',JOURNAL,flush=True);site=L.Site(JOURNAL,A)
    R.verify_app(A,site)
    prior=A.obj({'File':str(L.PARENT/'receipt.private.json'),'SHA256':L.RECEIPT_SHA});old_secret=A.obj(prior['SecretManifest'])
    L.verify_secret(site.get('secret',old_secret['metadata']['name']),old_secret)
    old_args=A.decode((T.PARENT/'author.sent.private.json').read_bytes())['Argv']
    common=old_args[2:old_args.index('--definition-file')]
    old_desired=A.obj(A.decode((H.PARENT/'delivery-plan.private.json').read_bytes())['DesiredSpec'])
    mint=JOURNAL/'mint';mint.mkdir(mode=0o700,exist_ok=True)
    saved=mint/'native.receipt.private.json'
    if not saved.exists():
        pod=H.current_controller(site,A,L,selected,old_desired)
        A.need(not (mint/'native.sent.private.json').exists(),'metadata mint outcome unknown; do not reissue')
        writer=A.obj(parent['VaultWriterSelection']);dependency=writer['PreAdoptionVaultDependencies'][0];owner=A.obj(dependency['InstalledObserver'])
        endpoints=[(c['Purpose'],c['Endpoint']) for c in selected['Connections'] if (urlsplit(c['Endpoint']).hostname or '').endswith('.'+A.NS+'.svc')]
        dns=D.SourceDNS(site,mint,pod,endpoints,A.retain);dns.probe()
        out=mint/'material';A.need(not out.exists(),'mint output already exists');out.mkdir(mode=0o700)
        forward=mint/'forward';forward.mkdir(mode=0o700)
        with F.LocalForward(site,{'--provider-service':dependency['Workload']['Service'],'--provider-endpoint':owner['Endpoint']},forward,A.retain) as address:
            R.once(A,dns,mint,'native',[str(package/'system-backup-source-registries'),'issue-provider-metadata',*common,
                '--writer-selection-file',parent['VaultWriterSelection']['File'],'--writer-selection-sha256',parent['VaultWriterSelection']['SHA256'],
                '--provider-local-forward',address,'--output-directory',str(out)])
    minted=A.decode(saved.read_bytes());A.need(minted['Version']=='installed-vault-metadata-materials.v1' and minted['Workload']==prior['Workload'],'native provider scope changed')
    native=A.obj(minted['Observer']);token=A.read({'File':native['TokenFile'],'SHA256':native['TokenSHA256']})
    L.verify_metadata(A,F,site,JOURNAL,native,token,minted['Workload'],until)
    planfile=JOURNAL/'delivery-plan.private.json'
    if not planfile.exists():
        deployment=site.get('deployment',selected['Controller']['Deployment'])
        A.need(deployment['metadata']['uid']==selected['Controller']['DeploymentUID'] and deployment['spec']==old_desired,'controller changed before delivery')
        secret,desired,patch,digest=P.rotation_delivery(deployment,old_secret,native,token,image['Image'])
        secretpin=A.retain(JOURNAL/'secret.private.json',secret);specpin=A.retain(JOURNAL/'desired-spec.private.json',desired)
        A.retain(planfile,{'Secret':secretpin,'DesiredSpec':specpin,'Patch':patch,'ObserverSHA256':digest})
    plan=A.decode(planfile.read_bytes());secret=A.obj(plan['Secret']);desired=A.obj(plan['DesiredSpec'])
    current=site.get('deployment',selected['Controller']['Deployment'])
    A.need(current['metadata']['uid']==selected['Controller']['DeploymentUID'] and not current['metadata'].get('deletionTimestamp'),'controller replaced')
    if current['spec']!=desired:
        A.need(current['spec']==old_desired,'controller specification drift')
        patch=copy.deepcopy(plan['Patch']);patch[1]['value']=current['metadata']['resourceVersion']
        dry=A.decode(site.call(['patch','deployment',current['metadata']['name'],'--dry-run=server','--type=json','--patch-file=/dev/stdin','-o','json'],json.dumps(patch).encode()))
        A.need(dry['spec']==desired,'admission altered controller deployment')
        raw=site.call(['get','secret',secret['metadata']['name'],'--ignore-not-found','-o','json'])
        if not raw.strip():site.send('secret-create',['create','-f','-','-o','json'],json.dumps(secret).encode())
        L.verify_secret(site.get('secret',secret['metadata']['name']),secret)
        site.send('controller-update',['patch','deployment',current['metadata']['name'],'--type=json','--patch-file=/dev/stdin','-o','json'],json.dumps(patch).encode())
    site.call(['rollout','status','deployment/'+selected['Controller']['Deployment'],'--timeout=180s'],timeout=210)
    fresh,pod=controller_ref(A,site,L,selected,desired)
    for name,digest in [('observer.json',plan['ObserverSHA256']),('token',native['TokenSHA256'])]:
        path=L.MOUNT+'/'+name
        lines=site.call(['exec',fresh['Pod'],'-c','controller','--','sh','-ec','test -f "$1"; test ! -L "$1"; stat -c "%a %u" "$1"; sha256sum "$1"','readback',path]).decode().splitlines()
        A.need(len(lines)==2 and lines[0]=='600 65532' and lines[1].split()==[digest,path],'loaded metadata file differs')
    for name in ('system-backup-source-registries','system-backup-v2-controller'):
        line=site.call(['exec',fresh['Pod'],'-c','controller','--','sha256sum','/usr/local/bin/'+name]).decode().split()
        A.need(line==[build['Binaries'][name]['SHA256'],'/usr/local/bin/'+name],'running binary differs')
    A.retain(JOURNAL/'loaded.json',{'Controller':fresh,'Image':image['Image'],'BackupReady':False})
    print('P2_NOV14_IDENTITY_AND_CONTROLLER_LOADED',json.dumps({'ControllerPod':fresh['Pod'],'SourceRevision':build['SourceRevision'],'BackupReady':False}),flush=True)
    done=refresh(A,L,H,R,N,D,F,T,site,package,parent,original,selected,fresh,pod,desired,secret,plan,minted,observer,agent)
    mount(A,L,H,R,D,site,package,done,fresh,pod,desired)


def refresh(A,L,H,R,N,D,F,T,site,package,parent,original,selected,fresh,pod,desired,secret,plan,minted,observer,agent):
    journal=JOURNAL/'source';journal.mkdir(mode=0o700,exist_ok=True)
    donefile=journal/'completed.json'
    if donefile.exists():
        done=A.decode(donefile.read_bytes());A.read(done['Receipt']);return done
    api=A.obj(parent['SourceAPI']);connection=api['connection'];sa=site.get('serviceaccount',api['service_account'])
    A.need(sa['metadata']['uid']==api['service_account_uid']==connection['Account'] and not sa['metadata'].get('deletionTimestamp'),'source account changed')
    tokenfile=journal/'token.private.json'
    if tokenfile.exists():response=A.decode(tokenfile.read_bytes())
    else:
        raw=site.send('source-token',['create','--raw','/api/v1/namespaces/'+A.NS+'/serviceaccounts/'+api['service_account']+'/token','-f','-'],json.dumps({'apiVersion':'authentication.k8s.io/v1','kind':'TokenRequest','spec':{'expirationSeconds':28800}}).encode())
        A.retain(tokenfile,raw);response=A.decode(raw)
    token=response['status']['token']
    review=A.decode(site.call(['create','--raw','/apis/authentication.k8s.io/v1/tokenreviews','-f','-'],json.dumps({'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','spec':{'token':token}}).encode()))
    T.identity(A,review['status'],api['service_account'],api['service_account_uid'])
    now=dt.datetime.now(dt.timezone.utc);before,until=T.window(now,N.moment(response['status']['expirationTimestamp']),N.moment(observer['NotAfter']),N.moment(agent['NotAfter']),30)
    new=copy.deepcopy(connection);new['Credential']=A.retain(journal/'source-api.jwt',token.encode())
    out=MIRROR/'initial-source-20261114-team';definition=N.successor_definition(original,connection,new,Path(parent['SourceSelection']['File']).parent,out,before,until)
    definition['Controller']=fresh
    providers=definition['Deployment']['provider_dependencies'];A.need(len(providers)==1 and providers[0]['workload']==minted['Workload'],'source provider role changed')
    providers[0]['observer']={'File':L.MOUNT+'/observer.json','SHA256':plan['ObserverSHA256']}
    pin=A.retain(journal/'definition.private.json',definition)
    old=A.decode((T.PARENT/'author.sent.private.json').read_bytes())['Argv']
    endpoints=[(c['Purpose'],c['Endpoint']) for c in selected['Connections'] if (urlsplit(c['Endpoint']).hostname or '').endswith('.'+A.NS+'.svc')]
    dns=D.SourceDNS(site,journal,pod,endpoints,A.retain);dns.probe()
    A.need(not out.exists(),'source output exists; reconcile original author outcome');out.mkdir(mode=0o700)
    result=R.once(A,dns,journal,'author',[str(package/'system-backup-first-install-materials'),'author-initial-source-inputs',*old[2:old.index('--definition-file')],'--definition-file',pin['File'],'--definition-sha256',pin['SHA256'],'--output-directory',str(out)])
    A.need(result['GrantsIssued'] is False and result['BackupReady'] is False and A.obj(result['SourceSelection'])['Controller']==fresh and A.obj(result['Deployment'])==definition['Deployment'],'native refreshed source differs')
    changed=copy.deepcopy(api);changed['connection']=new;changed['token_expires_unix']=int(N.moment(response['status']['expirationTimestamp']).timestamp())
    done={'Version':'p2-nov14-source.v1','Receipt':A.retain(journal/'receipt.private.json',(journal/'author.receipt.private.json').read_bytes()),'Definition':pin,'SourceSelection':result['SourceSelection'],'SourceAPI':A.retain(journal/'source-api-fragment.json',changed),'Controller':fresh,'VaultWriterSelection':parent['VaultWriterSelection'],'Until':definition['Until'],'GrantsIssued':False,'BackupReady':False}
    controller_ref(A,site,L,{'Controller':fresh},desired)
    A.retain(donefile,done);print('P2_NOV14_SOURCE_REFRESHED_NO_HOLD',json.dumps(done),flush=True)

    return done

def mount(A,L,H,R,D,site,package,done,fresh,pod,desired):
    journal=ROOT/'longhorn-source-20261114-team-attachment';journal.mkdir(mode=0o700,exist_ok=True)
    saved=journal/'completed.json'
    if saved.exists():
        complete=A.decode(saved.read_bytes());A.read(complete['Receipt'])
        print('P2_LONGHORN_SOURCE_ALREADY_AUTHORED_NO_HOLD',json.dumps(complete),flush=True);return
    A.need(not (journal/'native.sent.private.json').exists(),'mount author already attempted; retain outputs')
    selected=A.obj(done['SourceSelection']);core=A.obj(A.obj(done['Receipt'])['Deployment'])
    until=dt.datetime.fromisoformat(selected['Until'].replace('Z','+00:00'))
    A.need(dt.datetime.now(dt.timezone.utc)<until-dt.timedelta(minutes=10),'source window insufficient')
    storage=load('prepare-p2-longhorn-source')
    layout=storage.storage_selection(site.get('volumesnapshotclass','sbk-validation-longhorn-local'),site.get('storageclass','longhorn'))
    layout['TeamAttachments']=load('prepare-p2-team-attachment').prepare(A,L,core,selected,journal)
    layouts=A.retain(journal/'mount-layouts.json',layout)
    endpoints=[(c['Purpose'],c['Endpoint']) for c in selected['Connections'] if (urlsplit(c['Endpoint']).hostname or '').endswith('.'+A.NS+'.svc')]
    dns=D.SourceDNS(site,journal,pod,endpoints,A.retain);dns.probe()
    out=MIRROR/journal.name;A.need(not out.exists(),'mount output exists; reconcile outcome');out.mkdir(mode=0o700)
    old=A.decode((JOURNAL/'source/author.sent.private.json').read_bytes())['Argv']
    value=R.once(A,dns,journal,'native',[str(package/'system-backup-source-registries'),'prepare-mount-materials',*old[2:old.index('--definition-file')],
        '--source-selection-file',done['SourceSelection']['File'],'--source-selection-sha256',done['SourceSelection']['SHA256'],
        '--mount-layouts-file',layouts['File'],'--mount-layouts-sha256',layouts['SHA256'],'--output-directory',str(out)])
    A.need(value['SelectionSHA256']==done['SourceSelection']['SHA256'] and value['LayoutSelectionSHA256']==layouts['SHA256'],'mount input pins differ')
    for k in ('Deployment','MaterialsTemplate','SourceSelection','LonghornHoldMaterials'):A.read(value[k])
    storage.validate_successor(selected,A.obj(value['SourceSelection']),value,A.obj(value['MaterialsTemplate']))
    H.validate_core_successor(core,A.obj(value['Deployment']),value['LonghornHoldMaterials'])
    controller_ref(A,site,L,{'Controller':fresh},desired)
    complete={'Version':'p2-longhorn-source-materials-authored.v1','Receipt':A.retain(journal/'native.receipt.private.json',(journal/'native.stdout.private').read_bytes()),
        'ParentSelection':done['SourceSelection'],**{k:value[k] for k in ('Deployment','MaterialsTemplate','SourceSelection','LonghornHoldMaterials')},
        'VaultWriterSelection':done['VaultWriterSelection'],'Until':selected['Until'],'NativeHoldClaim':False,'GrantsIssued':False,'BackupReady':False}
    A.retain(saved,complete);print('P2_LONGHORN_SOURCE_MATERIALS_AUTHORED_NO_HOLD',json.dumps(complete),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_NOV14_UNCONFIRMED '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
