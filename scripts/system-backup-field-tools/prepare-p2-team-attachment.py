#!/usr/bin/env python3
"""Prepare the exact idle team PVC as an installation-scoped read-only consumer."""
import importlib.util
import json
import os
import time
from pathlib import Path

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NS = 'clawmanager-sbk-validation-user-1'
CLAIM = 'clawreef-team-1-shared'
PV = 'pvc-0b508d4e-7039-462a-9c62-69ae598cbd0e'
PVC_UID = '0b508d4e-7039-462a-9c62-69ae598cbd0e'
PV_UID = 'f5f3556c-bdf4-4fec-9790-41bc79a9e2cf'
POD = 'sbk-team-1-readonly-p2'
IMAGE = '10.130.14.23:5000/clawmanager@sha256:4c196dd9b904244e7715f2151f9f672c9db129b582ca716f1324b2bf31b6847a'


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def need(ok, message):
    if not ok: raise ValueError(message)


def manifest():
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':POD,'namespace':NS,
        'labels':{'app.kubernetes.io/name':'system-backup-team-attachment'}},
        'spec':{'nodeName':'node1','serviceAccountName':'default','automountServiceAccountToken':False,
            'restartPolicy':'Never','terminationGracePeriodSeconds':10,
            'containers':[{'name':'attachment','image':IMAGE,'imagePullPolicy':'IfNotPresent',
                'command':['/bin/sh','-ec'],'args':['exec sleep 2147483647'],
                'resources':{'requests':{'cpu':'1m','memory':'8Mi'},'limits':{'cpu':'50m','memory':'32Mi'}},
                'securityContext':{'runAsUser':65532,'runAsNonRoot':True,'readOnlyRootFilesystem':True,
                    'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}},
                'volumeMounts':[{'name':'source','mountPath':'/source','readOnly':True}]}],
            'volumes':[{'name':'source','persistentVolumeClaim':{'claimName':CLAIM,'readOnly':True}}]}}


def check_admission(actual, requested):
    spec=actual['spec']; expected=requested['spec']
    for key in ('nodeName','serviceAccountName','automountServiceAccountToken','restartPolicy','volumes'):
        need(spec.get(key)==expected[key],'admission changed attachment '+key)
    need(not spec.get('initContainers') and not spec.get('ephemeralContainers') and not spec.get('hostNetwork') and
         not spec.get('hostPID') and not spec.get('hostIPC') and not spec.get('shareProcessNamespace') and
         not spec.get('securityContext',{}).get('fsGroup'),'admission added privileged or ownership-changing settings')
    need(len(spec['containers'])==1,'admission injected another container')
    c=spec['containers'][0]
    for key,value in expected['containers'][0].items():
        need(c.get(key)==value,'admission changed attachment container '+key)
    need(not any(c.get(k) for k in ('env','envFrom','lifecycle','livenessProbe','readinessProbe','startupProbe','volumeDevices','ports')), 'admission added attachment behavior')


def complete_items(value):
    need(isinstance(value,dict) and isinstance(value.get('items'),list) and
         not value.get('metadata',{}).get('continue'), 'incomplete Kubernetes list; retain state and do not mutate')
    return value['items']


def check_recorded_attachment(current, original):
    expected={'name':POD,'namespace':NS}
    need(all(original.get('metadata',{}).get(k)==v and current.get('metadata',{}).get(k)==v for k,v in expected.items()),
         'attachment coordinates changed')
    need(original['metadata'].get('uid') and current['metadata'].get('uid')==original['metadata']['uid'] and
         current.get('spec')==original.get('spec') and not current['metadata'].get('ownerReferences') and
         not current['metadata'].get('finalizers'), 'attachment identity/specification changed')
    check_admission(current,manifest())


def rollback_native_output(journal,A):
    need(not (journal/'completed.json').exists(),'successful source material requires source retirement; rollback refused')
    sent=journal/'native.sent.private.json'
    if not sent.exists(): return
    need((journal/'native.exit.json').exists() and A.decode((journal/'native.exit.json').read_bytes())=={'ExitCode':1},
         'native outcome unknown or successful; rollback refused')
    argv=A.decode(sent.read_bytes())['Argv']
    need(argv.count('--output-directory')==1,'ambiguous native output directory')
    output=Path(argv[argv.index('--output-directory')+1])
    expected=Path('/run/system-backup/runtime/p2-renew-1048e373bfe0')/journal.name
    need(output==expected and output.resolve(strict=True)==output and output.is_dir() and not list(output.iterdir()),
         'native partial or foreign outputs require reconciliation')


def check_binding(ns, pvc, pv):
    need(ns['metadata'].get('uid') and not ns['metadata'].get('deletionTimestamp') and
         all(ns['metadata'].get('labels',{}).get(k)==v for k,v in {'app':'clawreef','managed-by':'clawreef','user-id':'1'}.items()), 'tenant identity changed')
    need(pvc['metadata']['uid']==PVC_UID and not pvc['metadata'].get('deletionTimestamp') and
         pvc['spec']['volumeName']==PV and pvc['spec']['accessModes']==['ReadWriteMany'] and
         pvc['status']['phase']=='Bound', 'team PVC binding changed')
    need(pv['metadata']['uid']==PV_UID and not pv['metadata'].get('deletionTimestamp') and
         all(pv['spec']['claimRef'].get(k)==v for k,v in {'name':CLAIM,'namespace':NS,'uid':PVC_UID}.items()) and
         pv['spec']['csi']['driver']=='driver.longhorn.io' and pv['spec']['csi']['volumeHandle']==PV, 'team PV binding changed')


def prepare(A, L, core, selected, journal):
    site = L.Site(journal,A)
    def read(path): return A.decode(site.call(['get','--raw',path]))
    base='/api/v1/namespaces/'+NS
    ns=read('/api/v1/namespaces/'+NS); pvc=read(base+'/persistentvolumeclaims/'+CLAIM); pv=read('/api/v1/persistentvolumes/'+PV)
    check_binding(ns,pvc,pv)
    prior=ROOT/'longhorn-source-20261113-tenant-team-namespace'
    failure=A.decode((prior/'native.stdout.private').read_bytes())
    need(A.decode((prior/'native.exit.json').read_bytes())=={'ExitCode':1} and
         failure.get('Phase')=='longhorn_hold_materials' and failure.get('Step')=='longhorn_share_manager_state' and
         failure.get('Reason')=='validation' and not (prior/'completed.json').exists(), 'observed stopped-share-manager refusal required')
    argv=A.decode((prior/'native.sent.private.json').read_bytes())['Argv']
    output=Path(argv[argv.index('--output-directory')+1])
    need(argv[argv.index('--source-selection-sha256')+1]=='8901e7fb9ecc37f5df8a4c84de08fe77930b5a67d70c2d32d1f807a5e9444b9f', 'prior native selection differs')
    need(output==Path('/run/system-backup/runtime/p2-renew-1048e373bfe0')/prior.name and output.resolve(strict=True)==output and not list(output.iterdir()), 'prior partial native outputs require reconciliation')
    sa=read(base+'/serviceaccounts/default'); need(sa['metadata'].get('uid') and not sa['metadata'].get('deletionTimestamp'),'default account unavailable')
    request=manifest()
    existing=complete_items(read(base+'/pods'))
    mine=[p for p in existing if p['metadata']['name']==POD]
    other=[p for p in existing if p['metadata']['name']!=POD and any(v.get('persistentVolumeClaim',{}).get('claimName')==CLAIM for v in p['spec'].get('volumes',[]))]
    need(not other,'team volume acquired another consumer; reconcile before preparation')
    record=journal/'team-attachment.created.private.json'
    if mine:
        need(record.exists(),'same-name Pod lacks this preparation receipt; do not adopt')
        original=A.decode(record.read_bytes())
        check_recorded_attachment(mine[0],original)
        pod=mine[0]
    else:
        need(not record.exists(),'recorded attachment disappeared; do not recreate')
        nodes=complete_items(read('/api/v1/nodes')); allpods=complete_items(read('/api/v1/pods'))
        for n in nodes:
            if n['metadata']['name'] not in ('node1','k8s-master'): continue
            used=sum(p['spec'].get('nodeName')==n['metadata']['name'] and p.get('status',{}).get('phase') not in ('Succeeded','Failed') for p in allpods)
            need(int(n['status']['allocatable']['pods'])-used>=2,'insufficient Pod capacity for attachment and share manager')
        node=next(n for n in nodes if n['metadata']['name']=='node1')
        need(node['metadata']['uid']==core['worker_security']['node_uids']['node1'],'installed node identity changed')
        A.retain(journal/'team-attachment.binding.private.json',{'Namespace':ns,'PVC':pvc,'PV':pv,'ServiceAccount':sa})
        raw=json.dumps(request).encode()
        dry=A.decode(site.call(['-n',NS,'create','--dry-run=server','-f','-','-o','json'],raw))
        A.retain(journal/'team-attachment.dry-run.private.json',dry)
        check_admission(dry,request)
        pod=A.decode(site.send('team-attachment-create',['-n',NS,'create','-f','-','-o','json'],raw))
        A.retain(record,pod)
        need(pod['spec']==dry['spec'],'admission changed attachment specification')
    deadline=time.monotonic()+180
    while True:
        current=read(base+'/pods/'+POD)
        need(current['metadata']['uid']==pod['metadata']['uid'] and current['spec']==pod['spec'] and not current['metadata'].get('deletionTimestamp'),'attachment identity changed')
        statuses=current.get('status',{}).get('containerStatuses',[])
        volume=read('/apis/longhorn.io/v1beta2/namespaces/longhorn-system/volumes/'+PV)
        if current.get('status',{}).get('phase')=='Running' and len(statuses)==1 and statuses[0].get('ready') and volume.get('status',{}).get('shareState')=='running': break
        need(time.monotonic()<deadline,'attachment/share manager not ready; retain Pod and journal for reconciliation')
        time.sleep(3)
    # Independently re-read exact PVC/PV identity after the physical mount exists.
    check_binding(read('/api/v1/namespaces/'+NS),read(base+'/persistentvolumeclaims/'+CLAIM),read('/api/v1/persistentvolumes/'+PV))
    ready=journal/'team-attachment.ready.private.json'
    if ready.exists():check_recorded_attachment(current,A.decode(ready.read_bytes()))
    else:A.retain(ready,current)
    print('P2_TEAM_ATTACHMENT_READY_NO_HOLD',json.dumps({'Pod':POD,'UID':pod['metadata']['uid'],'Node':'node1','ReadOnly':True,'BackupReady':False}),flush=True)
    return [{'TeamID':1,'Namespace':NS,'Pod':POD,'Image':IMAGE}]


def rollback_failed_preparation(nov14=False,attempt=1):
    A, L = load('assemble-p2-installation-candidate'), load('load-p2-formal-vault')
    journal=ROOT/('longhorn-source-20261114-team-attachment' if nov14 else 'longhorn-source-20261113-team-attachment')
    need(1<=attempt<=99 and (nov14 or attempt==1),'numbered attempts require --nov14')
    if attempt>1:journal=journal.with_name(journal.name+'-'+str(attempt))
    rollback_native_output(journal,A)
    original=A.decode((journal/'team-attachment.created.private.json').read_bytes())
    site=L.Site(journal,A); base='/api/v1/namespaces/'+NS
    pods=complete_items(A.decode(site.call(['get','--raw',base+'/pods'])))
    matches=[p for p in pods if p['metadata']['name']==POD]
    if matches:
        current=matches[0]
        check_recorded_attachment(current,original)
        options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Orphan',
                 'preconditions':{'uid':current['metadata']['uid'],'resourceVersion':current['metadata']['resourceVersion']}}
        site.send('team-attachment-delete',['delete','--raw',base+'/pods/'+POD,'-f','-'],json.dumps(options).encode())
        deadline=time.monotonic()+90
        while any(p['metadata']['name']==POD for p in complete_items(A.decode(site.call(['get','--raw',base+'/pods'])))):
            need(time.monotonic()<deadline,'attachment deletion unconfirmed'); time.sleep(2)
    def read(path): return A.decode(site.call(['get','--raw',path]))
    check_binding(read('/api/v1/namespaces/'+NS),read(base+'/persistentvolumeclaims/'+CLAIM),read('/api/v1/persistentvolumes/'+PV))
    A.retain(journal/'team-attachment.rollback.json',{'PodUID':original['metadata']['uid'],'PVCPreserved':True,'BackupReady':False})
    print('P2_TEAM_ATTACHMENT_ROLLED_BACK_PVC_PRESERVED',flush=True)


if __name__=='__main__':
    try:
        import argparse
        parser=argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--rollback-failed-preparation',action='store_true')
        parser.add_argument('--nov14',action='store_true')
        parser.add_argument('--source-attempt',type=int,default=1)
        args=parser.parse_args()
        os.umask(0o077)
        if args.rollback_failed_preparation: rollback_failed_preparation(args.nov14,args.source_attempt)
        else: load('prepare-p2-longhorn-provider-loaded').main(team_attachment=True)
    except Exception as error:
        raise SystemExit('P2_TEAM_ATTACHMENT_UNCONFIRMED '+(str(error) if isinstance(error,ValueError) else type(error).__name__))
