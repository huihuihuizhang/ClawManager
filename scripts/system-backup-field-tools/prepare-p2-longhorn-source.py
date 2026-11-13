#!/usr/bin/env python3
"""Read and author Longhorn source DATA using the existing native owner; no hold."""
import datetime as dt
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
BIN = Path('/root/sbk/p2-jwt-api-c888315f/system-backup-source-registries')
BIN_SHA = '408c8d9d6ae3ab295d8ab9eeb72276a886ae331bbda81548da595696d85fd049'
HELPER = Path('/root/sbk/p2-runtime-cert-rotation-fcc26a0a/rotate-p2-runtime-certificates.py')
HELPER_SHA = 'ab1539c5e06c8c237e8516d9985b162fbec3216570abb5ebec1902df47f7052c'
SELECTION_SHA = 'f42db72c7774a9a5fe50e1d5df837c1a2ffb954995ea8e5d09b44ae0e2a073b2'

def need(ok, why):
    if not ok: raise ValueError(why)

def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

def storage_selection(snapshot, clone):
    need(snapshot['metadata']['name'] == 'sbk-validation-longhorn-local' and
         snapshot['metadata']['uid'] == 'f28ccd84-5689-4c56-a25c-5ba1b1d2e24e' and
         snapshot['driver'] == 'driver.longhorn.io' and snapshot['deletionPolicy'] == 'Delete' and
         snapshot.get('parameters') == {'type':'snap'}, 'original Longhorn snapshot class changed')
    need(clone['metadata']['name'] == 'longhorn' and
         clone['metadata']['uid'] == '9086f7e9-1213-485e-9ec2-3e5de93f908a' and
         clone['provisioner'] == 'driver.longhorn.io' and clone['parameters'].get('fsType') == 'ext4' and
         clone.get('volumeBindingMode') == 'Immediate' and clone.get('reclaimPolicy') == 'Delete',
         'original ext4 Longhorn clone class changed')
    # No asserted per-instance ownership: native complete coverage checks reject
    # an undeclared additional mount. Primary workspace/Pro mappings are native.
    return {'Version':'original-instance-mount-layout-selection.v1','Layouts':[],
        'AuthorLonghornHold':True,'Longhorn':{'ProviderNamespace':'longhorn-system',
        'SnapshotClass':snapshot['metadata']['name'],'CloneClass':clone['metadata']['name']}}

def validate_successor(parent, selected, receipt, material):
    need(receipt['Version'] == 'original-instance-mount-materials-receipt.v1' and
         selected['Deployment'] == receipt['Deployment'] and selected['MaterialsTemplate'] == receipt['MaterialsTemplate'] and
         material['DeploymentConfigSHA256'] == receipt['Deployment']['SHA256'] and
         {k:v for k,v in selected.items() if k not in ['Deployment','MaterialsTemplate']} ==
         {k:v for k,v in parent.items() if k not in ['Deployment','MaterialsTemplate']},
         'native successor changed unrelated selection or mixed core/material identities')

def release_pod_identity(pod):
    name = 'sbk-app-tls-release-4e4c205c283a0486'
    meta, spec, status = pod['metadata'], pod['spec'], pod['status']
    need(meta['name'] == name and meta['namespace'] == 'clawmanager-sbk-validation-system' and
         meta['uid'] == 'b1c9882d-4017-4f5b-90a7-69bcbad8732e' and
         not meta.get('ownerReferences') and not meta.get('deletionTimestamp') and
         status['phase'] == 'Succeeded', 'original completed release Pod required')
    containers = spec['containers']; states = status['containerStatuses']
    need(len(containers) == len(states) == 1 and containers[0]['name'] == states[0]['name'] == 'release' and
         containers[0]['image'] == '10.130.14.23:5000/clawmanager@sha256:ae64fd8a1c0fd825c44722107894a0d60ce428e0daf5a66e9b2064d5b3c4335e' and
         states[0]['state'].get('terminated',{}).get('exitCode') == 0 and
         [v['persistentVolumeClaim']['claimName'] for v in spec['volumes'] if 'persistentVolumeClaim' in v] == [name],
         'release Pod image, exit or PVC changed')
    return name, meta['uid']

def cleanup_release_pod(site, r, A):
    name = 'sbk-app-tls-release-4e4c205c283a0486'
    raw = site.call(['get','pod',name,'--ignore-not-found','-o','json'])
    if not raw.strip():
        print('P2_COMPLETED_RELEASE_POD_ABSENT',flush=True); return
    pod = json.loads(raw); name, uid = release_pod_identity(pod)
    claim = site.get('pvc',name)
    need(not claim['metadata'].get('deletionTimestamp') and
         not any(o.get('uid')==uid for o in claim['metadata'].get('ownerReferences',[])),
         'release PVC deleting or owned by temporary Pod')
    A.retain(r/'release-pod.before.private.json',pod)
    A.retain(r/'release-pvc.before.private.json',claim)
    marker = r/'release-pod-delete.sent.json'
    need(not marker.exists(),'release Pod deletion already sent; reconcile original result')
    options = {'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Orphan',
               'preconditions':{'uid':uid,'resourceVersion':pod['metadata']['resourceVersion']}}
    A.retain(marker,options)
    site.call(['delete','--raw','/api/v1/namespaces/'+pod['metadata']['namespace']+'/pods/'+name,'-f','-'],options)
    site.call(['wait','--for=delete','pod/'+name,'--timeout=60s'])
    need(not site.call(['get','pod',name,'--ignore-not-found','-o','json']).strip(),'release Pod still present')
    after = site.get('pvc',name)
    need(after['metadata']['uid']==claim['metadata']['uid'] and not after['metadata'].get('deletionTimestamp') and
         after['spec']==claim['spec'],'release PVC changed')
    A.retain(r/'release-pod-cleaned.json',{'PodUID':uid,'PVCUID':after['metadata']['uid'],'PVCPreserved':True})
    print('P2_COMPLETED_RELEASE_POD_CLEANED_PVC_PRESERVED',flush=True)

def main(redis_renewed=False, phase_readback=False, credential_encoding=False, pv_read_repaired=False, november13=False, runtime_scope=False, writer_readback=False):
    os.umask(0o077); need(os.name == 'posix','Linux operator required')
    directory = Path(__file__).resolve().parent
    A = load('longhorn_assembly',directory/'assemble-p2-installation-candidate.py')
    source_name = 'source-preparation-redis-renew7d' if redis_renewed else 'source-preparation-renew8h'
    output_name = 'longhorn-source-redis-renew7d' if redis_renewed else 'longhorn-source-renew8h'
    native, native_sha = BIN, BIN_SHA
    need(not writer_readback or runtime_scope,'writer readback requires renewed runtime scope')
    need(not (november13 and runtime_scope),'select one November source')
    if november13 or runtime_scope:
        need(not any([redis_renewed,phase_readback,credential_encoding,pv_read_repaired]),'select one successor mode')
        source_name, output_name = 'source-preparation-20261113-ca-alias', 'longhorn-source-20261113'
        prior = ROOT/'longhorn-source-redis-renew7d-pv-read-repaired'
        if runtime_scope:
            source_name, output_name = 'source-preparation-20261113-runtime-scope-final-retry', 'longhorn-source-20261113-runtime-scope'
            prior = ROOT/'longhorn-source-20261113'
        if writer_readback:
            prior=ROOT/output_name
            output_name += '-writer-readback'
        need(json.loads((prior/'native.exit.json').read_bytes()) == {'ExitCode':1} and
             not (prior/'completed.json').exists(),'prior native failure required')
        refusal = json.loads((prior/'native.stdout.private').read_bytes())
        expected_phase = 'writer_api' if writer_readback else 'source_sql' if runtime_scope else 'native_writers'
        need(refusal['Status']=='original_mount_author_refused' and refusal['Phase']==expected_phase,'observed prior refusal required')
        old = json.loads((prior/'native.sent.private.json').read_bytes())['Argv']
        old_out = Path(old[old.index('--output-directory')+1])
        need(old_out.is_dir() and not list(old_out.iterdir()),'partial outputs require reconciliation')
        native = Path('/root/sbk/p2-credential-encoding-8d0f5dfc/system-backup-source-registries')
        native_sha = '2c786044554aa445c3789ab84756e988da56ea1b6f5df6f32d00571405eb08a1'
        if writer_readback:
            build=json.loads((directory/'BUILD_RECEIPT.json').read_bytes())
            need(build['Diagnostic']=='writer-api-read-step.v1','reviewed writer diagnostic build required')
            native=directory/'system-backup-source-registries';native_sha=build['NativeSHA256']
    need(sum([phase_readback, credential_encoding, pv_read_repaired]) <= 1, 'select one successor mode')
    if phase_readback or credential_encoding or pv_read_repaired:
        need(redis_renewed, 'phase readback requires observed Redis source successor')
        suffix = '-credential-encoding' if pv_read_repaired else '-phase-readback' if credential_encoding else ''
        prior = ROOT/(output_name+suffix)
        need(json.loads((prior/'native.exit.json').read_bytes()) == {'ExitCode':1} and
             not (prior/'completed.json').exists(), 'prior failure must be confirmed')
        old = json.loads((prior/'native.sent.private.json').read_bytes())['Argv']
        old_out = Path(old[old.index('--output-directory')+1])
        need(old_out.is_dir() and not list(old_out.iterdir()), 'partial native outputs require reconciliation')
        if credential_encoding or pv_read_repaired:
            refusal = json.loads((prior/'native.stdout.private').read_bytes())
            expected_phase = 'writer_api' if pv_read_repaired else 'metadata_clients'
            need(refusal['Status'] == 'original_mount_author_refused' and refusal['Phase'] == expected_phase,
                 'observed predecessor refusal required')
        if pv_read_repaired:
            repair = json.loads((ROOT/'source-pv-read-repair/completed.json').read_bytes())
            need(repair['Version'] == 'p2-source-pv-read-repaired.v1' and repair['SourceReadVerified'] is True and
                 repair['PV'] == 'pvc-cd9cbe86-f701-4869-b9ed-0adae5baa427', 'source PV read repair required')
        build = json.loads((directory/'BUILD_RECEIPT.json').read_bytes())
        native = directory/'system-backup-source-registries'
        native_sha = build['NativeSHA256']
        expected = 'source-credential-encoding.v1' if credential_encoding or pv_read_repaired else 'original-mount-author-phase.v1'
        need(build['Diagnostic'] == expected, 'reviewed successor build required')
        output_name += '-pv-read-repaired' if pv_read_repaired else '-credential-encoding' if credential_encoding else '-phase-readback'
    r = ROOT/output_name; r.mkdir(mode=0o700,exist_ok=True)
    need(r.resolve(strict=True) == r and r.stat().st_mode & 0o077 == 0,'private journal required')
    renewed = json.loads((ROOT/source_name/'completed.json').read_bytes())
    pin = renewed['SourceSelection']
    if november13 or runtime_scope:
        version = 'p2-runtime-scope-source-reauthored.v1' if runtime_scope else 'p2-source-ca-alias-reauthored.v1'
        receipt_sha = '11dfe569db6defd550bcc124e3659e15823d922f618e6f5ec2b2e9ab051601c8' if runtime_scope else 'b6c38df3fc7cf42f461c7bdd693bda6eefe9ed22ba09bf913e9df10f676b10c8'
        selection_sha = 'a323dc03ada6b3ef8863ee4e0126f2ea7549fd8aecc9f182d7d8a49946db9565' if runtime_scope else 'bf23877e281b5b44669f285bee4943d26a100d713e1247884b3530c650ba5d62'
        need(renewed['Version']==version and renewed['Receipt']['SHA256']==receipt_sha and
             pin['SHA256']==selection_sha,'observed November source required')
        if runtime_scope:
            need(renewed['DeferredIDs']==[4,5,6] and renewed['TokenReissued'] is False,'original runtime scope required')
            A.read(renewed['Coordinates']);A.read(renewed['Definition'])
        receipt = A.obj(renewed['Receipt'])
        need(receipt['SourceSelection']==pin and receipt['GrantsIssued'] is False and receipt['BackupReady'] is False,'native source receipt differs')
    elif redis_renewed:
        need(renewed['Version'] == 'p2-redis-source-reauthored.v1', 'Redis successor receipt required')
        receipt = A.obj(renewed['Receipt'])
        need(receipt['SourceSelection'] == pin and receipt['GrantsIssued'] is False, 'native Redis successor differs')
        prior = ROOT/'longhorn-source-renew8h'
        need(json.loads((prior/'native.exit.json').read_bytes()) == {'ExitCode':1} and
             not (prior/'completed.json').exists(), 'original mount failure not confirmed')
        old = json.loads((prior/'native.sent.private.json').read_bytes())['Argv']
        old_out = Path(old[old.index('--output-directory')+1])
        need(old_out.is_dir() and not list(old_out.iterdir()), 'original mount outputs exist; reconcile first')
    else:
        need(pin['SHA256'] == SELECTION_SHA,'exact renewed source selection required')
    parent = A.obj(pin); A.read(renewed['Receipt']); A.read(renewed['VaultWriterSelection'])
    if (r/'completed.json').exists():
        done = json.loads((r/'completed.json').read_bytes()); A.read(done['Receipt'])
        print('P2_LONGHORN_SOURCE_MATERIALS_ALREADY_AUTHORED_NO_HOLD',json.dumps(done)); return
    need(not (r/'native.sent.private.json').exists(),'native mount author already sent; retain original outcome')
    now = dt.datetime.now(dt.timezone.utc)
    need(dt.datetime.fromisoformat(parent['NotBefore'].replace('Z','+00:00')) <= now <
         dt.datetime.fromisoformat(parent['Until'].replace('Z','+00:00')) - dt.timedelta(minutes=5),
         'source preparation window expired or too short')
    for key in ['PartsFile','SourceWritersFile','RedisSourcesFile']:
        need(not parent.get(key) or not Path(parent[key]).exists(),'source facts already exist; reconcile before successor')
    A.read({'File':str(native),'SHA256':native_sha},128<<20)
    need(hashlib.sha256(HELPER.read_bytes()).hexdigest() == HELPER_SHA,'retained API helper changed')
    site = load('longhorn_site',HELPER).Site(r)
    snapshot = json.loads(site.call(['get','volumesnapshotclass','sbk-validation-longhorn-local','-o','json']))
    clone = json.loads(site.call(['get','storageclass','longhorn','-o','json']))
    layout = A.retain(r/'mount-layouts.json',storage_selection(snapshot,clone))
    controller = parent['Controller']
    pod = site.get('pod',controller['Pod'])
    need(pod['metadata']['uid'] == controller['PodUID'],'source controller changed')
    if november13: cleanup_release_pod(site,r,A)
    endpoints = [(c['Purpose'],c['Endpoint']) for c in parent['Connections']
        if (urlsplit(c['Endpoint']).hostname or '').endswith('.'+A.NS+'.svc')]
    dns = load('longhorn_dns',directory/'p2-source-dns.py').SourceDNS(site,r,pod,endpoints,A.retain)
    dns.probe()
    out = Path(pin['File']).parent.parent/output_name; out.mkdir(mode=0o700,exist_ok=True)
    need(out.resolve(strict=True) == out and out.stat().st_mode & 0o077 == 0 and not list(out.iterdir()),'new empty native output directory required')
    old = json.loads((ROOT/source_name/'author.sent.private.json').read_bytes())['Argv']
    need(old[1] == 'author-initial-source-inputs','original source author invocation required')
    common = old[2:old.index('--definition-file')]
    argv = [str(native),'prepare-mount-materials',*common,'--source-selection-file',pin['File'],
        '--source-selection-sha256',pin['SHA256'],'--mount-layouts-file',layout['File'],
        '--mount-layouts-sha256',layout['SHA256'],'--output-directory',str(out)]
    A.retain(r/'native.sent.private.json',{'Argv':argv,'SourceSelection':pin,'Layouts':layout,'VaultWriterSelection':renewed['VaultWriterSelection']})
    with (r/'native.stdout.private').open('xb') as stdout,(r/'native.stderr.private').open('xb') as stderr:
        result = dns.run(argv,stdout=stdout,stderr=stderr,timeout=180)
    A.retain(r/'native.exit.json',{'ExitCode':result.returncode})
    raw = (r/'native.stdout.private').read_bytes()
    if result.returncode:
        try:
            error = json.loads(raw)
            if error.get('Status') in ['original_mount_materials_blocked', 'original_mount_author_refused']:
                print('P2_LONGHORN_NATIVE_REFUSAL',json.dumps({k:error.get(k) for k in ['Phase','Step','Kind','Reason','Code','InstanceID','MountID']}),flush=True)
        except ValueError: pass
        raise ValueError('native mount author refused; retain journal and partial outputs')
    value = json.loads(raw)
    need(value['SelectionSHA256'] == pin['SHA256'] and value['LayoutSelectionSHA256'] == layout['SHA256'],'native receipt input pins differ')
    for key in ['Deployment','MaterialsTemplate','SourceSelection','LonghornHoldMaterials']: A.read(value[key])
    validate_successor(parent,A.obj(value['SourceSelection']),value,A.obj(value['MaterialsTemplate']))
    done = {'Version':'p2-longhorn-source-materials-authored.v1','Receipt':A.retain(r/'native.receipt.private.json',raw),
        'ParentSelection':pin,**{k:value[k] for k in ['Deployment','MaterialsTemplate','SourceSelection','LonghornHoldMaterials']},
        'VaultWriterSelection':renewed['VaultWriterSelection'],'Until':parent['Until'],'NativeHoldClaim':False,'GrantsIssued':False,'BackupReady':False}
    A.retain(r/'completed.json',done)
    print('P2_LONGHORN_SOURCE_MATERIALS_AUTHORED_NO_HOLD',json.dumps(done),flush=True)

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--redis-renewed-source', action='store_true')
        parser.add_argument('--phase-readback', action='store_true')
        parser.add_argument('--credential-encoding', action='store_true')
        parser.add_argument('--pv-read-repaired', action='store_true')
        parser.add_argument('--november13', action='store_true')
        parser.add_argument('--runtime-scope-renewed', action='store_true')
        parser.add_argument('--writer-api-readback', action='store_true')
        args = parser.parse_args()
        main(args.redis_renewed_source, args.phase_readback, args.credential_encoding, args.pv_read_repaired, args.november13, args.runtime_scope_renewed, args.writer_api_readback)
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        raise SystemExit('P2_LONGHORN_SOURCE_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
