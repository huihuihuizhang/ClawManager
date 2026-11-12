#!/usr/bin/env python3
"""Read and author Longhorn source DATA using the existing native owner; no hold."""
import datetime as dt
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

def main():
    os.umask(0o077); need(os.name == 'posix','Linux operator required')
    directory = Path(__file__).resolve().parent
    A = load('longhorn_assembly',directory/'assemble-p2-installation-candidate.py')
    r = ROOT/'longhorn-source-renew8h'; r.mkdir(mode=0o700,exist_ok=True)
    need(r.resolve(strict=True) == r and r.stat().st_mode & 0o077 == 0,'private journal required')
    renewed = json.loads((ROOT/'source-preparation-renew8h/completed.json').read_bytes())
    pin = renewed['SourceSelection']; need(pin['SHA256'] == SELECTION_SHA,'exact renewed source selection required')
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
    A.read({'File':str(BIN),'SHA256':BIN_SHA},128<<20)
    need(hashlib.sha256(HELPER.read_bytes()).hexdigest() == HELPER_SHA,'retained API helper changed')
    site = load('longhorn_site',HELPER).Site(r)
    snapshot = json.loads(site.call(['get','volumesnapshotclass','sbk-validation-longhorn-local','-o','json']))
    clone = json.loads(site.call(['get','storageclass','longhorn','-o','json']))
    layout = A.retain(r/'mount-layouts.json',storage_selection(snapshot,clone))
    controller = parent['Controller']
    pod = site.get('pod',controller['Pod'])
    need(pod['metadata']['uid'] == controller['PodUID'],'source controller changed')
    endpoints = [(c['Purpose'],c['Endpoint']) for c in parent['Connections']
        if (urlsplit(c['Endpoint']).hostname or '').endswith('.'+A.NS+'.svc')]
    dns = load('longhorn_dns',directory/'p2-source-dns.py').SourceDNS(site,r,pod,endpoints,A.retain)
    dns.probe()
    out = Path(pin['File']).parent.parent/'longhorn-source-renew8h'; out.mkdir(mode=0o700,exist_ok=True)
    need(out.resolve(strict=True) == out and out.stat().st_mode & 0o077 == 0 and not list(out.iterdir()),'new empty native output directory required')
    old = json.loads((ROOT/'source-preparation-renew8h/author.sent.private.json').read_bytes())['Argv']
    need(old[1] == 'author-initial-source-inputs','original source author invocation required')
    common = old[2:old.index('--definition-file')]
    argv = [str(BIN),'prepare-mount-materials',*common,'--source-selection-file',pin['File'],
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
            if error.get('Status') == 'original_mount_materials_blocked':
                print('P2_LONGHORN_NATIVE_REFUSAL',json.dumps({k:error.get(k) for k in ['Code','InstanceID','MountID']}),flush=True)
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
    try: main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        raise SystemExit('P2_LONGHORN_SOURCE_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
