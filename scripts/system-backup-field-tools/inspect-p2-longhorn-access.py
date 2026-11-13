#!/usr/bin/env python3
"""Batch read the selected Longhorn metadata with the actual source credential."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
SELECTION_SHA = '99e192900ec2428c38554cfdc5348329d108b7dc8ff0a8935b240f34e3a24b1e'


def need(ok, message):
    if not ok:
        raise ValueError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def main():
    need(os.name == 'posix', 'Linux operator required'); os.umask(0o077)
    spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
    prior = ROOT / 'longhorn-source-20261113-runtime-recovered-census-window'
    sent = A.decode((prior / 'native.sent.private.json').read_bytes())
    need(sent['SourceSelection']['SHA256'] == SELECTION_SHA and
         A.decode((prior / 'native.exit.json').read_bytes()) == {'ExitCode': 1}, 'observed source refusal required')
    refusal = A.decode((prior / 'native.stdout.private').read_bytes())
    need(refusal.get('Phase') == 'longhorn_sources' and refusal.get('Status') == 'original_mount_author_refused', 'observed Longhorn source phase required')
    selected = A.obj(sent['SourceSelection']); core = A.obj(selected['Deployment'])
    now = dt.datetime.now(dt.timezone.utc)
    need(now < dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00')), 'source authorization expired')
    source = next(c for c in selected['Connections'] if c['Purpose'] == 'source_api')
    endpoint = urllib.parse.urlsplit(source['Endpoint'])
    need(endpoint.scheme == 'https' and endpoint.hostname and not endpoint.username and not endpoint.query and not endpoint.fragment,
         'pinned source API endpoint required')
    token = A.read(source['Credential']).decode().strip()
    need(token and not any(c in token for c in '\r\n\0'), 'bounded bearer credential required')
    context = ssl.create_default_context(cadata=A.read(source['CA']).decode()); context.minimum_version = ssl.TLSVersion.TLSv1_3
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    records = Path(tempfile.mkdtemp(prefix='longhorn-access-', dir=ROOT))
    print('LONGHORN_ACCESS_RECORDS', records, flush=True)
    print('LONGHORN_ACCESS_WINDOW', json.dumps({'UTCNow': now.isoformat(), 'Until': selected['Until']}), flush=True)
    results = []

    def get(path):
        report = {'Path': path}
        try:
            request = urllib.request.Request(source['Endpoint'].rstrip('/') + path, headers={'Authorization': 'Bearer ' + token})
            with opener.open(request, timeout=12) as response:
                raw = response.read((8 << 20) + 1); report['Status'] = response.status
            need(0 < len(raw) <= 8 << 20 and report['Status'] == 200, 'bounded API response required')
            obj = A.decode(raw); A.retain(records / ('api-%02d.private.json' % len(results)), raw)
        except urllib.error.HTTPError as error:
            report['Status'] = error.code; obj = None
        except Exception as error:
            report['ErrorType'] = type(error).__name__; obj = None
        results.append(report); print('LONGHORN_SOURCE_READ', json.dumps(report), flush=True)
        return obj

    for path in ['/api/v1/namespaces/longhorn-system',
                 '/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/sbk-validation-longhorn-local',
                 '/apis/storage.k8s.io/v1/storageclasses/longhorn']:
        obj = get(path)
        if obj:
            print('LONGHORN_SOURCE_OBJECT', json.dumps({'Kind': obj.get('kind'), 'Name': obj['metadata']['name'],
                'UID': obj['metadata']['uid'], 'Deleting': bool(obj['metadata'].get('deletionTimestamp')),
                'Driver': obj.get('driver', obj.get('provisioner')), 'Parameters': obj.get('parameters'),
                'DeletionPolicy': obj.get('deletionPolicy'), 'ReclaimPolicy': obj.get('reclaimPolicy')}), flush=True)
    q = lambda value: urllib.parse.quote(value, safe='')
    for namespace, name in [('clawmanager-sbk-validation-system', 'clawmanager-workspaces'),
                            ('clawmanager-sbk-validation-user-1', 'clawreef-2-pvc'),
                            ('clawmanager-sbk-validation-user-1', 'clawreef-team-1-shared')]:
        claim = get('/api/v1/namespaces/' + namespace + '/persistentvolumeclaims/' + name)
        if not claim or not claim['spec'].get('volumeName'): continue
        pv = get('/api/v1/persistentvolumes/' + q(claim['spec']['volumeName']))
        if not pv: continue
        csi = pv['spec'].get('csi', {}); handle = csi.get('volumeHandle', ''); ref = pv['spec'].get('claimRef', {})
        print('LONGHORN_SOURCE_VOLUME', json.dumps({'Namespace': namespace, 'Claim': name, 'ClaimUID': claim['metadata']['uid'],
            'PV': pv['metadata']['name'], 'PVUID': pv['metadata']['uid'], 'Bound': claim.get('status', {}).get('phase') == 'Bound',
            'ClaimRefMatches': ref.get('name') == name and ref.get('namespace') == namespace and ref.get('uid') == claim['metadata']['uid'],
            'AccessModes': claim['spec'].get('accessModes'), 'PVAccessModes': pv['spec'].get('accessModes'),
            'Driver': csi.get('driver'), 'Handle': handle, 'VolumeMode': pv['spec'].get('volumeMode'),
            'FSType': csi.get('fsType'), 'Deleting': bool(pv['metadata'].get('deletionTimestamp') or claim['metadata'].get('deletionTimestamp'))}), flush=True)
        if handle and csi.get('driver') == 'driver.longhorn.io':
            volume = get('/apis/longhorn.io/v1beta2/namespaces/longhorn-system/volumes/' + q(handle))
            if volume:
                print('LONGHORN_VOLUME_STATE', json.dumps({k: volume.get('status', {}).get(k) for k in ['state','robustness','currentNodeID','shareState']}), flush=True)
    command = ['kubectl', '--kubeconfig', '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml',
               '--request-timeout=15s', 'get', 'clusterrole', 'sbk-p2-source-read', '-o', 'json']
    process = subprocess.run(command, capture_output=True, timeout=25)
    A.retain(records / 'role.stdout.private', process.stdout or b'\n'); A.retain(records / 'role.stderr.private', process.stderr or b'\n')
    if process.returncode == 0:
        role = A.decode(process.stdout)
        print('LONGHORN_SOURCE_ROLE', json.dumps({'UID': role['metadata']['uid'], 'Rules': [r for r in role['rules']
            if any(v in ('namespaces','volumesnapshotclasses','storageclasses','volumes') for v in r.get('resources', []))]}), flush=True)
    else:
        print('LONGHORN_SOURCE_ROLE_UNCONFIRMED', process.returncode, flush=True)
    timing = round((prior / 'native.exit.json').stat().st_mtime - (prior / 'native.sent.private.json').stat().st_mtime, 3)
    report = {'Version': 'p2-longhorn-source-access-readback.v1', 'SourceSelection': sent['SourceSelection'],
              'Reads': results, 'ElapsedSeconds': timing, 'Mutated': False, 'BackupReady': False}
    A.retain(records / 'completed.json', report)
    print('LONGHORN_NATIVE_TIMING', timing, flush=True)
    print('LONGHORN_ACCESS_READONLY_FINISHED', flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('LONGHORN_ACCESS_UNCONFIRMED ' + (str(error) if type(error) is ValueError else type(error).__name__))
