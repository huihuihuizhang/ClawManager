#!/usr/bin/env python3
"""Read-only formal Vault handoff inspection; no token issuance or workload patch."""
import base64
import datetime as dt
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
PARENT = ROOT / 'source-preparation-20261113-role-repair'
RECEIPT_SHA = '4fa1247abe132d70ba37d3e241c18c93b0c302ab45826144653bd1fac4592ead'
SOURCE_SHA = '3050ddef86abc37bd95feb1c16795f4df05fb73571d3185065baa77d2502cb70'
DEFINITION_SHA = 'a9b199b150f9e3f2610f11c5f1b47fd3cd8f5064940df67f9735e6b375fb7c40'
WRITER_SHA = '1e7560fbcba32bdd812aea39c19c743f3338cba71eb432cb28e4aa099edf3163'
NS = 'clawmanager-sbk-validation-system'
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def controller_projection(deployment, ref):
    meta, spec = deployment['metadata'], deployment['spec']
    pod = spec['template']['spec']
    need(meta['namespace'] == ref['Namespace'] == NS and meta['name'] == ref['Deployment'] and
         meta['uid'] == ref['DeploymentUID'] and not meta.get('deletionTimestamp') and
         pod['serviceAccountName'] == ref['ServiceAccount'], 'pinned controller identity changed')
    security = pod.get('securityContext', {})
    rows = []
    for container in pod['containers']:
        own = container.get('securityContext', {})
        uid = own.get('runAsUser', security.get('runAsUser'))
        group = security.get('fsGroup')
        mounts = container.get('volumeMounts', [])
        root = '/var/run/clawreef/system-backup/provider-dependency'
        conflict = any(m['name'] in ('provider-dependency', 'provider-dependency-input') or
                       m['mountPath'] == root or root.startswith(m['mountPath'] + '/') or
                       m['mountPath'].startswith(root + '/') for m in mounts)
        rows.append({'Name': container['name'], 'Image': container['image'],
                     'DigestPinned': re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}', container['image']) is not None,
                     'RunAsUser': uid, 'FSGroup': group,
                     'ExplicitIdentityEligible': type(uid) is int and uid >= 0 and
                         (uid == 0 or type(group) is int and group > 0),
                     'ProviderMountConflict': conflict,
                     'Mounts': [{'Name': m['name'], 'Path': m['mountPath'], 'ReadOnly': m.get('readOnly', False)} for m in mounts]})
    return {'Name': meta['name'], 'UID': meta['uid'], 'Generation': meta['generation'],
            'Replicas': spec.get('replicas'), 'Ready': deployment.get('status', {}).get('readyReplicas', 0),
            'ServiceAccount': pod['serviceAccountName'], 'Containers': rows,
            'ProviderVolumePresent': any(v['name'] in ('provider-dependency', 'provider-dependency-input') for v in pod.get('volumes', [])),
            'ProviderInitPresent': any(c['name'] == 'provider-dependency-install' for c in pod.get('initContainers', []))}


class Site:
    def __init__(self, directory, save):
        self.directory, self.save, self.sequence = directory, save, 0

    def run(self, argv):
        need(bool(argv) and (argv[0] == 'get' or len(argv) == 7 and argv[0] == 'exec' and argv[2:] ==
             ['-c', argv[3], '--', 'sha256sum', '/usr/local/bin/system-backup-source-registries']),
             'read-only API/file inspection required')
        self.sequence += 1
        p = subprocess.run(['kubectl', '--kubeconfig', KUBE, '--request-timeout=20s', '-n', NS, *argv],
                           capture_output=True, timeout=40)
        self.save(self.directory / ('api-%03d.stdout.private' % self.sequence), p.stdout or b'\n')
        self.save(self.directory / ('api-%03d.stderr.private' % self.sequence), p.stderr or b'\n')
        self.save(self.directory / ('api-%03d.exit.json' % self.sequence), {'ExitCode': p.returncode})
        need(len(p.stdout) <= 8 << 20, 'bounded API response required')
        return p

    def call(self, argv):
        p = self.run(argv)
        need(p.returncode == 0, 'read-only API request refused; retain private records')
        return p.stdout

    def get(self, kind, name):
        return json.loads(self.call(['get', kind, name, '-o', 'json']))


def main():
    os.umask(0o077)
    need(os.name == 'posix', 'Linux operator required')
    A, F = load('assemble-p2-installation-candidate'), load('p2-vault-local-forward')
    receipt = A.obj({'File': str(PARENT / 'receipt.private.json'), 'SHA256': RECEIPT_SHA})
    done = A.decode((PARENT / 'completed.json').read_bytes())
    need(done['Receipt']['SHA256'] == RECEIPT_SHA and receipt['SourceSelection']['SHA256'] == SOURCE_SHA and
         done['Definition']['SHA256'] == DEFINITION_SHA and
         done['VaultWriterSelection']['SHA256'] == WRITER_SHA and
         receipt['GrantsIssued'] is False and receipt['BackupReady'] is False, 'observed unsigned role successor required')
    selected = A.obj(receipt['SourceSelection'])
    definition = A.obj(done['Definition'])
    core = A.obj(receipt['Deployment'])
    writer = A.obj(done['VaultWriterSelection'])
    need(len(writer['PreAdoptionVaultDependencies']) == 1 and not writer.get('VaultProviderDependencies') and
         not core.get('provider_dependencies'), 'unconverted original Vault dependency required')
    dependency = writer['PreAdoptionVaultDependencies'][0]
    config = A.obj(dependency['InstalledObserver'])
    need(config['IdentityMode'] == 'original-owner-readonly', 'original read-only owner observer required')
    now = dt.datetime.now(dt.timezone.utc)
    until = dt.datetime.fromisoformat(definition['Until'].replace('Z', '+00:00'))
    print('SOURCE_ROLE_WINDOW', json.dumps({'UTCNow': now.isoformat(), 'Until': definition['Until'],
          'RemainingSeconds': int((until - now).total_seconds())}), flush=True)
    directory = Path(tempfile.mkdtemp(prefix='formal-vault-preflight-', dir=ROOT))
    print('FORMAL_VAULT_PREFLIGHT_RECORDS', directory, flush=True)
    site = Site(directory, A.retain)
    ref = selected['Controller']
    deployment = site.get('deployment', ref['Deployment'])
    projection = controller_projection(deployment, ref)
    A.retain(directory / 'controller.before.private.json', deployment)
    print('FORMAL_VAULT_CONTROLLER', json.dumps(projection), flush=True)
    pod, rs = site.get('pod', ref['Pod']), site.get('replicaset', ref['ReplicaSet'])
    for obj, uid, parent_kind, parent_uid in [(pod, ref['PodUID'], 'ReplicaSet', ref['ReplicaSetUID']),
                                            (rs, ref['ReplicaSetUID'], 'Deployment', ref['DeploymentUID'])]:
        need(obj['metadata']['uid'] == uid and not obj['metadata'].get('deletionTimestamp') and
             [(o['kind'], o['uid']) for o in obj['metadata'].get('ownerReferences', []) if o.get('controller')] ==
             [(parent_kind, parent_uid)], 'controller owner chain changed')
    need(pod['status']['phase'] == 'Running', 'current controller Pod required')
    for container in projection['Containers']:
        result = site.run(['exec', pod['metadata']['name'], '-c', container['Name'], '--',
                           'sha256sum', '/usr/local/bin/system-backup-source-registries'])
        match = re.fullmatch(rb'([a-f0-9]{64})\s+/usr/local/bin/system-backup-source-registries\s*', result.stdout)
        print('FORMAL_VAULT_INSTALLER_BINARY', json.dumps({'Container': container['Name'], 'ExitCode': result.returncode,
              'SHA256': match[1].decode() if result.returncode == 0 and match else None}), flush=True)
    endpoint = urlsplit(config['Endpoint'])
    flags = {'--provider-service': dependency['Workload']['Service'], '--provider-endpoint': config['Endpoint']}
    ca = base64.b64decode(config['CAPEM'], validate=True)
    need(hashlib.sha256(ca).hexdigest() == config['CASHA256'], 'pinned Vault CA changed')
    token = A.read({'File': config['TokenFile'], 'SHA256': config['TokenSHA256']}, 16384).decode('ascii')
    need(token and all(33 <= ord(c) <= 126 for c in token), 'one original token required')
    tls = ssl.create_default_context(cadata=ca.decode('ascii'))
    forward = F.LocalForward(site, flags, directory, A.retain)
    with forward as address:
        class Connection(http.client.HTTPSConnection):
            def connect(self):
                raw = socket.create_connection(('127.0.0.1', int(address.split(':')[1])), timeout=5)
                try:
                    self.sock = tls.wrap_socket(raw, server_hostname=endpoint.hostname)
                except BaseException:
                    raw.close()
                    raise
        for label, path in [('health', '/v1/sys/health'), ('identity', '/v1/auth/token/lookup-self')]:
            connection = Connection(endpoint.hostname, endpoint.port or 443, context=tls, timeout=5)
            try:
                connection.request('GET', path, headers={'X-Vault-Token': token} if label == 'identity' else {})
                response = connection.getresponse()
                body = response.read((1 << 20) + 1)
                need(response.status == 200 and len(body) <= 1 << 20, 'Vault read-only ' + label + ' refused')
                value = A.decode(body)
                if label == 'health':
                    report = {'Initialized': value.get('initialized'), 'Sealed': value.get('sealed'),
                              'Version': value.get('version'), 'ClusterMatches': value.get('cluster_id') == config['ClusterID']}
                    need(report['Initialized'] is True and report['Sealed'] is False and report['ClusterMatches'], 'Vault health identity differs')
                else:
                    data = value['data']
                    report = {'RootOnly': data.get('policies') == ['root'],
                              'IdentityPolicyCount': len(data.get('identity_policies') or []), 'TTL': data.get('ttl')}
                    need(report['RootOnly'] and report['IdentityPolicyCount'] == 0, 'original Vault owner identity differs')
                print('FORMAL_VAULT_' + label.upper(), json.dumps(report), flush=True)
            finally:
                connection.close()
        forward.check()
    token = ''
    need(site.get('deployment', ref['Deployment']) == deployment, 'controller changed during inspection')
    A.retain(directory / 'completed.json', {'Version': 'p2-formal-vault-readonly-preflight.v1',
             'SourceSelection': receipt['SourceSelection'], 'Controller': projection,
             'IAMMutated': False, 'WorkloadPatched': False, 'BackupReady': False})
    print('FORMAL_VAULT_READONLY_PREFLIGHT_FINISHED', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        raise SystemExit('FORMAL_VAULT_PREFLIGHT_UNCONFIRMED ' + (str(e) if type(e) is ValueError else type(e).__name__))
