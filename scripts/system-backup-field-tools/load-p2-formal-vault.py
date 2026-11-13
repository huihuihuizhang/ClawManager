#!/usr/bin/env python3
"""Load the already-issued provider material and natively refresh controller source references."""
import base64
import copy
import datetime as dt
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
PARENT = ROOT / 'formal-vault-materials-20261113'
ROLE = ROOT / 'source-preparation-20261113-role-repair'
RECEIPT_SHA = 'ec5f93e8334be3c73f6f05a82179320aca37a6c6c7412860db16df18b06345b3'
PINS = {'SourceSelection': '1b9cc5d68f4ec78fd8134acc67ecdd143cfb7aab856309817271e26ea145907a',
        'SecretManifest': '0feae04ecec8a272e321bbe4784eec50de5746bb31412a72822dd9c42c73bad6',
        'DeploymentPatch': '5f33909e824066ba26792b973f2c68d803b230bf0abc548778e1bdd17a5a82a1'}
BIN = Path('/root/sbk/p2-role-repair-030a2a66/system-backup-first-install-materials')
BIN_SHA = 'fdb545d35e2cbc5d2a468aa6cee89abd0b5a00eb3feb8394b3794c1ed95f2596'
NS = 'clawmanager-sbk-validation-system'
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'
MOUNT = '/var/run/clawreef/system-backup/provider-dependency'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guarded_patch(original, current, native):
    need(original['metadata']['uid'] == current['metadata']['uid'] and not current['metadata'].get('deletionTimestamp') and
         original['spec'] == current['spec'], 'controller specification changed since native issuance')
    need(native[:2] == [{'op': 'test', 'path': '/metadata/uid', 'value': original['metadata']['uid']},
                        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': original['metadata']['resourceVersion']}],
         'original native patch guards differ')
    # Preserve the native patch. A successor CAS uses the current RV only after
    # complete spec equality, with an extra atomic spec test protecting every field.
    return [native[0], {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec', 'value': copy.deepcopy(original['spec'])}, *copy.deepcopy(native[2:])]


def validate_delivery_spec(original, desired, secret, observer_sha, token_sha):
    stripped = copy.deepcopy(desired)
    pod, before = stripped['template']['spec'], original['template']['spec']
    names = ('provider-dependency-input', 'provider-dependency')
    added = [v for v in pod.get('volumes', []) if v['name'] in names]
    need(len(added) == 2 and not any(v['name'] in names for v in before.get('volumes', [])), 'exact new provider volumes required')
    by_name = {v['name']: v for v in added}
    need(by_name[names[0]] == {'name': names[0], 'secret': {'secretName': secret['metadata']['name'], 'defaultMode': 0o440}} and
         by_name[names[1]] == {'name': names[1], 'emptyDir': {'medium': 'Memory'}}, 'provider volume source changed')
    pod['volumes'] = [v for v in pod['volumes'] if v['name'] not in names]
    init = [c for c in pod.get('initContainers', []) if c['name'] == 'provider-dependency-install']
    need(len(init) == 1, 'one native provider initializer required')
    pod['initContainers'] = [c for c in pod['initContainers'] if c['name'] != 'provider-dependency-install']
    if not pod['initContainers'] and 'initContainers' not in before:
        del pod['initContainers']
    controllers = [c for c in pod['containers'] if c['name'] == 'controller']
    need(len(controllers) == 1, 'one controller container required')
    controller = controllers[0]
    mount = [m for m in controller.get('volumeMounts', []) if m['name'] == names[1]]
    need(mount == [{'name': names[1], 'mountPath': MOUNT, 'subPath': 'private', 'readOnly': True}], 'exact private read-only mount required')
    controller['volumeMounts'] = [m for m in controller['volumeMounts'] if m['name'] != names[1]]
    old_controller = next(c for c in before['containers'] if c['name'] == 'controller')
    if not controller['volumeMounts'] and 'volumeMounts' not in old_controller:
        del controller['volumeMounts']
    security = copy.deepcopy(old_controller.get('securityContext', {}))
    uid = security.get('runAsUser', before.get('securityContext', {}).get('runAsUser'))
    need(uid == 65532 and before.get('securityContext', {}).get('fsGroup') == 65532, 'observed nonroot identity required')
    security['runAsUser'] = uid
    wanted = {'name': 'provider-dependency-install', 'image': old_controller['image'],
              'imagePullPolicy': old_controller['imagePullPolicy'], 'securityContext': security,
              'command': ['/usr/local/bin/system-backup-source-registries'],
              'args': ['install-provider-files', '--observer-sha256', observer_sha, '--token-sha256', token_sha],
              'volumeMounts': [{'name': names[0], 'mountPath': '/input', 'readOnly': True}, {'name': names[1], 'mountPath': '/output'}]}
    actual = copy.deepcopy(init[0])
    for k, default in [('resources', {}), ('terminationMessagePath', '/dev/termination-log'), ('terminationMessagePolicy', 'File')]:
        need(actual.pop(k, default) == default, 'unexpected initializer setting')
    need(actual == wanted and stripped == original, 'delivery changes image, startup, business mounts or unrelated controller configuration')


def successor_definition(original, core, materials, selected, new_controller, out):
    value = copy.deepcopy(original)
    need(value['Controller'] == selected['Controller'], 'original controller source reference differs')
    stable = [k for k in selected['Controller'] if k not in ('Pod', 'PodUID', 'ReplicaSet', 'ReplicaSetUID')]
    need(all(new_controller[k] == selected['Controller'][k] for k in stable), 'controller authority identity changed')
    need(core['profile_file'] == selected['ExecutionProfile']['File'] and
         core['capture_modules']['path'] == str(Path(selected['ExecutionProfile']['File']).parent / 'capture-materials.json') and
         materials['DeploymentConfigSHA256'] == selected['Deployment']['SHA256'] and materials['CaptureGrantSHA256'] == '',
         'native unsigned core/material binding required')
    value['Controller'] = copy.deepcopy(new_controller)
    value['Deployment'], value['Materials'] = copy.deepcopy(core), copy.deepcopy(materials)
    value['Deployment']['profile_file'] = str(out / 'execution-profile.json')
    value['Deployment']['capture_modules']['path'] = str(out / 'capture-materials.json')
    value['Materials']['DeploymentConfigSHA256'] = ''
    return value


def validate_running_pod(desired, pod):
    template = desired['template']['spec']
    actual = pod['spec']
    for group in ('containers', 'initContainers'):
        expected = template.get(group, [])
        observed = actual.get(group, [])
        need([c['name'] for c in observed] == [c['name'] for c in expected], 'running Pod container roster differs')
        for before, after in zip(expected, observed):
            for field in ('image', 'imagePullPolicy', 'command', 'args', 'env', 'envFrom', 'securityContext'):
                need(before.get(field) == after.get(field), 'running Pod image, startup or identity differs')
            mounts = lambda c: [m for m in c.get('volumeMounts', []) if m['name'].startswith('provider-dependency')]
            need(mounts(before) == mounts(after), 'running Pod provider mounts differ')
    volumes = lambda p: [v for v in p.get('volumes', []) if v['name'].startswith('provider-dependency')]
    need(volumes(template) == volumes(actual) and template.get('securityContext') == actual.get('securityContext') and
         template.get('serviceAccountName') == actual.get('serviceAccountName'), 'running Pod provider volumes or identity differ')


class Site:
    def __init__(self, directory, A):
        self.directory, self.A = directory, A
        self.seq = len(list(directory.glob('api-*.stdout.private')))

    def run(self, args, body=None, timeout=45):
        self.seq += 1
        result = subprocess.run(['kubectl', '--kubeconfig', KUBE, '--request-timeout=20s', '-n', NS, *args],
                                input=body, capture_output=True, timeout=timeout)
        stem = self.directory / ('api-%05d' % self.seq)
        self.A.retain(Path(str(stem) + '.stdout.private'), result.stdout or b'\n')
        self.A.retain(Path(str(stem) + '.stderr.private'), result.stderr or b'\n')
        self.A.retain(Path(str(stem) + '.exit.json'), {'ExitCode': result.returncode})
        return result

    def call(self, args, body=None, timeout=45):
        result = self.run(args, body, timeout)
        need(result.returncode == 0, 'API operation unconfirmed; retain journal and read back before retrying')
        return result.stdout

    def get(self, kind, name):
        return self.A.decode(self.call(['get', kind, name, '-o', 'json']))

    def send(self, label, args, body):
        marker = self.directory / (label + '.sent.private.json')
        need(not marker.exists(), label + ' was already sent; inspect actual state, never resend blindly')
        self.A.retain(marker, {'Argv': args, 'InputSHA256': self.A.sha(body)})
        return self.call(args, body)


def verify_secret(actual, wanted):
    need(actual['metadata'].get('uid') and not actual['metadata'].get('deletionTimestamp') and
         not actual['metadata'].get('ownerReferences') and actual['metadata']['name'] == wanted['metadata']['name'] and
         actual['metadata']['namespace'] == wanted['metadata']['namespace'] and actual.get('immutable') is True and
         actual.get('type') == wanted.get('type') and actual.get('data') == wanted.get('data'), 'existing Secret differs from native material')


def verify_metadata(A, F, site, journal, observer, token, workload, until):
    from urllib.parse import urlsplit
    endpoint = urlsplit(observer['Endpoint'])
    ca = base64.b64decode(observer['CAPEM'], validate=True)
    need(A.sha(ca) == observer['CASHA256'] and A.sha(token) == observer['TokenSHA256'] and
         observer['IdentityMode'] == 'metadata-only' and observer['ObserverPolicy'] not in ('root', 'default'), 'native metadata identity required')
    tls = ssl.create_default_context(cadata=ca.decode('ascii'))
    forward_dir = journal / ('metadata-readback-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
    forward_dir.mkdir(mode=0o700)
    forward = F.LocalForward(site, {'--provider-service': workload['Service'], '--provider-endpoint': observer['Endpoint']}, forward_dir, A.retain)
    with forward as address:
        class Connection(http.client.HTTPSConnection):
            def connect(self):
                raw = socket.create_connection(('127.0.0.1', int(address.split(':')[1])), timeout=5)
                try: self.sock = tls.wrap_socket(raw, server_hostname=endpoint.hostname)
                except BaseException:
                    raw.close()
                    raise
        connection = Connection(endpoint.hostname, endpoint.port or 443, timeout=5, context=tls)
        try:
            connection.request('GET', '/v1/auth/token/lookup-self', headers={'X-Vault-Token': token.decode('ascii')})
            response = connection.getresponse(); body = response.read((1 << 20) + 1)
            need(response.status == 200 and len(body) <= 1 << 20, 'metadata identity readback refused')
            data = A.decode(body)['data']; now = dt.datetime.now(dt.timezone.utc)
            need(data.get('policies') == [observer['ObserverPolicy']] and not data.get('identity_policies') and
                 data.get('renewable') is False and data.get('type') == 'service' and type(data.get('ttl')) is int and
                 data['ttl'] > max(600, int((until - now).total_seconds())), 'metadata-only token does not cover source window')
            report = {'CheckedAt': now.isoformat(), 'TTLSeconds': data['ttl'], 'MetadataPolicyMatches': True, 'CoversSourceWindow': True}
            A.retain(forward_dir / 'identity-readback.json', report)
            print('P2_FORMAL_VAULT_METADATA_IDENTITY_VERIFIED', json.dumps(report), flush=True)
        finally:
            connection.close()
        forward.check()


def main():
    os.umask(0o077); need(os.name == 'posix', 'Linux operator required')
    A, F = load('assemble-p2-installation-candidate'), load('p2-vault-local-forward')
    receipt = A.obj({'File': str(PARENT / 'receipt.private.json'), 'SHA256': RECEIPT_SHA})
    for key, expected in PINS.items(): need(receipt[key]['SHA256'] == expected, 'observed native material pin differs')
    selected, core, materials = A.obj(receipt['SourceSelection']), A.obj(receipt['Deployment']), A.obj(receipt['MaterialsTemplate'])
    need(receipt['Version'] == 'formal-vault-dependency-materials.v1' and
         selected['Deployment'] == receipt['Deployment'] and selected['MaterialsTemplate'] == receipt['MaterialsTemplate'],
         'native formal source pin chain required')
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts already exist')
    A.read({'File': str(BIN), 'SHA256': BIN_SHA}, 128 << 20)
    role = A.decode((ROLE / 'completed.json').read_bytes())
    need(role['Definition']['SHA256'] == 'a9b199b150f9e3f2610f11c5f1b47fd3cd8f5064940df67f9735e6b375fb7c40', 'observed original definition required')
    successor_definition(A.obj(role['Definition']), core, materials, selected, selected['Controller'],
                         Path(selected['ExecutionProfile']['File']).parent.parent / 'initial-source-20261113-provider-loaded')
    secret, native_patch = A.obj(receipt['SecretManifest']), A.obj(receipt['DeploymentPatch'])
    until = dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00'))
    need(dt.datetime.now(dt.timezone.utc) < until - dt.timedelta(minutes=10), 'source window insufficient; renew before loading')
    need(secret['immutable'] is True and secret['metadata']['namespace'] == NS and set(secret['data']) == {'token', 'observer.json'}, 'native immutable provider Secret required')
    observer_raw, token = (base64.b64decode(secret['data'][n], validate=True) for n in ('observer.json', 'token'))
    observer = A.decode(observer_raw); observer_sha, token_sha = A.sha(observer_raw), A.sha(token)
    need(secret['metadata']['name'] == 'backup-provider-' + observer_sha[:24] and observer['TokenFile'] == MOUNT + '/token' and
         core['provider_dependencies'][0]['observer'] == {'File': MOUNT + '/observer.json', 'SHA256': observer_sha}, 'native provider delivery binding differs')
    original = A.decode((PARENT / 'controller.before.private.json').read_bytes())
    journal = ROOT / 'formal-vault-load-20261113'; journal.mkdir(mode=0o700, exist_ok=True)
    need(journal.resolve() == journal and journal.stat().st_mode & 0o077 == 0, 'private load journal required')
    print('P2_FORMAL_VAULT_LOAD_RECORDS', journal, flush=True)
    A.retain(journal / 'inputs.json', {'Receipt': {'File': str(PARENT / 'receipt.private.json'), 'SHA256': RECEIPT_SHA}})
    site = Site(journal, A); ref = selected['Controller']; current = site.get('deployment', ref['Deployment'])
    need(current['metadata']['uid'] == ref['DeploymentUID'] == original['metadata']['uid'], 'controller replaced')
    verify_metadata(A, F, site, journal, observer, token, receipt['Workload'], until)
    plan_file = journal / 'delivery-plan.private.json'
    if plan_file.exists():
        plan = A.decode(plan_file.read_bytes()); desired = A.obj(plan['DesiredSpec']); transport = A.read(plan['TransportPatch'])
    else:
        transport_pin = A.retain(journal / 'transport-patch.private.json', guarded_patch(original, current, native_patch))
        transport = A.read(transport_pin)
        dry = A.decode(site.call(['patch', 'deployment', ref['Deployment'], '--type=json', '--patch-file=/dev/stdin', '--dry-run=server', '-o', 'json'], transport))
        desired = dry['spec']
        validate_delivery_spec(original['spec'], desired, secret, observer_sha, token_sha)
        A.retain(plan_file, {'NativePatch': receipt['DeploymentPatch'], 'TransportPatch': transport_pin,
                            'DesiredSpec': A.retain(journal / 'desired-spec.private.json', desired)})
    validate_delivery_spec(original['spec'], desired, secret, observer_sha, token_sha)
    if current['spec'] != desired:
        need(current['spec'] == original['spec'], 'controller drift before delivery')
        # Invalid hashes are refused before any file I/O by this init-only command.
        protocol = site.run(['exec', ref['Pod'], '-c', 'installation-owner', '--', '/usr/local/bin/system-backup-source-registries',
                             'install-provider-files', '--observer-sha256', 'invalid', '--token-sha256', 'invalid'])
        need(protocol.returncode == 1 and not protocol.stdout.strip(), 'current image initializer protocol unconfirmed')
    raw = site.call(['get', 'secret', secret['metadata']['name'], '--ignore-not-found', '-o', 'json'])
    if not raw.strip():
        print('P2_FORMAL_VAULT_STEP secret_create', flush=True)
        site.send('secret-create', ['create', '-f', '-', '-o', 'json'], A.read(receipt['SecretManifest']))
    actual_secret = site.get('secret', secret['metadata']['name']); verify_secret(actual_secret, secret)
    A.retain(journal / 'secret-created.json', {'Name': actual_secret['metadata']['name'], 'UID': actual_secret['metadata']['uid']})
    if current['spec'] != desired:
        print('P2_FORMAL_VAULT_STEP controller_patch', flush=True)
        site.send('controller-patch', ['patch', 'deployment', ref['Deployment'], '--type=json', '--patch-file=/dev/stdin', '-o', 'json'], transport)
    print('P2_FORMAL_VAULT_STEP controller_rollout', flush=True)
    site.call(['rollout', 'status', 'deployment/' + ref['Deployment'], '--timeout=180s'], timeout=210)
    deployed = site.get('deployment', ref['Deployment'])
    need(deployed['metadata']['uid'] == ref['DeploymentUID'] and not deployed['metadata'].get('deletionTimestamp') and
         deployed['spec'] == desired and deployed['status'].get('observedGeneration') == deployed['metadata']['generation'] and
         deployed['status'].get('readyReplicas') == deployed['status'].get('updatedReplicas') == desired.get('replicas') == 1,
         'controller rollout or configuration unconfirmed')
    selector = ','.join(k + '=' + v for k, v in desired['selector']['matchLabels'].items())
    pods = A.decode(site.call(['get', 'pods', '-l', selector, '-o', 'json']))['items']
    pods = [p for p in pods if not p['metadata'].get('deletionTimestamp')]
    need(len(pods) == 1, 'one settled controller Pod required'); pod = pods[0]
    owners = [o for o in pod['metadata'].get('ownerReferences', []) if o.get('controller')]
    need(len(owners) == 1 and owners[0]['kind'] == 'ReplicaSet', 'controller Pod owner required')
    rs = site.get('replicaset', owners[0]['name']); parents = [o for o in rs['metadata'].get('ownerReferences', []) if o.get('controller')]
    need(rs['metadata']['uid'] == owners[0]['uid'] and not rs['metadata'].get('deletionTimestamp') and
         [(o['kind'], o['uid']) for o in parents] == [('Deployment', ref['DeploymentUID'])], 'current controller owner chain differs')
    validate_running_pod(desired, pod)
    statuses = pod['status'].get('containerStatuses', [])
    init = [s for s in pod['status'].get('initContainerStatuses', []) if s['name'] == 'provider-dependency-install']
    need(pod['status']['phase'] == 'Running' and len(statuses) == 2 and all(s.get('ready') and s['state'].get('running') is not None for s in statuses) and
         len(init) == 1 and init[0]['state'].get('terminated', {}).get('exitCode') == 0, 'provider initializer or controller not ready')
    readback = 'set -eu; test "$(id -u)" = 65532; for name in observer.json token; do file=' + MOUNT + '/"$name"; test -f "$file"; test ! -L "$file"; stat -c "%a %u" "$file"; sha256sum "$file"; done'
    lines = site.call(['exec', pod['metadata']['name'], '-c', 'controller', '--', 'sh', '-ec', readback]).decode('ascii').splitlines()
    need(len(lines) == 4, 'bounded loaded file readback required')
    for index, (name, expected) in enumerate([('observer.json', observer_sha), ('token', token_sha)]):
        need(lines[index * 2].split() == ['600', '65532'] and lines[index * 2 + 1].split() == [expected, MOUNT + '/' + name], 'loaded file mode, owner or hash differs')
        print('P2_FORMAL_VAULT_FILE_LOADED', json.dumps({'File': name, 'Mode': '0600', 'UID': 65532, 'SHA256Matches': True}), flush=True)
    fresh = {**ref, 'Pod': pod['metadata']['name'], 'PodUID': pod['metadata']['uid'], 'ReplicaSet': rs['metadata']['name'], 'ReplicaSetUID': rs['metadata']['uid']}
    need(pod['spec']['serviceAccountName'] == fresh['ServiceAccount'] and site.get('serviceaccount', fresh['ServiceAccount'])['metadata']['uid'] == fresh['ServiceAccountUID'], 'controller ServiceAccount changed')
    A.retain(journal / 'loaded.json', {'Controller': fresh, 'SecretUID': actual_secret['metadata']['uid'], 'BackupReady': False})
    print('P2_FORMAL_VAULT_MOUNT_LOADED_SOURCE_REFRESH_REQUIRED', json.dumps({'Controller': fresh, 'BackupReady': False}), flush=True)
    reauthor(A, site, journal, receipt, selected, core, materials, fresh)


def reauthor(A, site, journal, receipt, selected, core, materials, fresh):
    role = A.decode((ROLE / 'completed.json').read_bytes())
    need(role['Definition']['SHA256'] == 'a9b199b150f9e3f2610f11c5f1b47fd3cd8f5064940df67f9735e6b375fb7c40', 'observed original definition required')
    original = A.obj(role['Definition'])
    out = Path(selected['ExecutionProfile']['File']).parent.parent / 'initial-source-20261113-provider-loaded'
    definition = successor_definition(original, core, materials, selected, fresh, out)
    author = journal / 'source-author'; author.mkdir(mode=0o700, exist_ok=True)
    pin = A.retain(author / 'definition.private.json', definition)
    A.read({'File': str(BIN), 'SHA256': BIN_SHA}, 128 << 20)
    saved = author / 'receipt.private.json'
    if not saved.exists():
        need(not (author / 'native.sent.private.json').exists(), 'source author already sent; reconcile its retained result')
        need(not out.exists(), 'new source output directory required'); out.mkdir(mode=0o700)
        old = A.decode((ROLE / 'author.sent.private.json').read_bytes())['Argv']
        need(old[1] == 'author-initial-source-inputs', 'original source author invocation required')
        argv = [str(BIN), 'author-initial-source-inputs', *old[2:old.index('--definition-file')],
                '--definition-file', pin['File'], '--definition-sha256', pin['SHA256'], '--output-directory', str(out)]
        A.retain(author / 'native.sent.private.json', {'Argv': argv, 'ParentReceipt': {'File': str(PARENT / 'receipt.private.json'), 'SHA256': RECEIPT_SHA}})
        print('P2_FORMAL_VAULT_STEP source_reauthor', flush=True)
        with (author / 'native.stdout.private').open('xb') as stdout, (author / 'native.stderr.private').open('xb') as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=180)
        A.retain(author / 'native.exit.json', {'ExitCode': result.returncode})
        need(result.returncode == 0, 'mount loaded but native source refresh refused; retain source author records')
        A.retain(saved, (author / 'native.stdout.private').read_bytes())
    raw = saved.read_bytes(); result = A.decode(raw)
    need(result['Version'] == 'original-initial-source-inputs-authored.v1' and result['GrantsIssued'] is False and result['BackupReady'] is False, 'native unsigned source refresh required')
    for key in ('Deployment', 'MaterialsTemplate', 'ExecutionProfile', 'SourceSelection'): A.read(result[key])
    actual = A.obj(result['SourceSelection'])
    need(actual['Controller'] == fresh and A.obj(result['Deployment'])['provider_dependencies'] == core['provider_dependencies'], 'refreshed controller/provider reference differs')
    current = site.get('pod', fresh['Pod']); need(current['metadata']['uid'] == fresh['PodUID'] and not current['metadata'].get('deletionTimestamp'), 'controller changed during source refresh')
    complete = {'Version': 'p2-formal-vault-loaded-source-reauthored.v1', 'Receipt': {'File': str(saved), 'SHA256': A.sha(raw)},
                'Definition': pin, 'SourceSelection': result['SourceSelection'], 'Controller': fresh, 'Until': selected['Until'],
                'SourceAPI': role['SourceAPI'], 'VaultWriterSelection': role['VaultWriterSelection'],
                'MetadataTokenReissued': False, 'SecretLoaded': True, 'GrantsIssued': False, 'BackupReady': False}
    A.retain(journal / 'completed.json', complete)
    print('P2_FORMAL_VAULT_LOADED_SOURCE_REAUTHORED_NO_HOLD', json.dumps(complete), flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as e:
        raise SystemExit('P2_FORMAL_VAULT_LOAD_UNCONFIRMED ' + (str(e) if type(e) is ValueError else type(e).__name__))
