#!/usr/bin/env python3
"""Reauthor the recovered runtime scope, then continue native Longhorn authoring."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
IMAGE = '10.130.14.23:5000/clawmanager@sha256:4c196dd9b904244e7715f2151f9f672c9db129b582ca716f1324b2bf31b6847a'
ELF_SHA = '0cb51fc5e39901c26538b2acb94699c4e5f63d08c80297a8c53e02e2b060bc8e'
NATIVE_SHA = 'af8a68e9ce5d236078b33de163498c8f5bb4a25cb753ab6c758577c22e49495c'
APP_UID = '8ebd4d4c-57b6-4a82-b310-fae596681a4e'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def validate_recovery(value):
    need(value == {'Version': 'p2-runtime-pool-recovered.v1',
                  'SourceRevision': '312eaa9e47ad45f71479640185496aa4323e6d06', 'Image': IMAGE,
                  'InstanceID': 3, 'Generation': 9, 'Pool': 8,
                  'PodUID': 'a384ba3f-984d-4108-ae5d-14eaf19ccea8', 'VerifiedLiteIDs': [1, 3, 7, 8],
                  'SourceReauthorRequired': True, 'BackupReady': False}, 'observed completed runtime recovery required')
    need(value['SourceReauthorRequired'] is True and value['BackupReady'] is False and
         all(type(value[k]) is int for k in ('InstanceID', 'Generation', 'Pool')), 'recovery receipt types differ')


def successor(original, coordinates, out):
    scope = load('renew-p2-runtime-scope-nov13')
    value = scope.replace_scope(original, coordinates)
    rows = coordinates['Instances']
    need([(r['ID'], r['Generation']) for r in rows] == [(1,4),(2,0),(3,9),(4,1),(5,1),(6,1),(7,4),(8,4)],
         'instance generations changed after confirmed recovery')
    recovered = rows[2]
    need(recovered['UserID'] == 1 and recovered['Mode'] == 'lite' and recovered['Type'] == 'hermes' and
         recovered['Backend'] == 'gateway' and recovered['Status'] == 'running', 'recovered runtime identity differs')
    core = value['Deployment']
    core['profile_file'] = str(out / 'execution-profile.json')
    core['capture_modules']['path'] = str(out / 'capture-materials.json')
    return value


def verify_app(A, site):
    app = site.get('deployment', 'clawmanager-app')
    need(app['metadata']['uid'] == APP_UID and not app['metadata'].get('deletionTimestamp') and
         app['status'].get('observedGeneration') == app['metadata']['generation'] and
         app['status'].get('updatedReplicas') == app['status'].get('readyReplicas') == app['spec']['replicas'] == 2,
         'recovered application rollout changed')
    containers = app['spec']['template']['spec']['containers']
    need(len(containers) == 1 and containers[0]['name'] == 'clawmanager-app' and containers[0]['image'] == IMAGE,
         'observed recovery image required')
    selector = ','.join(k + '=' + v for k, v in app['spec']['selector']['matchLabels'].items())
    pods = A.decode(site.call(['get', 'pods', '-l', selector, '-o', 'json']))['items']
    pods = [p for p in pods if not p['metadata'].get('deletionTimestamp')]
    need(len(pods) == 2, 'two settled application Pods required')
    for pod in pods:
        statuses = pod['status'].get('containerStatuses', [])
        need(len(statuses) == 1 and statuses[0].get('ready') and
             statuses[0]['imageID'].endswith('@' + IMAGE.split('@')[1]), 'recovery image is not loaded')
        digest = site.call(['exec', pod['metadata']['name'], '-c', 'clawmanager-app', '--',
                            'sha256sum', '/usr/local/bin/clawreef-server']).decode().split()[0]
        need(digest == ELF_SHA, 'running recovery program changed')
    return app


def once(A, dns, directory, label, argv):
    receipt, marker = directory / (label + '.receipt.private.json'), directory / (label + '.sent.private.json')
    if receipt.exists():
        need(A.decode(marker.read_bytes())['Argv'] == argv and
             A.decode((directory / (label + '.exit.json')).read_bytes()) == {'ExitCode': 0}, 'retained native invocation differs')
        return A.decode(receipt.read_bytes())
    need(not marker.exists(), 'native operation already attempted; retain partial outputs')
    A.retain(marker, {'Argv': argv})
    with (directory / (label + '.stdout.private')).open('xb') as stdout, (directory / (label + '.stderr.private')).open('xb') as stderr:
        result = dns.run(argv, stdout=stdout, stderr=stderr, timeout=180)
    A.retain(directory / (label + '.exit.json'), {'ExitCode': result.returncode})
    raw = (directory / (label + '.stdout.private')).read_bytes()
    if result.returncode:
        report = {'Label': label, 'ExitCode': result.returncode}
        try:
            value = A.decode(raw)
            for key in ('state', 'phase', 'Status', 'Phase', 'Step', 'Kind', 'Reason'):
                v = value.get(key)
                if isinstance(v, str) and len(v) < 100 and all(c.isalnum() or c == '_' for c in v): report[key] = v
        except (ValueError, AttributeError):
            pass
        print('P2_RECOVERED_SOURCE_NATIVE_REFUSAL', json.dumps(report), flush=True)
        raise ValueError('native ' + label + ' refused; original and partial outputs retained')
    value = A.decode(raw); A.retain(receipt, raw)
    return value


def prepare(A, L, parent, parent_receipt, selected, core):
    H, D = load('prepare-p2-longhorn-provider-loaded'), load('p2-source-dns')
    recovery = A.decode((ROOT / 'runtime-pool-recovery-312eaa9e/completed.json').read_bytes())
    validate_recovery(recovery)
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        need(not selected.get(key) or not Path(selected[key]).exists(), 'parent source facts already exist; reconcile before refresh')
    original = A.obj(parent['Definition'])
    until = dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00'))
    need(dt.datetime.now(dt.timezone.utc) < until - dt.timedelta(minutes=10), 'source window insufficient; renew before continuing')
    need(original['Until'] == selected['Until'] and original['Controller'] == selected['Controller'], 'parent source window/controller differs')
    oldout = Path(parent_receipt['SourceSelection']['File']).parent
    need(original['Deployment']['profile_file'] == str(oldout / 'execution-profile.json') and
         original['Deployment']['capture_modules']['path'] == str(oldout / 'capture-materials.json'), 'parent native output paths differ')
    prior = ROOT / 'longhorn-source-20261113-provider-loaded-tenant-workspace-repair'
    failure = A.decode((prior / 'native.stdout.private').read_bytes())
    args = A.decode((prior / 'native.sent.private.json').read_bytes())['Argv']
    failed_out = H.confirmed_native_failure(A.decode((prior / 'native.exit.json').read_bytes()), failure, args)
    need(failure.get('Step') == 'native_instance_binding' and failure.get('Kind') == 'RuntimeBinding' and
         failure.get('InstanceID') == 3 and failure.get('Reason') == 'validation' and
         not (prior / 'completed.json').exists() and failed_out == oldout.parent / prior.name and
         failed_out.resolve(strict=True) == failed_out and not list(failed_out.iterdir()), 'confirmed instance 3 refusal without outputs required')
    native = {'File': args[0], 'SHA256': NATIVE_SHA}; A.read(native, 128 << 20)
    journal = ROOT / 'source-preparation-20261113-runtime-recovered'
    journal.mkdir(mode=0o700, exist_ok=True)
    need(journal.resolve() == journal and journal.stat().st_mode & 0o077 == 0, 'private recovery journal required')
    A.retain(journal / 'parent.json', {'Receipt': parent['Receipt'], 'Definition': parent['Definition'], 'Recovery': recovery})
    site = L.Site(journal, A)
    app = verify_app(A, site)
    desired = A.obj(A.decode((H.PARENT / 'delivery-plan.private.json').read_bytes())['DesiredSpec'])
    pod = H.current_controller(site, A, L, selected, desired)
    endpoints = [(c['Purpose'], c['Endpoint']) for c in selected['Connections']
                 if (urlsplit(c['Endpoint']).hostname or '').endswith('.' + A.NS + '.svc')]
    dns = D.SourceDNS(site, journal, pod, endpoints, A.retain); dns.probe()
    old = A.decode((H.PARENT / 'source-author/native.sent.private.json').read_bytes())['Argv']
    need(old[:2] == [str(L.BIN), 'author-initial-source-inputs'] and
         old[old.index('--definition-sha256') + 1] == parent['Definition']['SHA256'], 'original native invocation required')
    common = old[2:old.index('--definition-file')]
    binary_dir = Path('/root/sbk/p2-native-execution-eca964d4')
    build = A.decode((binary_dir / 'BUILD_RECEIPT.json').read_bytes())
    binary = binary_dir / 'system-backup-first-install-materials'
    need(build['SourceRevision'] == 'eca964d42b96c31cb381531889a39c23a366ffab', 'reviewed coordinate author required')
    A.read({'File': str(binary), 'SHA256': build['Binaries'][binary.name]['SHA256']}, 128 << 20)
    coordinate_out = journal / 'coordinates'; coordinate_out.mkdir(mode=0o700, exist_ok=True)
    print('P2_RECOVERED_SOURCE_STEP coordinates', flush=True)
    coordinates = once(A, dns, journal, 'coordinates', [str(binary), 'author-initial-source-coordinates', *common,
        '--running-only-runtime-test', '1,2,3,7,8:4,5,6', '--output-directory', str(coordinate_out)])
    need(coordinates['Version'] == 'original-initial-source-data-authored.v1' and coordinates['InstanceCount'] == 8 and
         coordinates['WriterQualified'] is False and coordinates['BackupReady'] is False, 'unsigned native coordinate receipt required')
    data = A.obj(coordinates['Coordinates']); snapshot = A.obj(coordinates['KubernetesSnapshot'])
    apps = [d for d in snapshot['Deployments'] if d['metadata']['uid'] == APP_UID]
    need(len(apps) == 1 and apps[0]['spec'] == app['spec'], 'native snapshot did not include recovered application spec')
    out = oldout.parent / 'initial-source-20261113-runtime-recovered'
    definition = successor(original, data, out)
    pin = A.retain(journal / 'definition.private.json', definition)
    if not (journal / 'author.sent.private.json').exists():
        need(not out.exists(), 'new native source output directory required'); out.mkdir(mode=0o700)
    A.read({'File': str(L.BIN), 'SHA256': L.BIN_SHA}, 128 << 20)
    print('P2_RECOVERED_SOURCE_STEP source_reauthor', flush=True)
    result = once(A, dns, journal, 'author', [str(L.BIN), 'author-initial-source-inputs', *common,
        '--definition-file', pin['File'], '--definition-sha256', pin['SHA256'], '--output-directory', str(out)])
    need(result['Version'] == 'original-initial-source-inputs-authored.v1' and result['GrantsIssued'] is False and
         result['BackupReady'] is False, 'unsigned native source receipt required')
    for key in ('Deployment', 'MaterialsTemplate', 'ExecutionProfile', 'SourceSelection'): A.read(result[key])
    actual = A.obj(result['SourceSelection']); actual_core = A.obj(result['Deployment'])
    need(actual['Controller'] == selected['Controller'] and actual['Connections'] == selected['Connections'] and
         actual['Until'] == selected['Until'] and actual_core == definition['Deployment'], 'native successor changed source selection or deployment')
    need(verify_app(A, site)['spec'] == app['spec'], 'application changed during source authoring')
    done = {'Version': 'p2-runtime-recovered-source-reauthored.v1',
            'Receipt': A.retain(journal / 'receipt.private.json', (journal / 'author.receipt.private.json').read_bytes()),
            'Definition': pin, 'Coordinates': coordinates['Coordinates'], 'SourceSelection': result['SourceSelection'],
            'Controller': selected['Controller'], 'SourceAPI': parent['SourceAPI'], 'VaultWriterSelection': parent['VaultWriterSelection'],
            'Until': selected['Until'], 'Image': IMAGE, 'InstanceID': 3, 'Generation': 9,
            'TokenReissued': False, 'GrantsIssued': False, 'BackupReady': False}
    A.retain(journal / 'completed.json', done)
    print('P2_RUNTIME_RECOVERED_SOURCE_REAUTHORED_NO_HOLD', json.dumps(done), flush=True)
    return done, journal / 'author.sent.private.json', native


if __name__ == '__main__':
    try:
        os.umask(0o077)
        load('prepare-p2-longhorn-provider-loaded').main(recovered=True)
    except Exception as error:
        raise SystemExit('P2_RECOVERED_SOURCE_UNCONFIRMED ' + (str(error) if type(error) is ValueError else type(error).__name__))
