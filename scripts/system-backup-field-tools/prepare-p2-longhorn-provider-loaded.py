#!/usr/bin/env python3
"""Continue native mount authoring from the observed formal-provider source."""
import datetime as dt
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
PARENT = ROOT / 'formal-vault-load-20261113'
RECEIPT_SHA = 'f8e02ac2f9ea6f8102a270c527245c4e3056cbfa67d2ce8214dc25366018ba8c'
DEFINITION_SHA = 'd9d65c0fe227bb6c316b42d3f501b6d2910f81d8a34de187dd1ee8db201809aa'
SELECTION_SHA = 'e868971899c29149296d3a11b5d5fb2063cf7c4994800b770bafa2b434dcf79e'
BIN = Path('/root/sbk/p2-formal-vault-dda78123/system-backup-source-registries')
BIN_SHA = '263aa44897f50984412351bc1ac130f3fef0afdd77231f07c2f0d230e1820f79'
POD_UID = '8bd02772-a4dc-4d85-80e0-d45b2adbe7a7'
RS_UID = 'cf31dcd6-3868-464c-840e-269eabfb1e0e'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_parent(done, receipt, selected, core):
    need(done['Version'] == 'p2-formal-vault-loaded-source-reauthored.v1' and done['SecretLoaded'] is True and
         done['MetadataTokenReissued'] is False and done['GrantsIssued'] is False and done['BackupReady'] is False,
         'observed loaded unsigned source required')
    need(done['Receipt']['SHA256'] == RECEIPT_SHA and done['Definition']['SHA256'] == DEFINITION_SHA and
         done['SourceSelection']['SHA256'] == SELECTION_SHA and receipt['SourceSelection'] == done['SourceSelection'] and
         receipt['Version'] == 'original-initial-source-inputs-authored.v1' and receipt['GrantsIssued'] is False and
         receipt['BackupReady'] is False and selected['Deployment'] == receipt['Deployment'] and
         selected['MaterialsTemplate'] == receipt['MaterialsTemplate'] and selected['Controller'] == done['Controller'],
         'observed native source pin chain differs')
    ref = selected['Controller']
    need(ref['PodUID'] == POD_UID and ref['ReplicaSetUID'] == RS_UID and
         ref['DeploymentUID'] == 'e4e27f27-8f02-40ab-8c62-09f2ffa3fafa', 'post-load controller identity differs')
    providers = core.get('provider_dependencies', [])
    need(len(providers) == 1 and providers[0]['schema_version'] == 'formal-vault-provider-dependency.v1' and
         providers[0]['workload']['DeploymentUID'] == '3d254222-e5e3-491e-9556-ab74d400e074' and
         core['database_workload'] == {'namespace': ref['Namespace'], 'name': 'mysql', 'uid': 'dcc73970-1bbe-4eb7-9ab6-5e9a4f4f19cd'} and
         not any(w['uid'] in (ref['DeploymentUID'], providers[0]['workload']['DeploymentUID'], core['database_workload']['uid'])
                 for w in core['platform_writers']), 'formal provider/database/controller roles differ')


def current_controller(site, A, L, selected, desired):
    ref = selected['Controller']
    deployment = site.get('deployment', ref['Deployment'])
    need(deployment['metadata']['uid'] == ref['DeploymentUID'] and not deployment['metadata'].get('deletionTimestamp') and
         deployment['spec'] == desired and deployment['status'].get('observedGeneration') == deployment['metadata']['generation'] and
         deployment['status'].get('readyReplicas') == deployment['status'].get('updatedReplicas') == 1, 'loaded controller changed')
    pod, rs = site.get('pod', ref['Pod']), site.get('replicaset', ref['ReplicaSet'])
    for obj, uid, kind, parent_uid in [(pod, ref['PodUID'], 'ReplicaSet', ref['ReplicaSetUID']),
                                      (rs, ref['ReplicaSetUID'], 'Deployment', ref['DeploymentUID'])]:
        need(obj['metadata']['uid'] == uid and not obj['metadata'].get('deletionTimestamp') and
             [(o['kind'], o['uid']) for o in obj['metadata'].get('ownerReferences', []) if o.get('controller')] == [(kind, parent_uid)],
             'loaded controller owner chain changed')
    L.validate_running_pod(desired, pod)
    need(pod['status']['phase'] == 'Running' and len(pod['status'].get('containerStatuses', [])) == 2 and
         all(c.get('ready') for c in pod['status']['containerStatuses']) and
         site.get('serviceaccount', ref['ServiceAccount'])['metadata']['uid'] == ref['ServiceAccountUID'],
         'loaded controller/account not ready')
    return pod


def validate_core_successor(core, successor, hold_pin):
    actual = copy.deepcopy(successor)
    need('longhorn_hold' not in core['runtime_sources'], 'parent already has Longhorn hold material')
    hold = actual['runtime_sources'].pop('longhorn_hold')
    observer = core['runtime_sources']['shared_runtime_observer']
    expected = {k: observer[k] for k in ('CAFile', 'CASHA256', 'CertificateFile', 'CertificateSHA256', 'KeyFile', 'KeySHA256', 'Endpoints')}
    expected.update(WholeNodeEndpoints=None, Nodes=None)
    need(actual == core and hold == {'Observer': expected, 'Materials': [hold_pin]},
         'native successor changed unrelated configuration or Longhorn material binding')


def confirmed_native_failure(exit_record, refusal, argv):
    need(exit_record == {'ExitCode': 1} and refusal.get('Status') == 'original_mount_author_refused' and
         refusal.get('Phase') == 'native_writers' and argv[1] == 'prepare-mount-materials' and
         argv[argv.index('--source-selection-sha256') + 1] == SELECTION_SHA,
         'observed native writer refusal required; reconcile other outcomes')
    return Path(argv[argv.index('--output-directory') + 1])


def main(native_readback=False):
    os.umask(0o077); need(os.name == 'posix', 'Linux operator required')
    A, L, H, D, F = [load(name) for name in ('assemble-p2-installation-candidate', 'load-p2-formal-vault',
                                           'prepare-p2-longhorn-source', 'p2-source-dns', 'p2-vault-local-forward')]
    done = A.decode((PARENT / 'completed.json').read_bytes())
    receipt, selected = A.obj(done['Receipt']), A.obj(done['SourceSelection'])
    core = A.obj(receipt['Deployment']); A.read(done['Definition'])
    validate_parent(done, receipt, selected, core)
    now = dt.datetime.now(dt.timezone.utc); until = dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00'))
    need(dt.datetime.fromisoformat(selected['NotBefore'].replace('Z', '+00:00')) <= now < until - dt.timedelta(minutes=10),
         'source window insufficient; preserve records and renew source')
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts already exist')
    native, native_sha = BIN, BIN_SHA
    journal = ROOT / 'longhorn-source-20261113-provider-loaded'
    if native_readback:
        need(not (journal / 'completed.json').exists(), 'prior mount author already completed')
        previous = A.decode((journal / 'native.sent.private.json').read_bytes())['Argv']
        prior_out = confirmed_native_failure(A.decode((journal / 'native.exit.json').read_bytes()),
                                            A.decode((journal / 'native.stdout.private').read_bytes()), previous)
        expected_out = Path(done['SourceSelection']['File']).parent.parent / journal.name
        need(prior_out == expected_out and prior_out.resolve(strict=True) == prior_out and prior_out.is_dir() and
             not list(prior_out.iterdir()), 'partial mount outputs require reconciliation')
        package = Path(__file__).resolve().parent
        build = A.decode((package / 'BUILD_RECEIPT.json').read_bytes())
        need(build['Diagnostic'] == 'native-writer-step.v1' and
             build['SourceRevision'] == (package / 'SOURCE_REVISION').read_text().strip(), 'native writer diagnostic build required')
        native, native_sha = package / 'system-backup-source-registries', build['NativeSHA256']
        journal = ROOT / (journal.name + '-native-readback')
    A.read({'File': str(native), 'SHA256': native_sha}, 128 << 20)
    journal.mkdir(mode=0o700, exist_ok=True)
    need(journal.resolve() == journal and journal.stat().st_mode & 0o077 == 0, 'private journal required')
    print('P2_LONGHORN_PROVIDER_LOADED_RECORDS', journal, flush=True)
    if (journal / 'completed.json').exists():
        completed = A.decode((journal / 'completed.json').read_bytes()); A.read(completed['Receipt'])
        print('P2_LONGHORN_SOURCE_MATERIALS_ALREADY_AUTHORED_NO_HOLD', json.dumps(completed), flush=True); return
    need(not (journal / 'native.sent.private.json').exists(), 'native mount author already sent; retain partial outputs')
    site = L.Site(journal, A)
    desired = A.obj(A.decode((PARENT / 'delivery-plan.private.json').read_bytes())['DesiredSpec'])
    pod = current_controller(site, A, L, selected, desired)
    formal = A.obj({'File': str(L.PARENT / 'receipt.private.json'), 'SHA256': L.RECEIPT_SHA})
    secret = A.obj(formal['SecretManifest']); L.verify_secret(site.get('secret', secret['metadata']['name']), secret)
    import base64
    observer_raw, token = [base64.b64decode(secret['data'][k], validate=True) for k in ('observer.json', 'token')]
    observer = A.decode(observer_raw)
    need(core['provider_dependencies'][0]['observer'] == {'File': L.MOUNT + '/observer.json', 'SHA256': A.sha(observer_raw)},
         'formal provider observer binding differs')
    for name, raw in [('observer.json', observer_raw), ('token', token)]:
        lines = site.call(['exec', pod['metadata']['name'], '-c', 'controller', '--', 'sh', '-ec',
                          'test -f "$1"; test ! -L "$1"; stat -c "%a %u" "$1"; sha256sum "$1"', 'readback', L.MOUNT + '/' + name]).decode('ascii').splitlines()
        need(len(lines) == 2 and lines[0].split() == ['600', '65532'] and lines[1].split() == [A.sha(raw), L.MOUNT + '/' + name],
             'loaded provider file changed')
    L.verify_metadata(A, F, site, journal, observer, token, formal['Workload'], until)
    # Mount authoring does not call the full source-registry Vault observer.
    # Its native workload graph still authenticates the formal provider role.
    snapshot = site.get('volumesnapshotclass', 'sbk-validation-longhorn-local')
    clone = site.get('storageclass', 'longhorn')
    layouts = A.retain(journal / 'mount-layouts.json', H.storage_selection(snapshot, clone))
    endpoints = [(c['Purpose'], c['Endpoint']) for c in selected['Connections']
                 if (urlsplit(c['Endpoint']).hostname or '').endswith('.' + A.NS + '.svc')]
    dns = D.SourceDNS(site, journal, pod, endpoints, A.retain); dns.probe()
    out = Path(done['SourceSelection']['File']).parent.parent / journal.name
    need(not out.exists(), 'new native output directory required'); out.mkdir(mode=0o700)
    old = A.decode((PARENT / 'source-author/native.sent.private.json').read_bytes())['Argv']
    need(old[1] == 'author-initial-source-inputs' and old[old.index('--definition-sha256') + 1] == DEFINITION_SHA,
         'observed source author invocation required')
    argv = [str(native), 'prepare-mount-materials', *old[2:old.index('--definition-file')],
            '--source-selection-file', done['SourceSelection']['File'], '--source-selection-sha256', SELECTION_SHA,
            '--mount-layouts-file', layouts['File'], '--mount-layouts-sha256', layouts['SHA256'], '--output-directory', str(out)]
    A.retain(journal / 'native.sent.private.json', {'Argv': argv, 'SourceSelection': done['SourceSelection'], 'Layouts': layouts})
    with (journal / 'native.stdout.private').open('xb') as stdout, (journal / 'native.stderr.private').open('xb') as stderr:
        result = dns.run(argv, stdout=stdout, stderr=stderr, timeout=180)
    A.retain(journal / 'native.exit.json', {'ExitCode': result.returncode})
    raw = (journal / 'native.stdout.private').read_bytes()
    if result.returncode:
        try:
            refusal = A.decode(raw)
            if refusal.get('Status') in ('original_mount_author_refused', 'original_mount_materials_blocked'):
                print('P2_LONGHORN_NATIVE_REFUSAL', json.dumps({k: refusal.get(k) for k in ('Phase', 'Step', 'Kind', 'Reason', 'Code', 'InstanceID', 'MountID')}), flush=True)
        except ValueError:
            pass
        raise ValueError('native mount author refused; retain journal and partial outputs')
    value = A.decode(raw)
    need(value['SelectionSHA256'] == SELECTION_SHA and value['LayoutSelectionSHA256'] == layouts['SHA256'], 'native input pins differ')
    for key in ('Deployment', 'MaterialsTemplate', 'SourceSelection', 'LonghornHoldMaterials'): A.read(value[key])
    H.validate_successor(selected, A.obj(value['SourceSelection']), value, A.obj(value['MaterialsTemplate']))
    successor = A.obj(value['Deployment'])
    validate_core_successor(core, successor, value['LonghornHoldMaterials'])
    current_controller(site, A, L, selected, desired)
    completed = {'Version': 'p2-longhorn-source-materials-authored.v1', 'Receipt': A.retain(journal / 'native.receipt.private.json', raw),
                 'ParentSelection': done['SourceSelection'], **{k: value[k] for k in ('Deployment', 'MaterialsTemplate', 'SourceSelection', 'LonghornHoldMaterials')},
                 'VaultWriterSelection': done['VaultWriterSelection'], 'Until': selected['Until'],
                 'NativeHoldClaim': False, 'GrantsIssued': False, 'BackupReady': False}
    A.retain(journal / 'completed.json', completed)
    print('P2_LONGHORN_SOURCE_MATERIALS_AUTHORED_NO_HOLD', json.dumps(completed), flush=True)


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--native-writer-readback', action='store_true')
        main(parser.parse_args().native_writer_readback)
    except Exception as error:
        raise SystemExit('P2_LONGHORN_PROVIDER_LOADED_UNCONFIRMED ' + (str(error) if type(error) is ValueError else type(error).__name__))
