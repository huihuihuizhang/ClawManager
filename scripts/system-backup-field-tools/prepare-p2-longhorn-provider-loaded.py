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


def confirmed_native_failure(exit_record, refusal, argv, pool_history=False, service_account=False, shared_protocol=False, tenant_workspace=False):
    need(exit_record == {'ExitCode': 1} and refusal.get('Status') == 'original_mount_author_refused' and
         refusal.get('Phase') == 'native_writers' and argv[1] == 'prepare-mount-materials' and
         argv[argv.index('--source-selection-sha256') + 1] == SELECTION_SHA,
         'observed native writer refusal required; reconcile other outcomes')
    if pool_history:
        need(refusal.get('Step') == 'native_runtime_pool_state' and refusal.get('Kind') == 'RuntimePod' and
             refusal.get('Reason') == 'validation', 'observed runtime pool state refusal required')
    if service_account:
        need(refusal.get('Step') == 'native_instance_deployment' and refusal.get('Kind') == 'Deployment' and
             refusal.get('Reason') == 'validation' and refusal.get('InstanceID') == 1,
             'observed instance 1 deployment refusal required')
    if shared_protocol:
        need(refusal.get('Step') == 'native_agent_capabilities' and refusal.get('Kind') == 'RuntimeAgent' and
             refusal.get('Reason') == 'read_error' and refusal.get('InstanceID') == 1,
             'observed instance 1 isolated capability refusal required')
    if tenant_workspace:
        need(refusal.get('Step') == 'native_tenant_pro' and refusal.get('Kind') == 'Instance' and
             refusal.get('Reason') == 'read_error' and refusal.get('InstanceID') == 2,
             'observed instance 2 tenant mount refusal required')
    return Path(argv[argv.index('--output-directory') + 1])


def confirmed_mount_window_failure(exit_record, refusal, argv, selection_sha):
    need(exit_record == {'ExitCode': 1} and refusal.get('Status') == 'original_mount_author_refused' and
         refusal.get('Phase') == 'mount_scope' and not refusal.get('Code') and not refusal.get('Step') and
         argv[1] == 'prepare-mount-materials' and argv[argv.index('--source-selection-sha256') + 1] == selection_sha,
         'observed recovered mount-scope refusal required')
    return Path(argv[argv.index('--output-directory') + 1])


def main(native_readback=False, pool_history=False, service_account=False, shared_protocol=False, tenant_workspace=False, recovered=False, recovered_window=False, tenant_team=False):
    os.umask(0o077); need(os.name == 'posix', 'Linux operator required')
    need(sum((native_readback, pool_history, service_account, shared_protocol, tenant_workspace, recovered, recovered_window, tenant_team)) <= 1, 'select one successor mode')
    A, L, H, D, F = [load(name) for name in ('assemble-p2-installation-candidate', 'load-p2-formal-vault',
                                           'prepare-p2-longhorn-source', 'p2-source-dns', 'p2-vault-local-forward')]
    done = A.decode((PARENT / 'completed.json').read_bytes())
    receipt, selected = A.obj(done['Receipt']), A.obj(done['SourceSelection'])
    core = A.obj(receipt['Deployment']); A.read(done['Definition'])
    validate_parent(done, receipt, selected, core)
    source_author = PARENT / 'source-author/native.sent.private.json'
    definition_sha, selection_sha = DEFINITION_SHA, SELECTION_SHA
    recovery_native = None
    if recovered or recovered_window:
        refresh = load('resume-p2-recovered-source')
        done, source_author, recovery_native = refresh.prepare(A, L, done, receipt, selected, core)
        receipt, selected = A.obj(done['Receipt']), A.obj(done['SourceSelection'])
        core = A.obj(receipt['Deployment'])
        definition_sha, selection_sha = done['Definition']['SHA256'], done['SourceSelection']['SHA256']
    if tenant_team:
        package = Path(__file__).resolve().parent
        build = A.decode((package / 'BUILD_RECEIPT.json').read_bytes())
        need(build['Diagnostic'] == 'tenant-team-source-namespace.v1' and
             build['SourceRevision'] == (package / 'SOURCE_REVISION').read_text().strip(), 'reviewed tenant team build required')
        A.read({'File': str(package / 'system-backup-source-registries'), 'SHA256': build['NativeSHA256']}, 128 << 20)
        done, source_author = load('resume-p2-tenant-team-source').prepare(A, L)
        receipt, selected = A.obj(done['Receipt']), A.obj(done['SourceSelection'])
        core = A.obj(receipt['Deployment'])
        definition_sha, selection_sha = done['Definition']['SHA256'], done['SourceSelection']['SHA256']
    if shared_protocol or tenant_workspace:
        need(core['runtime_sources'].get('shared_runtime_protocol') == 'shared-container-freeze.v1' and
             core['runtime_sources'].get('shared_runtime_observer'), 'original shared protocol and observer required')
    now = dt.datetime.now(dt.timezone.utc); until = dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00'))
    need(dt.datetime.fromisoformat(selected['NotBefore'].replace('Z', '+00:00')) <= now < until - dt.timedelta(minutes=10),
         'source window insufficient; preserve records and renew source')
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts already exist')
    native, native_sha = BIN, BIN_SHA
    journal = ROOT / 'longhorn-source-20261113-provider-loaded'
    if recovered or recovered_window:
        native, native_sha = Path(recovery_native['File']), recovery_native['SHA256']
        journal = ROOT / 'longhorn-source-20261113-runtime-recovered'
    if recovered_window:
        need(selection_sha == '99e192900ec2428c38554cfdc5348329d108b7dc8ff0a8935b240f34e3a24b1e' and
             done['Receipt']['SHA256'] == 'a57883aa0ff3403cdd529120b9f7ec7146f755fc3cc6cb183a449e051a38749d',
             'observed recovered source receipt required')
        previous = A.decode((journal / 'native.sent.private.json').read_bytes())['Argv']
        prior_out = confirmed_mount_window_failure(A.decode((journal / 'native.exit.json').read_bytes()),
            A.decode((journal / 'native.stdout.private').read_bytes()), previous, selection_sha)
        need(not (journal / 'completed.json').exists() and prior_out == Path(done['SourceSelection']['File']).parent.parent / journal.name and
             prior_out.resolve(strict=True) == prior_out and not list(prior_out.iterdir()), 'partial mount outputs require reconciliation')
        package = Path(__file__).resolve().parent
        build = A.decode((package / 'BUILD_RECEIPT.json').read_bytes())
        need(build['Diagnostic'] == 'source-author-full-census-window.v1' and
             build['SourceRevision'] == (package / 'SOURCE_REVISION').read_text().strip(), 'reviewed census-window build required')
        native, native_sha = package / 'system-backup-source-registries', build['NativeSHA256']
        journal = ROOT / 'longhorn-source-20261113-runtime-recovered-census-window'
    if native_readback or pool_history or service_account or shared_protocol or tenant_workspace:
        if tenant_workspace:
            journal = ROOT / (journal.name + '-shared-protocol-repair')
        elif shared_protocol:
            journal = ROOT / (journal.name + '-service-account-repair')
        elif service_account:
            journal = ROOT / (journal.name + '-pool-history-repair')
        elif pool_history:
            journal = ROOT / (journal.name + '-native-readback')
        need(not (journal / 'completed.json').exists(), 'prior mount author already completed')
        previous = A.decode((journal / 'native.sent.private.json').read_bytes())['Argv']
        prior_out = confirmed_native_failure(A.decode((journal / 'native.exit.json').read_bytes()),
                                            A.decode((journal / 'native.stdout.private').read_bytes()), previous, pool_history, service_account, shared_protocol, tenant_workspace)
        expected_out = Path(done['SourceSelection']['File']).parent.parent / journal.name
        need(prior_out == expected_out and prior_out.resolve(strict=True) == prior_out and prior_out.is_dir() and
             not list(prior_out.iterdir()), 'partial mount outputs require reconciliation')
        package = Path(__file__).resolve().parent
        build = A.decode((package / 'BUILD_RECEIPT.json').read_bytes())
        expected_build = 'tenant-desktop-pvc-workspace.v1' if tenant_workspace else 'runtime-shared-protocol.v1' if shared_protocol else 'runtime-service-account-default.v1' if service_account else ('runtime-pool-history.v1' if pool_history else 'native-writer-step.v1')
        need(build['Diagnostic'] == expected_build and
             build['SourceRevision'] == (package / 'SOURCE_REVISION').read_text().strip(), 'native writer diagnostic build required')
        native, native_sha = package / 'system-backup-source-registries', build['NativeSHA256']
        suffix = 'tenant-workspace-repair' if tenant_workspace else 'shared-protocol-repair' if shared_protocol else 'service-account-repair' if service_account else ('pool-history-repair' if pool_history else 'native-readback')
        journal = ROOT / ('longhorn-source-20261113-provider-loaded-' + suffix)
    if tenant_team:
        package = Path(__file__).resolve().parent
        build = A.decode((package / 'BUILD_RECEIPT.json').read_bytes())
        need(build['Diagnostic'] == 'tenant-team-source-namespace.v1' and
             build['SourceRevision'] == (package / 'SOURCE_REVISION').read_text().strip(), 'reviewed tenant team build required')
        native, native_sha = package / 'system-backup-source-registries', build['NativeSHA256']
        journal = ROOT / 'longhorn-source-20261113-tenant-team-namespace'
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
    old = A.decode(source_author.read_bytes())['Argv']
    need(old[1] == 'author-initial-source-inputs' and old[old.index('--definition-sha256') + 1] == definition_sha,
         'observed source author invocation required')
    argv = [str(native), 'prepare-mount-materials', *old[2:old.index('--definition-file')],
            '--source-selection-file', done['SourceSelection']['File'], '--source-selection-sha256', selection_sha,
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
    need(value['SelectionSHA256'] == selection_sha and value['LayoutSelectionSHA256'] == layouts['SHA256'], 'native input pins differ')
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
        modes = parser.add_mutually_exclusive_group()
        modes.add_argument('--native-writer-readback', action='store_true')
        modes.add_argument('--runtime-pool-history-repair', action='store_true')
        modes.add_argument('--runtime-service-account-repair', action='store_true')
        modes.add_argument('--runtime-shared-protocol-repair', action='store_true')
        modes.add_argument('--tenant-workspace-repair', action='store_true')
        args = parser.parse_args()
        main(args.native_writer_readback, args.runtime_pool_history_repair, args.runtime_service_account_repair, args.runtime_shared_protocol_repair, args.tenant_workspace_repair)
    except Exception as error:
        raise SystemExit('P2_LONGHORN_PROVIDER_LOADED_UNCONFIRMED ' + (str(error) if type(error) is ValueError else type(error).__name__))
