#!/usr/bin/env python3
"""Issue native metadata-only Vault material once; produce, but do not apply, delivery manifests."""
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
PARENT = ROOT / 'source-preparation-20261113-role-repair'
PREFLIGHT = ROOT / 'formal-vault-preflight-x_b5ahp0'
RECEIPT_SHA = '4fa1247abe132d70ba37d3e241c18c93b0c302ab45826144653bd1fac4592ead'
SOURCE_SHA = '3050ddef86abc37bd95feb1c16795f4df05fb73571d3185065baa77d2502cb70'
WRITER_SHA = '1e7560fbcba32bdd812aea39c19c743f3338cba71eb432cb28e4aa099edf3163'
IMAGE = '10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780'
MOUNT = '/var/run/clawreef/system-backup/provider-dependency'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_successor(before, after, original, successor, workload, secret, patch, deployment, digest, original_observer):
    need({k: v for k, v in before.items() if k not in ('Deployment', 'MaterialsTemplate')} ==
         {k: v for k, v in after.items() if k not in ('Deployment', 'MaterialsTemplate')}, 'unrelated source selection changed')
    removed = [w for w in original['platform_writers'] if w['name'] == workload['Deployment']]
    need(removed == [{'namespace': original['namespace'], 'name': workload['Deployment'], 'uid': workload['DeploymentUID']}],
         'one exact original provider writer required')
    kept = [w for w in original['platform_writers'] if w != removed[0]]
    need(successor['platform_writers'] == kept and len(successor['provider_dependencies']) == 1 and
         {k: v for k, v in original.items() if k not in ('platform_writers', 'provider_dependencies')} ==
         {k: v for k, v in successor.items() if k not in ('platform_writers', 'provider_dependencies')},
         'database/controller/runtime or unrelated configuration changed')
    provider = successor['provider_dependencies'][0]
    observer_raw = base64.b64decode(secret['data']['observer.json'], validate=True)
    token = base64.b64decode(secret['data']['token'], validate=True)
    observer = json.loads(observer_raw)
    need(provider['schema_version'] == 'formal-vault-provider-dependency.v1' and provider['workload'] == workload and
         provider['observer'] == {'File': MOUNT + '/observer.json', 'SHA256': digest(observer_raw)} and
         secret['kind'] == 'Secret' and secret['immutable'] is True and secret['metadata']['namespace'] == original['namespace'] and
         observer['IdentityMode'] == 'metadata-only' and observer['TokenFile'] == MOUNT + '/token' and
         observer['TokenSHA256'] == digest(token), 'native metadata-only delivery binding differs')
    identity_fields = ('IdentityMode', 'ObserverPolicy', 'TokenFile', 'TokenSHA256')
    need({k: v for k, v in observer.items() if k not in identity_fields} ==
         {k: v for k, v in original_observer.items() if k not in identity_fields},
         'original Vault endpoint, trust or cluster metadata changed')
    containers = deployment['spec']['template']['spec']['containers']
    positions = [i for i, c in enumerate(containers) if c['name'] == 'controller']
    need(len(positions) == 1, 'one actual controller container required')
    position = '/spec/template/spec/containers/' + str(positions[0])
    need(patch[:2] == [{'op': 'test', 'path': '/metadata/uid', 'value': deployment['metadata']['uid']},
                      {'op': 'test', 'path': '/metadata/resourceVersion', 'value': deployment['metadata']['resourceVersion']}],
         'guarded original controller patch required')
    allowed = {'/spec/template/spec/volumes', '/spec/template/spec/volumes/-', '/spec/template/spec/initContainers',
               '/spec/template/spec/initContainers/-', position + '/volumeMounts', position + '/volumeMounts/-'}
    need(all(op['op'] == 'add' and op['path'] in allowed or op ==
             {'op': 'test', 'path': position + '/name', 'value': 'controller'} for op in patch[2:]),
         'patch changes unrelated controller fields')


def main():
    os.umask(0o077)
    need(os.name == 'posix', 'Linux operator required')
    A, P, D, F = [load(n) for n in ('assemble-p2-installation-candidate', 'inspect-p2-formal-vault',
                                   'p2-source-dns', 'p2-vault-local-forward')]
    package = Path(__file__).resolve().parent
    build = A.decode((package / 'BUILD_RECEIPT.json').read_bytes())
    need(build['FormalVaultForward'] == 'installer-transport-only.v1' and
         build['SourceRevision'] == (package / 'SOURCE_REVISION').read_text().strip(), 'reviewed formal forward build required')
    binary = package / 'system-backup-source-registries'
    A.read({'File': str(binary), 'SHA256': build['Binaries'][binary.name]['SHA256']}, 128 << 20)
    receipt = A.obj({'File': str(PARENT / 'receipt.private.json'), 'SHA256': RECEIPT_SHA})
    done = A.decode((PARENT / 'completed.json').read_bytes())
    need(receipt['SourceSelection']['SHA256'] == SOURCE_SHA and done['VaultWriterSelection']['SHA256'] == WRITER_SHA and
         done['Definition']['SHA256'] == P.DEFINITION_SHA and receipt['GrantsIssued'] is False and receipt['BackupReady'] is False,
         'observed unsigned source successor required')
    definition, selected = A.obj(done['Definition']), A.obj(receipt['SourceSelection'])
    until = dt.datetime.fromisoformat(definition['Until'].replace('Z', '+00:00'))
    need(dt.datetime.now(dt.timezone.utc) < until - dt.timedelta(minutes=10), 'source window insufficient; renew before issuance')
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts already issued')
    writer, original = A.obj(done['VaultWriterSelection']), A.obj(receipt['Deployment'])
    need(not original.get('provider_dependencies') and len(writer['PreAdoptionVaultDependencies']) == 1,
         'original pre-adoption stage required')
    dependency = writer['PreAdoptionVaultDependencies'][0]
    observer = A.obj(dependency['InstalledObserver'])
    preflight = A.decode((PREFLIGHT / 'completed.json').read_bytes())
    need(preflight['SourceSelection'] == receipt['SourceSelection'] and preflight['IAMMutated'] is False and
         preflight['WorkloadPatched'] is False, 'completed read-only preflight required')
    journal = ROOT / 'formal-vault-materials-20261113'
    # Never replay a mint after a timeout, error, partial file or lost receipt.
    need(not journal.exists(), 'formal issuance already attempted; reconcile retained journal, do not resend')
    journal.mkdir(mode=0o700)
    need(journal.resolve() == journal, 'private canonical journal required')
    print('P2_FORMAL_VAULT_RECORDS', journal, flush=True)

    class Site(P.Site):
        def run(self, argv):
            dns_read = argv == ['-n', 'kube-system', 'get', 'service', 'kube-dns', '-o', 'json'] or (
                len(argv) == 7 and argv[0] == 'exec' and argv[2:] == ['-c', 'installation-owner', '--', 'cat', '/etc/resolv.conf'])
            if not dns_read:
                return super().run(argv)
            self.sequence += 1
            result = subprocess.run(['kubectl', '--kubeconfig', P.KUBE, '--request-timeout=20s', '-n', P.NS, *argv],
                                    capture_output=True, timeout=40)
            self.save(self.directory / ('dns-api-%03d.stdout.private' % self.sequence), result.stdout or b'\n')
            self.save(self.directory / ('dns-api-%03d.stderr.private' % self.sequence), result.stderr or b'\n')
            return result

    site = Site(journal, A.retain)
    ref = selected['Controller']
    deployment = site.get('deployment', ref['Deployment'])
    projection = P.controller_projection(deployment, ref)
    need(projection == preflight['Controller'] and projection['Generation'] == 4 and projection['Ready'] == projection['Replicas'] == 1 and
         all(c['Image'] == IMAGE and c['ExplicitIdentityEligible'] and not c['ProviderMountConflict'] for c in projection['Containers']) and
         not projection['ProviderVolumePresent'] and not projection['ProviderInitPresent'], 'observed controller layout changed')
    A.retain(journal / 'controller.before.private.json', deployment)
    pod = site.get('pod', ref['Pod'])
    need(pod['metadata']['uid'] == ref['PodUID'] and not pod['metadata'].get('deletionTimestamp'), 'pinned controller Pod changed')
    old = A.decode((PARENT / 'author.sent.private.json').read_bytes())['Argv']
    need(old[1] == 'author-initial-source-inputs', 'original installer invocation required')
    common = old[2:old.index('--definition-file')]
    out = Path(receipt['SourceSelection']['File']).parent.parent / 'initial-provider-20261113-formal'
    need(not out.exists(), 'new empty formal output required')
    out.mkdir(mode=0o700)
    need(out.resolve() == out, 'canonical native output required')
    endpoints = [(c['Purpose'], c['Endpoint']) for c in selected['Connections'] if c['Purpose'] in ('source_objects', 'source_redis')]
    dns = D.SourceDNS(site, journal, pod, endpoints, A.retain)
    dns.probe()
    forward = F.LocalForward(site, {'--provider-service': dependency['Workload']['Service'], '--provider-endpoint': observer['Endpoint']}, journal, A.retain)
    with forward as address:
        argv = [str(binary), 'prepare-provider-materials', *common,
                '--source-selection-file', receipt['SourceSelection']['File'], '--source-selection-sha256', SOURCE_SHA,
                '--writer-selection-file', done['VaultWriterSelection']['File'], '--writer-selection-sha256', WRITER_SHA,
                '--controller-container', 'controller', '--output-directory', str(out), '--provider-local-forward', address]
        A.retain(journal / 'native.sent.private.json', {'Argv': argv, 'SourceRevision': build['SourceRevision'],
                  'ParentReceipt': {'File': str(PARENT / 'receipt.private.json'), 'SHA256': RECEIPT_SHA}})
        started = time.monotonic()
        with (journal / 'native.stdout.private').open('xb') as stdout, (journal / 'native.stderr.private').open('xb') as stderr:
            result = dns.run(argv, stdout=stdout, stderr=stderr, timeout=180)
        A.retain(journal / 'native.exit.json', {'ExitCode': result.returncode})
        A.retain(journal / 'native.timing.json', {'ElapsedSeconds': round(time.monotonic() - started, 3)})
        forward.check()
    if result.returncode:
        failure = {'ExitCode': result.returncode, 'IAMOutcomeUnconfirmed': True}
        try:
            native = A.decode((journal / 'native.stdout.private').read_bytes())
            if native.get('Status') == 'formal_vault_materials_refused' and re.fullmatch('[a-z_]{1,80}', native.get('Phase', '')):
                failure['Phase'] = native['Phase']
        except ValueError:
            pass
        print('P2_FORMAL_VAULT_NATIVE_REFUSAL', json.dumps(failure), flush=True)
        raise ValueError('native formal issuer refused; retain journal, token and partial outputs; do not resend')
    raw = (journal / 'native.stdout.private').read_bytes()
    native = A.decode(raw)
    need(native['Version'] == 'formal-vault-dependency-materials.v1' and native['Workload'] == dependency['Workload'],
         'native provider material receipt required')
    for key in ('Deployment', 'MaterialsTemplate', 'SourceSelection', 'SecretManifest', 'DeploymentPatch'):
        A.read(native[key])
    successor, config, template = A.obj(native['SourceSelection']), A.obj(native['Deployment']), A.obj(native['MaterialsTemplate'])
    need(successor['Deployment'] == native['Deployment'] and successor['MaterialsTemplate'] == native['MaterialsTemplate'] and
         template['DeploymentConfigSHA256'] == native['Deployment']['SHA256'], 'native successor pin chain differs')
    validate_successor(selected, successor, original, config, native['Workload'], A.obj(native['SecretManifest']),
                       A.obj(native['DeploymentPatch']), deployment, A.sha, observer)
    need(site.get('deployment', ref['Deployment']) == deployment, 'controller changed during native issuance; retain output')
    complete = {'Version': 'p2-formal-vault-materials-issued.v1', 'Receipt': A.retain(journal / 'receipt.private.json', raw),
                'SourceSelection': native['SourceSelection'], 'SecretManifest': native['SecretManifest'],
                'DeploymentPatch': native['DeploymentPatch'], 'Until': definition['Until'],
                'MetadataIdentityIssued': True, 'IAMMutated': True, 'SecretCreated': False,
                'ControllerPatched': False, 'GrantsIssued': False, 'BackupReady': False}
    A.retain(journal / 'completed.json', complete)
    print('P2_FORMAL_VAULT_MATERIALS_ISSUED_NOT_LOADED', json.dumps(complete), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        raise SystemExit('P2_FORMAL_VAULT_MATERIALS_UNCONFIRMED ' + (str(e) if type(e) is ValueError else type(e).__name__))
