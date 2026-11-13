#!/usr/bin/env python3
"""Reauthor unsigned source role DATA; retain originals and issue no capture grant."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
PARENT = ROOT / 'source-preparation-20261113-runtime-scope-final-retry'
PARENT_SHA = '11dfe569db6defd550bcc124e3659e15823d922f618e6f5ec2b2e9ab051601c8'
WRITER_SHA = '1e7560fbcba32bdd812aea39c19c743f3338cba71eb432cb28e4aa099edf3163'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def reconcile(definition, selected, controller):
    value = copy.deepcopy(definition)
    core = value['Deployment']
    ns, name, uid = controller['Namespace'], controller['Deployment'], controller['DeploymentUID']
    need(core['namespace'] == ns and core['controller_owner'] == uid, 'controller identity changed')
    discovery = value['Materials']['Discovery']
    need(discovery['ControllerDeployment'] == name and discovery['ControllerDeploymentUID'] == uid,
         'controller discovery differs')
    need(not core.get('database_workload') and not core.get('provider_dependencies') and
         len(selected.get('PreAdoptionVaultDependencies', [])) == 1 and not selected.get('VaultProviderDependencies'),
         'original pre-adoption stage required')
    roles = selected['Deployments']
    need(len({d['Name'] for d in roles}) == len(roles) == len({d['UID'] for d in roles}),
         'duplicate original workload')
    need([d for d in roles if d['Name'] == name] == [{'Name': name, 'UID': uid, 'Role': 'writer'}],
         'original controller role differs')
    expected = {(d['Name'], d['UID']) for d in roles if d['Role'] in ('writer', 'provider-dependency')}
    writers = core['platform_writers']
    need(len(writers) == len(expected) and all(w['namespace'] == ns for w in writers) and
         {(w['name'], w['uid']) for w in writers} == expected, 'complete original writer roster differs')
    agents = core['runtime_sources']['deployments']
    expected_agents = {(d['Name'], d['UID']) for d in roles if d['Role'] == 'agent'}
    need(len(agents) == len(expected_agents) and all(w['namespace'] == ns for w in agents) and
         {(w['name'], w['uid']) for w in agents} == expected_agents, 'runtime agent roster differs')
    databases = [d for d in roles if d['Role'] == 'database']
    need(len(databases) == 1 and all(d['Role'] in ('writer', 'provider-dependency', 'agent', 'database') for d in roles),
         'one original database role required')
    provider = selected['PreAdoptionVaultDependencies'][0]['Workload']
    need([(d['Name'], d['UID']) for d in roles if d['Role'] == 'provider-dependency'] ==
         [(provider['Deployment'], provider['DeploymentUID'])], 'original Vault workload differs')
    core['platform_writers'] = [w for w in writers if (w['name'], w['uid']) != (name, uid)]
    core['database_workload'] = {'namespace': ns, 'name': databases[0]['Name'], 'uid': databases[0]['UID']}
    return value


def main():
    os.umask(0o077)
    need(os.name == 'posix', 'Linux operator required')
    package = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('assembly', package / 'assemble-p2-installation-candidate.py')
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    done = A.decode((PARENT / 'completed.json').read_bytes())
    need(done['Receipt']['SHA256'] == PARENT_SHA and done['VaultWriterSelection']['SHA256'] == WRITER_SHA,
         'observed source and original role pins required')
    receipt = A.obj(done['Receipt'])
    selected = A.obj(receipt['SourceSelection'])
    need(receipt['GrantsIssued'] is False and receipt['BackupReady'] is False, 'unissued source required')
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts already exist')
    original = A.obj(done['Definition'])
    definition = reconcile(original, A.obj(done['VaultWriterSelection']), selected['Controller'])
    until = dt.datetime.fromisoformat(definition['Until'].replace('Z', '+00:00'))
    need(dt.datetime.now(dt.timezone.utc) < until - dt.timedelta(minutes=10), 'source window insufficient; renew before reauthoring')
    build = A.decode((package / 'BUILD_RECEIPT.json').read_bytes())
    need(build['RoleRepair'] == 'controller-database-provider.v1' and
         build['SourceRevision'] == (package / 'SOURCE_REVISION').read_text().strip(), 'role repair build required')
    binary = package / 'system-backup-first-install-materials'
    A.read({'File': str(binary), 'SHA256': build['Binaries'][binary.name]['SHA256']}, 128 << 20)
    journal = ROOT / 'source-preparation-20261113-role-repair'
    journal.mkdir(mode=0o700, exist_ok=True)
    need(journal.resolve() == journal and journal.stat().st_mode & 0o077 == 0 and
         not (journal / 'author.sent.private.json').exists(), 'private unsent successor required; retain prior outputs')
    old_out = Path(receipt['SourceSelection']['File']).parent
    out = old_out.parent / 'initial-source-20261113-role-repair'
    out.mkdir(mode=0o700, exist_ok=True)
    need(out.resolve() == out and out.stat().st_mode & 0o077 == 0 and not list(out.iterdir()), 'new empty private output required')
    core = definition['Deployment']
    need(core['profile_file'] == str(old_out / 'execution-profile.json') and
         core['capture_modules']['path'] == str(old_out / 'capture-materials.json'), 'parent output paths differ')
    core['profile_file'] = str(out / 'execution-profile.json')
    core['capture_modules']['path'] = str(out / 'capture-materials.json')
    pin = A.retain(journal / 'definition.private.json', definition)
    intent = A.decode((PARENT / 'author.sent.private.json').read_bytes())
    argv = list(intent['Argv'])
    need(argv[1] == 'author-initial-source-inputs', 'original source invocation required')
    need(argv[argv.index('--definition-file') + 1] == done['Definition']['File'] and
         argv[argv.index('--definition-sha256') + 1] == done['Definition']['SHA256'], 'original invocation definition differs')
    argv[0] = str(binary)
    for flag, value in [('--definition-file', pin['File']), ('--definition-sha256', pin['SHA256']), ('--output-directory', str(out))]:
        argv[argv.index(flag) + 1] = value
    A.retain(journal / 'author.sent.private.json', {'Argv': argv, 'Definition': pin, 'ParentReceipt': done['Receipt']})
    with (journal / 'author.stdout.private').open('xb') as stdout, (journal / 'author.stderr.private').open('xb') as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=180)
    A.retain(journal / 'author.exit.json', {'ExitCode': result.returncode})
    need(result.returncode == 0, 'native source author refused; retain successor journal and partial outputs')
    raw = (journal / 'author.stdout.private').read_bytes()
    authored = A.decode(raw)
    need(authored['Version'] == 'original-initial-source-inputs-authored.v1' and
         authored['GrantsIssued'] is False and authored['BackupReady'] is False, 'native unsigned source required')
    for key in ('Deployment', 'MaterialsTemplate', 'ExecutionProfile', 'SourceSelection'):
        A.read(authored[key])
    actual = A.obj(authored['Deployment'])
    need(actual['database_workload'] == core['database_workload'] and actual['platform_writers'] == core['platform_writers'],
         'native role readback differs')
    complete = {'Version': 'p2-source-roles-reauthored.v1', 'Receipt': A.retain(journal / 'receipt.private.json', raw),
                'Definition': pin, 'SourceSelection': authored['SourceSelection'], 'SourceAPI': done['SourceAPI'],
                'VaultWriterSelection': done['VaultWriterSelection'], 'Until': definition['Until'],
                'FormalVaultMaterialsRequired': True, 'TokenReissued': False, 'GrantsIssued': False, 'BackupReady': False}
    A.retain(journal / 'completed.json', complete)
    print('P2_SOURCE_ROLES_REAUTHORED_NO_HOLD', json.dumps(complete), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        raise SystemExit('P2_SOURCE_ROLE_REPAIR_UNCONFIRMED ' + (str(e) if type(e) is ValueError else type(e).__name__))
