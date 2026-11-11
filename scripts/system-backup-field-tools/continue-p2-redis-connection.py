#!/usr/bin/env python3
"""This task only: original Redis TLS/reader lifecycle and retained source DATA."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit


def need(ok, text):
    if not ok:
        raise RuntimeError(text)


def load(directory, name, sha):
    file = directory / name
    need(not file.is_symlink() and hashlib.sha256(file.read_bytes()).hexdigest() == sha, 'reviewed field helper changed')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def redis_service(services, url, namespace):
    endpoint = urlsplit(url)
    need(endpoint.scheme == 'redis' and endpoint.hostname and not endpoint.query and not endpoint.fragment,
         'actual existing plain Redis source required before original native TLS lifecycle')
    db = endpoint.path.strip('/') or '0'
    need(db.isdigit() and 0 <= int(db) <= 65535, 'actual Redis database required')
    selected = []
    for service in services:
        name = service['metadata']['name']
        names = {name, name + '.' + namespace, name + '.' + namespace + '.svc',
            name + '.' + namespace + '.svc.cluster.local', service['spec'].get('clusterIP')}
        if endpoint.hostname in names and any(p['port'] == (endpoint.port or 6379) for p in service['spec']['ports']):
            selected.append(service)
    need(len(selected) == 1 and selected[0]['spec'].get('selector'), 'one actual original Redis Service required')
    return selected[0], int(db)


def main(directory, records):
    os.umask(0o077)
    need(os.name == 'posix' and directory.is_absolute() and directory.resolve(strict=True) == directory
         and records.is_absolute() and records.resolve() == records and not records.is_symlink(), 'Linux absolute input/output directories required')
    c = load(directory, 'continue-p2-minio-connection.py', '13da446e37fd45fd1344a04fe433e6e2306740cc5ede4fffa29745393d1a1b25')
    owner = load(directory, 'retry-p2-writer-selection.py', 'be22ac5d9f5c21c5900a51ee6f17345f282145edb2cdd19c7a2bcc3f15b720b6')
    sums = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        sha, name = line.split()
        need(name not in sums and '/' not in name and '\\' not in name, 'delivery manifest changed')
        sums[name] = sha
    native = directory / 'system-backup-original-maintenance'
    helper = {'File': str(native), 'SHA256': c.digest(native.read_bytes())}
    need(helper['SHA256'] == sums[native.name], 'native original maintenance executable changed')
    writer = {'File': '/root/sbk/p2-writer-selection-retry.hmq_j5mb/selection/original-writer-selection.json',
        'SHA256': '9d114d1ba974fa7997e695b385038dd43d8d7fdb30af6a61fd1477bed44f6c03'}
    selected = json.loads(c.private(Path(writer['File']), writer['SHA256']))
    need(len(selected.get('TenantPro', [])) == 1 and selected['TenantPro'][0]['Source']['ID'] == 2
         and not selected.get('RedisReadKeepers'), 'same complete pre-Redis writer selection required')
    c.private(c.ROOT / 'connection-continuation/minio-source-fragment.json',
        'c3b4eae48b3d78c12872742be55e6bc95f11bc9e594c83b8697728edc020ede8')
    if not records.exists():
        records.mkdir(mode=0o700)
    need(records.stat().st_mode & 0o077 == 0, 'private Redis records directory required')
    print('P2_REDIS_CONNECTION_RECORDS', records, flush=True)
    m = c.module(directory, 'system-backup-minio-first-hop-tls.py')
    a = c.module(directory, 'system-backup-minio-app-tls-cutover.py')
    a.m = m
    source = m.Source(c.source_arguments())
    dep, actors = a.app_source(source, 'clawmanager-app')
    urls = [a.app_exec(source, actor, '/bin/sh', '-ceu',
        'printf "%s" "${PLATFORM_REDIS_URL:-${TEAM_REDIS_URL-}}"') for actor in actors]
    need(urls and urls[0] and all(value == urls[0] for value in urls), 'loaded App Redis source differs across replicas')
    services = json.loads(source.kube('get', 'services', '-o', 'json'))['items']
    service, db = redis_service(services, urls[0].decode(), c.NS)
    selector = ','.join(k + '=' + v for k, v in sorted(service['spec']['selector'].items()))
    pods = json.loads(source.kube('get', 'pods', '-l', selector, '-o', 'json'))['items']
    need(len(pods) == 1 and not pods[0]['metadata'].get('deletionTimestamp'), 'one stable actual Redis Pod required')
    rs_ref = m.controller(pods[0], 'ReplicaSet')
    rs = source.get('replicaset', rs_ref['name'])
    dep_ref = m.controller(rs, 'Deployment')
    redis = source.get('deployment', dep_ref['name'])
    need(rs['metadata']['uid'] == rs_ref['uid'] and redis['metadata']['uid'] == dep_ref['uid']
         and any(row['Name'] == redis['metadata']['name'] and row['UID'] == redis['metadata']['uid']
             and row['Role'] == 'writer' for row in selected['Deployments']), 'actual Redis writer UID graph changed')
    descriptor = {'Version': 'original-redis-source-coordinate.v1', 'NamespaceUID': source.plan['Target']['NamespaceUID'],
        'Service': service['metadata']['name'], 'ServiceUID': service['metadata']['uid'],
        'Deployment': redis['metadata']['name'], 'DeploymentUID': redis['metadata']['uid'],
        'Database': db, 'BusinessPrefixes': ['claw:team:']}
    descriptor_pin = c.retain(records / 'redis-source.description.json', c.encode(descriptor))
    policy = {'Policy': {'Source': {'ID': 'redis-' + service['metadata']['uid'], 'Version': 'validation-p2-original.v1',
        'SHA256': descriptor_pin['SHA256']}, 'Topology': 'shared_keyspace', 'CaptureMode': 'scan_dump',
        'TTLPolicy': 'preserve_absolute', 'Purpose': 'functional_test', 'DB': db, 'Prefixes': ['claw:team:'],
        'MaxItems': 10000, 'MaxBytes': 32 << 20, 'MaxClockSkew': 5000}, 'ServerID': '', 'ExcludePrefixes': ['cm:restore-history:']}
    policy_pin = c.retain(records / 'redis-source.policy.json', c.encode(policy))
    output = records / 'native'
    if not output.exists():
        output.mkdir(mode=0o700)
    base = {'Version': 'original-redis-native-material-options.v1', 'Deployment': redis['metadata']['name'],
        'Service': service['metadata']['name'], 'OutputDirectory': str(output), 'Policy': policy_pin, 'Helper': helper}
    binding = {'writer': writer, 'options': base, 'loaded_redis_url_sha256': c.digest(urls[0])}
    binding_file = records / 'binding.json'
    safe_startup_refusal = False
    if binding_file.exists():
        old_raw = c.private(binding_file)
        old = json.loads(old_raw)
        previous = old['options']['Helper']
        original_shape = redis['spec']['template']['spec']['containers'][0]
        successor_file = records / 'binding-successor.json'
        if old != binding and successor_file.exists():
            successor_binding = json.loads(c.private(successor_file))
            need(successor_binding == {'ParentSHA256': c.digest(old_raw), 'Binding': binding,
                'Reason': 'fixed_old_command_guard_refused_before_original_redis_helper'}, 'retained binding successor changed')
        elif old != binding:
            old_options = json.loads(c.private(records / '0-prepare.options.json'))
            # The old fixed executable checked Command==[redis-server] BEFORE
            # originalRedisHelper or any native prepare. This exact observed
            # default-entry startup therefore could not have dispatched one.
            comparable = json.loads(c.encode(binding))
            comparable['options']['Helper'] = previous
            need(old == comparable and previous['SHA256'] == 'f78d0443a33c7debc9dea2e8d0921ba1de6da2f6cc9d9a25412a34e61b10865b'
                 and c.digest(c.private(Path(previous['File']), maximum=128 << 20)) == previous['SHA256']
                 and not list(output.iterdir()) and not (records / 'prepare.receipt.json').exists()
                 and c.private(records / '0-prepare.stdout.private') == b'\n'
                 and c.private(records / '0-prepare.stderr.private') == b'\n'
                 and old_options == dict(old['options'], Mode='prepare', Intent={'File': '', 'SHA256': ''})
                 and redis['metadata']['uid'] == 'dd724dc4-ad59-4a78-b5bb-50aba907e036'
                 and not original_shape.get('command') and original_shape.get('args') == ['redis-server', '--appendonly', 'yes']
                 and original_shape['image'] == 'docker.io/library/redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf',
                 'prior native preparation is not the known pre-inspection startup refusal; preserve and query')
            c.retain(records / 'binding-successor.json', c.encode({'ParentSHA256': c.digest(old_raw), 'Binding': binding,
                'Reason': 'fixed_old_command_guard_refused_before_original_redis_helper'}))
            safe_startup_refusal = True
            print('P2_REDIS_KNOWN_PRE_INSPECTION_REFUSAL_RESUMED', flush=True)
    else:
        c.retain(binding_file, c.encode(binding))

    def call(mode, prepared=None, optional=False):
        sequence = len(list(records.glob('*.options.json')))
        label = str(sequence) + '-' + mode
        options = dict(base, Mode=mode, Intent=prepared['Intent'] if prepared else {'File': '', 'SHA256': ''})
        pin = c.retain(records / (label + '.options.json'), c.encode(options))
        argv = [str(native), '--mode', 'redis-materials', *owner.owner_arguments(),
            '--selection-file', writer['File'], '--selection-sha256', writer['SHA256'],
            '--redis-materials-file', pin['File'], '--redis-materials-sha256', pin['SHA256']]
        c.retain(records / (label + '.send-unknown.json'), c.encode({'argv': argv}))
        result = subprocess.run(argv, capture_output=True, timeout=145)
        c.retain(records / (label + '.stdout.private'), result.stdout or b'\n')
        c.retain(records / (label + '.stderr.private'), result.stderr or b'\n')
        if result.returncode != 0 and result.stdout:
            try:
                failure = json.loads(result.stdout)
                if failure.get('Version') == 'original-redis-native-material-failure.v1':
                    print('P2_REDIS_REFUSAL_PHASE', failure.get('Mode'), failure.get('Phase'), flush=True)
            except (ValueError, AttributeError):
                pass
        if optional and result.returncode == 1:
            return None
        need(result.returncode == 0, 'original Redis owner refused at ' + label + '; retain private logs')
        receipt = json.loads(result.stdout)
        need(receipt['Version'] == 'original-redis-native-materials.v1', 'unexpected original Redis receipt')
        print('P2_REDIS_STAGE', mode, receipt['State'], flush=True)
        return receipt

    prepared_file = records / 'prepare.receipt.json'
    if prepared_file.exists():
        prepared = json.loads(c.private(prepared_file))
    else:
        need((not list(records.glob('*-prepare.send-unknown.json')) or safe_startup_refusal) and not list(output.iterdir()),
             'partial original Redis preparation retained; do not prepare again')
        prepared = call('prepare')
        need(prepared['State'] == 'native_prepared_loopback_isolated_requires_apply', 'native Redis preparation unconfirmed')
        c.retain(prepared_file, c.encode(prepared))
    c.private(Path(prepared['Intent']['File']), prepared['Intent']['SHA256'])
    if not list(records.glob('*-apply.send-unknown.json')):
        # A failed or lost apply response is followed only by the original query.
        call('apply', prepared, optional=True)
    observed = None
    for _ in range(40):
        observed = call('query', prepared, optional=True)
        if observed and observed['State'] == 'desired_specs_ready_requires_native_finalize':
            break
        time.sleep(2)
    need(observed and observed['State'] == 'desired_specs_ready_requires_native_finalize',
         'original Redis rollout unconfirmed; query same records, never reapply')
    mode = 'query-finalize' if list(records.glob('*-finalize.send-unknown.json')) else 'finalize'
    final = call(mode, prepared)
    need(final['State'] == 'native_tls_and_accounts_read_back_not_a_hold', 'native Redis finalize unconfirmed')
    successor = json.loads(c.private(Path(final['WriterSelection']['File']), final['WriterSelection']['SHA256']))
    keeper = json.loads(c.private(Path(final['KeeperSelection']['File']), final['KeeperSelection']['SHA256']))
    actual_policy = json.loads(c.private(Path(final['Policy']['File']), final['Policy']['SHA256']))
    need(successor.get('TenantPro') == selected.get('TenantPro') and successor['RuntimeTestScope'] == selected['RuntimeTestScope']
         and successor['RedisReadKeepers'] == [keeper] and keeper['Native']['Policy'] == actual_policy,
         'complete source roster or actual Redis keeper binding changed')
    credential = json.loads(c.private(Path(keeper['ReaderCredential']['File']), keeper['ReaderCredential']['SHA256']))
    c.private(Path(keeper['CA']['File']), keeper['CA']['SHA256'])
    address = keeper['ServerName'] + ':' + str(keeper['Port'])
    fragment = {'Version': 'validation-p2-redis-source-data.v1', 'Connection': {'Purpose': 'source_redis',
        'Endpoint': 'rediss://' + address, 'Account': credential['username'], 'ServerUUID': '', 'Database': '',
        'CA': keeper['CA'], 'Credential': keeper['ReaderCredential'], 'IdentitySHA256': '', 'ScopeSHA256': ''},
        'WriterSelection': final['WriterSelection'], 'KeeperSelection': final['KeeperSelection'], 'Policy': final['Policy'],
        'NativeReceipt': final, 'NativeSourceQualified': False, 'BackupReady': False}
    pin = c.retain(records / 'redis-source-fragment.json', c.encode(fragment))
    print('P2_REDIS_SOURCE_CONNECTION_READY', json.dumps({'fragment': pin, 'writer_selection': final['WriterSelection'],
        'tls_port': keeper['Port'], 'backup_ready': False}), flush=True)


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--tool-directory', type=Path, required=True)
        parser.add_argument('--records-directory', type=Path, required=True)
        args = parser.parse_args()
        main(args.tool_directory, args.records_directory)
    except Exception as error:
        raise SystemExit('P2_REDIS_CONNECTION_UNCONFIRMED ' + (str(error) if type(error) is RuntimeError else type(error).__name__))
