#!/usr/bin/env python3
"""Read-only, task-specific field snapshot with a separate redacted export.

Full API responses remain in a remote mode-0700 directory. Only the redacted
export is packaged for local offline work. No Secret values, environment
credentials, kubeconfig, DSN, private key or JWT enters the export.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.request

WORK = Path('/root/sbk-validation-tls-inspect.7LVU7vpE')
NS = 'clawmanager-sbk-validation-system'
SAFE_ENV = {'SYSTEM_BACKUP_SQL_GATE_SCOPE', 'SYSTEM_BACKUP_ENABLED', 'SYSTEM_BACKUP_EXECUTION_PROTOCOL',
            'CLAWMANAGER_RUNTIME_TYPE', 'CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME', 'CLAWMANAGER_RUNTIME_IMAGE_REF',
            'CLAWMANAGER_HERMES_DESKTOP_WEB_ENABLED', 'CLAWMANAGER_HERMES_BACKEND_MODE', 'RUNTIME_WORKSPACE_ROOT',
            'RUNTIME_AGENT_LISTEN_ADDR', 'RUNTIME_AGENT_PUBLIC_PORT', 'RUNTIME_GATEWAY_PORT_START',
            'RUNTIME_GATEWAY_PORT_END', 'RUNTIME_GATEWAY_PORT_BLOCK_SIZE', 'HERMES_TUI_DIR'}


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hidden(value):
    # Do not export hashes of individual potentially low-entropy credentials.
    return {'redacted': True, 'bytes': len(encode(value))}


def redact(value, key=''):
    if isinstance(value, list):
        if key == 'env':
            return [{k: (v if k != 'value' or row.get('name') in SAFE_ENV else hidden(v))
                     for k, v in row.items()} for row in value]
        if key in ('command', 'args'):
            return {'argument_count': len(value), 'sha256': digest(encode(value)),
                    'executable': value[0] if key == 'command' and value and re.fullmatch(r'/[A-Za-z0-9_./-]+', value[0]) else None}
        return [redact(v) for v in value]
    if not isinstance(value, dict):
        return value
    if value.get('kind') in ('Secret', 'ConfigMap'):
        return {'apiVersion': value.get('apiVersion'), 'kind': value['kind'], 'metadata': redact(value['metadata']),
                'type': value.get('type'), 'immutable': value.get('immutable'),
                'data_keys': sorted(set(value.get('data', {})) | set(value.get('binaryData', {})) | set(value.get('stringData', {})))}
    result = {}
    for k, v in value.items():
        if k == 'managedFields':
            continue
        if k == 'annotations':
            result[k] = {'keys': sorted(v)}
        elif k in ('message', 'terminationMessage', 'token', 'password', 'client-key-data', 'client-certificate-data'):
            result[k] = hidden(v)
        else:
            result[k] = redact(v, k)
    return result


def main():
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix='p2-offline-inventory.', dir='/root/sbk'))
    private, export = root / 'private', root / 'export'
    private.mkdir(mode=0o700); export.mkdir(mode=0o700)
    print('OFFLINE_INVENTORY_RECORDS', root, flush=True)
    base = ['kubectl', '--kubeconfig', str(WORK / 'operator.kubeconfig.yaml'), '--request-timeout=20s']
    errors, pins = [], []
    env = dict(os.environ)
    for k in list(env):
        if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'kubeconfig'): del env[k]
    env['NO_PROXY'] = '*'

    def save(path, raw):
        with path.open('xb') as stream:
            os.chmod(path, 0o600); stream.write(raw)
        return {'File': str(path), 'SHA256': digest(raw), 'Bytes': len(raw)}

    def run(label, args, body=None, parse=True):
        try:
            p = subprocess.run(base + args, input=body, capture_output=True, timeout=45, env=env)
            save(private / (label + '.stderr.private'), p.stderr)
            pin = save(private / (label + '.json.private'), p.stdout)
            pins.append(dict(label=label, **pin))
            if p.returncode or len(p.stdout) > 64 << 20:
                errors.append(dict(stage=label, exit_code=p.returncode)); return None
            value = json.loads(p.stdout) if parse else p.stdout
            save(export / (label + '.json'), encode(redact(value)) if parse else encode(value.decode(errors='replace')))
            return value
        except (OSError, ValueError, subprocess.TimeoutExpired) as e:
            errors.append(dict(stage=label, exception=type(e).__name__)); return None

    run('namespaces', ['get', 'namespaces', '-o', 'json'])
    run('nodes', ['get', 'nodes', '-o', 'json'])
    run('storage', ['get', 'persistentvolumes,storageclasses', '-o', 'json'])
    run('snapshot-classes', ['get', 'volumesnapshotclasses.snapshot.storage.k8s.io,volumesnapshotcontents.snapshot.storage.k8s.io', '-o', 'json'])
    resources = 'deployments,replicasets,statefulsets,daemonsets,jobs,cronjobs,pods,services,endpoints,endpointslices,persistentvolumeclaims,serviceaccounts,configmaps,secrets,roles,rolebindings,networkpolicies,horizontalpodautoscalers,ingresses'
    snapshots = {}
    for namespace in (NS, 'clawmanager-sbk-validation-user-1', 'longhorn-system'):
        snapshots[namespace] = run('namespace-' + namespace, ['-n', namespace, 'get', resources, '-o', 'json'])
    run('longhorn', ['-n', 'longhorn-system', 'get', 'volumes.longhorn.io,engines.longhorn.io,replicas.longhorn.io,sharemanagers.longhorn.io,nodes.longhorn.io', '-o', 'json'])
    run('cluster-rbac', ['get', 'clusterroles,clusterrolebindings', '-o', 'json'])

    # Actual mount metadata, without workspace contents or process environment.
    for namespace in ('clawmanager-sbk-validation-user-1', 'longhorn-system'):
        for pod in (snapshots.get(namespace) or {}).get('items', []):
            if pod.get('kind') != 'Pod' or pod.get('status', {}).get('phase') != 'Running': continue
            if namespace == 'longhorn-system' and not pod['metadata']['name'].startswith('share-manager-'): continue
            for c in pod['spec']['containers']:
                label = 'mountinfo-' + pod['metadata']['name'] + '-' + c['name']
                run(label, ['-n', namespace, 'exec', pod['metadata']['name'], '-c', c['name'], '--', 'cat', '/proc/self/mountinfo'], parse=False)
    app = snapshots.get(NS) or {}
    for pod in app.get('items', []):
        if pod.get('kind') != 'Pod' or not pod['metadata']['name'].startswith('clawmanager-app-') or pod.get('status', {}).get('phase') != 'Running': continue
        name = pod['metadata']['name']
        raw = subprocess.run(base + ['-n', NS, 'exec', name, '-c', pod['spec']['containers'][0]['name'], '--', '/usr/local/bin/clawreef-server', '--system-backup-source-config-data'], capture_output=True, timeout=40, env=env)
        try:
            value = json.loads(raw.stdout.splitlines()[-1])
            assert raw.returncode == 0 and value['Version'] == 'original-application-config-coordinates.v1'
            save(export / ('app-config-' + name + '.json'), encode(value))
        except (ValueError, KeyError, IndexError, AssertionError): errors.append(dict(stage='app-config-' + name))

    # One read-only SQL transaction for schema metadata, counts and source rows.
    try:
        dsn = (WORK / 'fresh-sql-prepare.faa4osWr/sql-operation/mysql-installer.dsn').read_text().strip()
        credentials, sep, address = dsn.rpartition('@tcp(')
        user, colon, password = credentials.partition(':'); _, sep2, tail = address.partition(')/'); database = tail.split('?', 1)[0]
        assert sep and colon and sep2 and re.fullmatch(r'[A-Za-z0-9_]+', database) and not any(c in password for c in '\r\n\x00')
        shell = 'IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mysql --protocol=TCP -h127.0.0.1 -u "$1" --database="$2" --batch --skip-column-names --raw -e "$3"'
        def sql(query):
            p = subprocess.run(base + ['-n', NS, 'exec', '-i', 'deployment/mysql', '-c', 'mysql', '--', 'sh', '-c', shell,
                'sbk-inventory-readonly', user, database, 'SET SESSION TRANSACTION READ ONLY; START TRANSACTION; ' + query + '; COMMIT;'],
                input=(password + '\n').encode(), capture_output=True, timeout=55, env=env)
            if p.returncode: raise RuntimeError('read-only SQL refused')
            return [json.loads(row) for row in p.stdout.splitlines() if row.strip()]
        schema_data = sql("SELECT JSON_OBJECT('table',TABLE_NAME,'column',COLUMN_NAME,'type',COLUMN_TYPE,'nullable',IS_NULLABLE,'key',COLUMN_KEY,'extra',EXTRA) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION")
        save(export / 'sql-schema.json', encode(schema_data))
        tables = sorted({v['table'] for v in schema_data if v['table'].startswith('system_backup')})
        assert all(re.fullmatch(r'[A-Za-z0-9_]+', t) for t in tables)
        counts = sql(' UNION ALL '.join("SELECT JSON_OBJECT('table','"+t+"','count',COUNT(*)) FROM `"+t+'`' for t in tables)) if tables else []
        save(export / 'sql-control-counts.json', encode(counts))
        instances = sql("SELECT JSON_OBJECT('id',id,'user_id',user_id,'mode',instance_mode,'type',type,'runtime_type',runtime_type,'variant',COALESCE(runtime_variant,''),'os',os_type,'status',status,'generation',runtime_generation,'namespace',COALESCE(pod_namespace,''),'pod',COALESCE(pod_name,''),'workspace',COALESCE(workspace_path,''),'pvc',COALESCE(pvc_name,''),'mount_path',COALESCE(mount_path,'')) FROM instances ORDER BY id")
        save(export / 'sql-source-instances.json', encode(instances))
        save(export / 'sql-participants.json', encode(sql("SELECT JSON_OBJECT('scope',scope,'id',participant_id,'state',state) FROM system_backup_participants ORDER BY scope,participant_id")))
    except Exception as e: errors.append(dict(stage='sql', exception=type(e).__name__))

    # Paths and schema only for existing private materials; never export bytes.
    inventory = []
    for selected_root in (WORK, Path('/root/sbk')):
        for current, dirs, files in os.walk(selected_root, followlinks=False):
            relative = Path(current).relative_to(selected_root)
            dirs[:] = [] if len(relative.parts) >= 5 else [d for d in dirs if not (Path(current)/d).is_symlink() and Path(current)/d != root]
            for name in files:
                p = Path(current)/name
                if p.is_symlink() or p.suffix not in ('.json', '.dsn', '.pem') or not p.is_file(): continue
                st = p.stat()
                row = dict(File=str(p), Bytes=st.st_size, Mode=oct(st.st_mode & 0o777))
                if p.suffix == '.json' and 0 < st.st_size <= 262144:
                    try:
                        value = json.loads(p.read_bytes())
                        if isinstance(value, dict): row['Fields'] = sorted(value)
                    except (ValueError, UnicodeError): pass
                inventory.append(row)
    save(export / 'material-inventory.json', encode(inventory))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open('http://10.130.14.23:5000/v2/_catalog?n=1000', timeout=10) as response:
            value = json.loads(response.read(1 << 20))
        save(export / 'registry-repositories.json', encode(value))
        for repository in value.get('repositories', []):
            if 'vault' not in repository.lower(): continue
            assert re.fullmatch(r'[A-Za-z0-9_./-]+', repository)
            with opener.open('http://10.130.14.23:5000/v2/' + repository + '/tags/list', timeout=10) as response:
                value = json.loads(response.read(1 << 20))
            save(export / ('registry-' + repository.replace('/', '_') + '-tags.json'), encode(value))
    except Exception as e: errors.append(dict(stage='registry', exception=type(e).__name__))
    save(export / 'capture-index.json', encode(dict(version='p2-redacted-offline-inventory.v1',
        captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), remote_private_inputs=pins, errors=errors,
        configuration_mutated=False, backup_ready=False)))
    archive = root / 'p2-offline-inventory.redacted.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for p in sorted(export.iterdir()): tar.add(p, arcname=p.name, recursive=False)
    os.chmod(archive, 0o600)
    sha = digest(archive.read_bytes())
    (root / 'SHA256SUMS').write_text(sha + '  ' + archive.name + '\n')
    print('OFFLINE_INVENTORY_PACKAGE', archive, flush=True)
    print('OFFLINE_INVENTORY_SHA256', sha, flush=True)
    print('OFFLINE_INVENTORY_ERRORS', json.dumps(errors), flush=True)
    # A fixed pointer is only a local download locator, never source authority.
    pointer = Path('/root/sbk/p2-offline-inventory.latest-path')
    if pointer.is_symlink(): raise RuntimeError('download pointer must not be a symlink')
    with pointer.open('w') as stream:
        os.chmod(pointer, 0o600); stream.write(str(root) + '\n')


if __name__ == '__main__':
    main()
