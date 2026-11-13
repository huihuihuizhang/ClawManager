#!/usr/bin/env python3
"""Read the actual app/SQL prerequisites together; never enable or issue anything."""
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'
NS = 'clawmanager-sbk-validation-system'
NS_UID = '0d1aebbb-fdd6-4b14-b9c5-0da456f8e65f'
APP_UID = '8ebd4d4c-57b6-4a82-b310-fae596681a4e'
SOURCE = {
    'File': '/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-20261113-provider-loaded/source-selection.json',
    'SHA256': 'e868971899c29149296d3a11b5d5fb2063cf7c4994800b770bafa2b434dcf79e',
}
TABLES = ('system_backup_v2_installation_state', 'system_backup_v2_configs',
          'system_backup_v2_execution_readiness')
QUERIES = {
    'installations': "SELECT JSON_OBJECT('Installation',origin_installation_id,'ActiveConfigVersion',active_config_version,'LastEffectiveEnabled',last_effective_enabled) FROM system_backup_v2_installation_state ORDER BY origin_installation_id LIMIT 101",
    'active_configs': "SELECT JSON_OBJECT('Installation',c.origin_installation_id,'Version',c.version,'Enabled',c.enabled,'RBACVersion',c.rbac_bindings_registry_version,'RBACSHA256',c.rbac_bindings_registry_sha256) FROM system_backup_v2_configs c JOIN system_backup_v2_installation_state s ON s.origin_installation_id=c.origin_installation_id AND s.active_config_version=c.version ORDER BY c.origin_installation_id LIMIT 101",
    'execution': "SELECT JSON_OBJECT('Installation',origin_installation_id,'TaskType',task_type,'ConfigVersion',config_version,'Ready',ready,'Fresh',expires_at>UTC_TIMESTAMP(6)) FROM system_backup_v2_execution_readiness ORDER BY origin_installation_id,task_type LIMIT 101",
}
MYSQL_SHELL = '''set -eu
IFS= read -r MYSQL_PWD
export MYSQL_PWD
IFS= read -r ca
umask 077
f=$(mktemp /tmp/sbk-app-wiring-ca.XXXXXX)
trap 'rm -f -- "$f"' EXIT HUP INT TERM
printf '%s' "$ca" | base64 -d > "$f"
mysql --protocol=TCP --connect-timeout=8 --ssl-mode=VERIFY_IDENTITY --tls-version=TLSv1.3 --ssl-ca="$f" -h "$1" -P "$2" -u "$3" --database="$4" --batch --skip-column-names --raw -e "$5"
'''


def emit(label, value):
    print(label, json.dumps(value, ensure_ascii=True), flush=True)


def installer_credentials(operation, connection):
    """Use the existing finite installer role, never the participant observer."""
    peer = urlsplit(connection['Endpoint'])
    if (operation['Address'] != peer.netloc or operation['Database'] != connection['Database']
            or operation['ServerUUID'] != connection['ServerUUID']):
        raise ValueError('original SQL producer identity changed')
    observers = [a for a in operation['Accounts'] if a['Role'] == 'control_sql']
    installers = [a for a in operation['Accounts'] if a['Role'] == 'installer']
    if (len(observers) != 1 or len(installers) != 1
            or observers[0]['User'] + '@' + observers[0]['Host'] != connection['Account']):
        raise ValueError('exact original participant and installer roles required')
    account = installers[0]
    readable = {p['Object'] for p in account['Privileges'] if p['Kind'] == 'table' and p['Verb'] == 'SELECT'}
    if (account['Locked'] or account['User'].lower() == 'root'
            or account['User'] == observers[0]['User'] or not set(TABLES) <= readable
            or not account['Password'] or any(v in account['Password'] for v in '\r\n\0')):
        raise ValueError('existing finite installer metadata-read privileges required')
    return account['User'], account['Password'], account['User'] + '@' + account['Host']


def main():
    if os.name != 'posix':
        raise ValueError('Linux operator required')
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location('app_wiring_assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    selected = A.obj(SOURCE)
    connections = [c for c in selected['Connections'] if c['Purpose'] == 'control_sql']
    A.need(len(connections) == 1, 'one pinned control SQL connection required')
    c = connections[0]
    ca = A.read(c['CA'])
    # The control_sql role intentionally sees only system_backup_participants.
    # Its information_schema visibility cannot establish that v2 tables are absent.
    A.read(c['Credential'])
    journal = ROOT / 'initial-source-author/configuration-data.result.json'
    result = A.obj({'File': str(journal), 'SHA256': hashlib.sha256(journal.read_bytes()).hexdigest()})
    inputs = A.obj(result['AssemblyInputs'])
    A.need(inputs['ControlDSN'] == c['Credential'], 'same original SQL producer connection required')
    operation = A.obj(inputs['SQLOperation'])
    user, password, expected_account = installer_credentials(operation, c)
    database = c['Database']
    peer = urlsplit(c['Endpoint'])
    records = Path(tempfile.mkdtemp(prefix='app-backup-wiring-', dir=ROOT))
    print('APP_BACKUP_WIRING_RECORDS', records, flush=True)
    now = dt.datetime.now(dt.timezone.utc)
    emit('APP_BACKUP_SOURCE_WINDOW', {'UTCNow': now.isoformat(), 'Until': selected['Until'],
         'RemainingSeconds': int((dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00')) - now).total_seconds())})
    kubectl = ['kubectl', '--kubeconfig', KUBE, '--request-timeout=20s']

    def get(kind, name, namespace=True):
        result = subprocess.run(kubectl + (['-n', NS] if namespace else []) + ['get', kind, name, '-o', 'json'], capture_output=True, timeout=30)
        A.need(result.returncode == 0, 'Kubernetes object read refused: ' + kind)
        obj = json.loads(result.stdout)
        A.need(not obj['metadata'].get('deletionTimestamp'), 'live Kubernetes object required')
        return obj

    ns = get('namespace', NS, False)
    A.need(ns['metadata']['uid'] == NS_UID, 'original namespace identity changed')
    app = get('deployment', 'clawmanager-app')
    A.need(app['metadata']['uid'] == APP_UID, 'original app identity changed')
    for container in app['spec']['template']['spec']['containers']:
        emit('APP_BACKUP_CONTAINER', {'Name': container['name'], 'Image': container['image'],
             'Mounts': container.get('volumeMounts', []),
             'BackupEnvironmentNames': sorted(e['name'] for e in container.get('env', []) if e['name'].startswith('SYSTEM_BACKUP_')),
             'EnvFromCount': len(container.get('envFrom', []))})
    emit('APP_BACKUP_VOLUME_SOURCES', [{'Name': v['name'],
         'Secret': v.get('secret', {}).get('secretName'), 'ConfigMap': v.get('configMap', {}).get('name'),
         'PVC': v.get('persistentVolumeClaim', {}).get('claimName')}
         for v in app['spec']['template']['spec'].get('volumes', [])])

    def query(label, statement):
        sql = 'SET SESSION TRANSACTION READ ONLY; START TRANSACTION; ' + statement + '; COMMIT;'
        args = kubectl + ['-n', NS, 'exec', '-i', 'deployment/mysql', '-c', 'mysql', '--',
                         'sh', '-c', MYSQL_SHELL, 'sbk-app-wiring-readonly', peer.hostname,
                         str(peer.port or 3306), user, database, sql]
        result = subprocess.run(args, input=password.encode() + b'\n' + base64.b64encode(ca) + b'\n', capture_output=True, timeout=45)
        A.retain(records / (label + '.stdout.private'), result.stdout or b'\n')
        A.retain(records / (label + '.stderr.private'), result.stderr or b'\n')
        if result.returncode:
            emit('APP_BACKUP_SQL_REFUSED', {'Query': label, 'ExitCode': result.returncode,
                 'MySQLErrorNumbers': re.findall(r'ERROR (\d+)', result.stderr.decode(errors='replace'), re.I)})
            return None
        A.need(len(result.stdout) <= 1 << 20, 'bounded SQL projection required')
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        A.need(len(rows) <= 100, 'bounded SQL row count required')
        return rows

    identity = query('identity', "SELECT JSON_OBJECT('Account',CURRENT_USER(),'Database',DATABASE(),'ServerUUID',@@server_uuid)")
    A.need(identity is not None and len(identity) == 1, 'control SQL identity unavailable')
    matches = {k: identity[0][k] == c[k] for k in ('Database', 'ServerUUID')}
    matches['Account'] = identity[0]['Account'] == expected_account
    emit('APP_BACKUP_SQL_IDENTITY', matches)
    A.need(all(matches.values()), 'control SQL identity changed')
    tables = query('tables', "SELECT JSON_OBJECT('Table',TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (" + ','.join("'" + t + "'" for t in TABLES) + ') ORDER BY TABLE_NAME')
    A.need(tables is not None, 'control schema inventory unavailable')
    present = {r['Table'] for r in tables}
    emit('APP_BACKUP_TABLE_VISIBILITY', {'Role': 'installer', 'Visible': {t: t in present for t in TABLES},
         'AbsenceNotInferred': True})
    results = {}
    for label, sql in QUERIES.items():
        # Always attempt the fixed SELECT. Error 1142 (permission) is distinct
        # from 1146 (table absent), even if information_schema omits the table.
        rows = query(label, sql)
        results[label] = rows
        if rows is not None:
            emit('APP_BACKUP_' + label.upper(), {'Count': len(rows), 'Rows': rows})
    after = get('deployment', 'clawmanager-app')
    A.need(after['metadata']['uid'] == APP_UID and after['spec'] == app['spec'], 'app changed during inventory; retain records')
    A.retain(records / 'completed.json', {'Version': 'p2-app-backup-wiring-readback.v2', 'Source': SOURCE,
             'SQL': results, 'Mutated': False, 'BackupSubmitted': False})
    print('APP_BACKUP_WIRING_READONLY_FINISHED', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit('APP_BACKUP_WIRING_UNCONFIRMED ' + (str(exc) if type(exc) is ValueError else type(exc).__name__))
