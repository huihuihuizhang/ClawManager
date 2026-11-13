#!/usr/bin/env python3
"""Read actual team SQL references and compare native volume pins; no mutation."""
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def main():
    os.umask(0o077)
    A, W = load('assemble-p2-installation-candidate'), load('inspect-p2-app-backup-wiring')
    A.need(os.name == 'posix', 'Linux operator required')
    selected = A.obj({'File': '/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-20261113-runtime-recovered/source-selection.json',
                      'SHA256': '99e192900ec2428c38554cfdc5348329d108b7dc8ff0a8935b240f34e3a24b1e'})
    core = A.obj(selected['Deployment'])
    A.need(dt.datetime.now(dt.timezone.utc) < dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00')), 'source window expired')
    coordinates = A.obj({'File': str(ROOT / 'source-preparation-20261113-runtime-recovered/coordinates/initial-source-coordinates.json'),
                         'SHA256': 'da53353b5dd4b15ecf90c09efbc182a3bbbc575400888ea101e59ce9026b3e92'})
    records = Path(tempfile.mkdtemp(prefix='longhorn-source-conditions-', dir=ROOT))
    print('LONGHORN_SOURCE_CONDITION_RECORDS', records, flush=True)
    claim = core['workspace']['claim']
    matches = [v for v in coordinates['Volumes'] if v['Namespace'] == core['namespace'] and v['ClaimName'] == claim]
    pins = core['worker_security']['volumes']
    print('LONGHORN_WORKSPACE_CONFIG', json.dumps({'Claim': claim, 'Namespace': core['namespace'],
        'CoordinateCount': len(matches), 'StagingClaim': core['staging_claim'], 'InstallationPresent': bool(core['installation_id'])}), flush=True)
    for v in matches:
        # Use the original native coordinate author's exact Go PV-spec hash.
        expected = {'Volume': 'workspace', 'Kind': 'PersistentVolumeClaim', 'Name': claim, 'UID': v['ClaimUID'],
                    'PVName': v['PVName'], 'PVUID': v['PVUID'], 'SHA256': v['PVSpecSHA256']}
        print('LONGHORN_WORKSPACE_PIN', json.dumps({'NativeCoordinate': expected,
            'Configured': pins, 'ExactMatchIgnoringVolumeLabel': any(dict(p, Volume='workspace') == expected for p in pins)}), flush=True)
    source = next(c for c in selected['Connections'] if c['Purpose'] == 'source_sql')
    dsn = A.read(source['Credential']).decode().strip(); ca = A.read(source['CA'])
    credentials, sep, address = dsn.rpartition('@tcp('); user, colon, password = credentials.partition(':')
    host, end, tail = address.partition(')/'); database = tail.split('?', 1)[0]; peer = urlsplit(source['Endpoint'])
    A.need(sep and colon and end and host == peer.netloc and database == source['Database'] and
           source['Account'].startswith(user + '@') and user.lower() != 'root' and not any(c in password for c in '\r\n\0'),
           'original source SQL credential binding differs')
    sql = """SET SESSION TRANSACTION READ ONLY; START TRANSACTION;
SELECT JSON_OBJECT('Account',CURRENT_USER(),'RoleNone',CURRENT_ROLE()='NONE','Database',DATABASE(),'ServerUUID',@@server_uuid);
SELECT JSON_OBJECT('ID',id,'UserID',user_id,'ResourceScope',resource_scope,'Status',status,'PVC',COALESCE(shared_pvc_name,''),'Namespace',COALESCE(shared_pvc_namespace,''),'Root',COALESCE(shared_mount_path,'')) FROM teams WHERE status<>'deleted' ORDER BY id LIMIT 101;
COMMIT;"""
    result = subprocess.run(['kubectl', '--kubeconfig', W.KUBE, '--request-timeout=20s', '-n', W.NS,
        'exec', '-i', 'deployment/mysql', '-c', 'mysql', '--', 'sh', '-c', W.MYSQL_SHELL, 'longhorn-readonly',
        peer.hostname, str(peer.port or 3306), user, database, sql],
        input=password.encode() + b'\n' + base64.b64encode(ca) + b'\n', capture_output=True, timeout=45)
    A.retain(records / 'sql.stdout.private', result.stdout or b'\n'); A.retain(records / 'sql.stderr.private', result.stderr or b'\n')
    A.need(result.returncode == 0 and 0 < len(result.stdout) <= 1 << 20, 'bounded SQL read refused')
    rows = [A.decode(line) for line in result.stdout.splitlines()]
    A.need(1 <= len(rows) <= 101 and rows[0] == {'Account': source['Account'], 'RoleNone': 1,
        'Database': source['Database'], 'ServerUUID': source['ServerUUID']}, 'actual source SQL identity differs')
    print('LONGHORN_TEAM_SQL_IDENTITY_VERIFIED', flush=True)
    for row in rows[1:]:
        print('LONGHORN_TEAM_SOURCE', json.dumps({**row, 'CurrentNamespaceRulePasses': not row['PVC'] or row['Namespace'] == core['namespace']}), flush=True)
    A.retain(records / 'completed.json', {'Version': 'p2-longhorn-source-conditions.v1', 'TeamCount': len(rows)-1,
        'NamespaceRuleFailures': [r['ID'] for r in rows[1:] if r['PVC'] and r['Namespace'] != core['namespace']],
        'Mutated': False, 'BackupReady': False})
    print('LONGHORN_SOURCE_CONDITIONS_READONLY_FINISHED', flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('LONGHORN_SOURCE_CONDITIONS_UNCONFIRMED ' + (str(error) if type(error) is ValueError else type(error).__name__))
