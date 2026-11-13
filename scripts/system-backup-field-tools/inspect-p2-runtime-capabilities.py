#!/usr/bin/env python3
"""Read instance 1's pinned runtime capability endpoint; never send control actions."""
import base64
import datetime as dt
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
SELECTION = {'File': '/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-20261113-provider-loaded/source-selection.json',
             'SHA256': 'e868971899c29149296d3a11b5d5fb2063cf7c4994800b770bafa2b434dcf79e'}
NS = 'clawmanager-sbk-validation-system'
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'
STRINGS = ('protocol', 'namespace', 'pod_uid', 'agent_epoch', 'slot', 'confirmation_scope', 'recovery_scope', 'agent_restart_policy')
BOOLS = ('supported', 'durable_reservation', 'agent_restart_reconciliation')


def need(ok, label):
    if not ok:
        raise ValueError(label)


def capability_summary(raw, row):
    def pairs(values):
        out = {}
        for key, value in values:
            need(key not in out, 'duplicate response field')
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        return {'JSONValid': False}
    if not isinstance(value, dict):
        return {'JSONValid': True, 'Object': False}
    known = set(STRINGS + BOOLS + ('gateway_port',))
    return {'JSONValid': True, 'Object': True, 'UnknownFieldCount': len(set(value)-known),
            'MissingFields': sorted(known-set(value)),
            'TypesMatch': all(k not in value or isinstance(value[k], str) for k in STRINGS) and
                          all(k not in value or type(value[k]) is bool for k in BOOLS) and
                          ('gateway_port' not in value or type(value['gateway_port']) is int),
            'ProtocolMatches': value.get('protocol') == 'isolated-backup.v1',
            'ScopeMatches': value.get('confirmation_scope') == 'instance_pid_namespaces_and_mounts',
            'NamespaceMatches': value.get('namespace') == row['namespace'],
            'PodUIDMatches': value.get('pod_uid') == row['pod_uid'],
            'GatewayPortMatches': type(value.get('gateway_port')) is int and value['gateway_port'] == row['port'],
            'Supported': value.get('supported') is True, 'DurableReservation': value.get('durable_reservation') is True,
            'SlotPresent': isinstance(value.get('slot'), str) and bool(value['slot']),
            'EpochValid': isinstance(value.get('agent_epoch'), str) and bool(re.fullmatch('[a-f0-9]{32}', value['agent_epoch'])),
            'RecoveryScopeMatches': value.get('recovery_scope') == 'original_operation_same_agent_epoch',
            'RestartPolicyMatches': value.get('agent_restart_policy') == 'quarantine_active_reservation',
            'RestartReconciliationFalse': value.get('agent_restart_reconciliation', False) is False}


def main():
    need(os.name == 'posix', 'Linux operator required'); os.umask(0o077)
    spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
    selected = A.obj(SELECTION)
    now = dt.datetime.now(dt.timezone.utc)
    need(dt.datetime.fromisoformat(selected['NotBefore'].replace('Z', '+00:00')) <= now <
         dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00')), 'source window expired; retain records')
    prior = ROOT / 'longhorn-source-20261113-provider-loaded-service-account-repair'
    need(A.decode((prior/'native.exit.json').read_bytes()) == {'ExitCode': 1}, 'observed native refusal required')
    refusal = A.decode((prior/'native.stdout.private').read_bytes())
    need(all(refusal.get(k) == v for k, v in {'Status': 'original_mount_author_refused', 'Phase': 'native_writers',
         'Step': 'native_agent_capabilities', 'Kind': 'RuntimeAgent', 'Reason': 'read_error', 'InstanceID': 1}.items()),
         'observed instance 1 capability read refusal required')
    need(A.decode((prior/'native.sent.private.json').read_bytes())['SourceSelection'] == SELECTION, 'source pin differs')
    agent = selected['RuntimeAgent']
    need(agent['Operations'] == ['backup_capabilities_read', 'gateway_state_read'], 'original read operations required')
    ca, token = A.read(agent['CA']), A.read(agent['Credential']).decode().strip()
    need(token and not any(c in token for c in '\r\n\0'), 'invalid control credential')
    connections = [c for c in selected['Connections'] if c['Purpose'] == 'source_sql']
    need(len(connections) == 1, 'one source SQL connection required'); sql = connections[0]
    sql_ca, dsn = A.read(sql['CA']), A.read(sql['Credential']).decode().strip()
    creds, sep, address = dsn.rpartition('@tcp('); user, colon, password = creds.partition(':')
    host, end, tail = address.partition(')/'); database = tail.split('?', 1)[0]; peer = urlsplit(sql['Endpoint'])
    need(sep and colon and end and host == peer.netloc and database == sql['Database'] and sql['Account'].startswith(user+'@') and
         user.lower() != 'root' and not any(c in password for c in '\r\n\0'), 'original source SQL credential required')
    records = Path(tempfile.mkdtemp(prefix='runtime-capability-readback-', dir=ROOT))
    print('RUNTIME_CAPABILITY_RECORDS', records, flush=True)
    print('RUNTIME_CAPABILITY_SOURCE', json.dumps({'UTCNow': now.isoformat(), 'Until': selected['Until'], 'InstanceID': 1}), flush=True)
    shell = '''set -eu
IFS= read -r MYSQL_PWD
export MYSQL_PWD
IFS= read -r ca
umask 077
f=$(mktemp /tmp/sbk-capability-sql-ca.XXXXXX)
trap 'rm -f -- "$f"' EXIT HUP INT TERM
printf '%s' "$ca" | base64 -d > "$f"
mysql --protocol=TCP --connect-timeout=8 --ssl-mode=VERIFY_IDENTITY --tls-version=TLSv1.3 --ssl-ca="$f" -h "$1" -P "$2" -u "$3" --database="$4" --batch --skip-column-names --raw -e "$5"
'''
    query = """SET SESSION TRANSACTION READ ONLY; START TRANSACTION;
SELECT JSON_OBJECT('account',CURRENT_USER(),'role_none',CURRENT_ROLE()='NONE','database',DATABASE(),'server',@@server_uuid);
SELECT JSON_OBJECT('id',i.id,'generation',i.runtime_generation,'binding_generation',b.generation,'instance_state',i.status,
'binding_state',b.state,'port',b.gateway_port,'pod_uid',p.pod_uid,'pod',p.pod_name,'namespace',p.namespace,
'endpoint',p.agent_endpoint,'deployment',p.deployment_name,'pool_state',p.state,'draining',p.draining)
FROM instances i JOIN instance_runtime_bindings b ON b.instance_id=i.id JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE i.id=1;
COMMIT;"""
    base = ['kubectl', '--kubeconfig', KUBE, '--request-timeout=20s', '-n', NS]
    result = subprocess.run(base+['exec', '-i', 'deployment/mysql', '-c', 'mysql', '--', 'sh', '-c', shell, 'sbk-readonly',
        peer.hostname, str(peer.port or 3306), user, database, query], input=password.encode()+b'\n'+base64.b64encode(sql_ca)+b'\n',
        capture_output=True, timeout=45)
    A.retain(records/'sql.stdout.private', result.stdout or b'\n'); A.retain(records/'sql.stderr.private', result.stderr or b'\n')
    need(result.returncode == 0, 'source SQL read refused; private records retained')
    lines = result.stdout.splitlines(); need(len(lines) == 2, 'one current binding required')
    identity, row = [A.decode(v) for v in lines]
    need(identity == {'account': sql['Account'], 'role_none': 1, 'database': sql['Database'], 'server': sql['ServerUUID']}, 'SQL identity differs')
    need(row['id'] == 1 and row['generation'] == row['binding_generation'] and row['instance_state'] == row['binding_state'] == 'running' and
         row['pool_state'] == 'ready' and not row['draining'] and type(row['port']) is int and 0 < row['port'] < 65536 and row['namespace'] == NS,
         'current instance binding differs')
    def get(kind, name):
        result = subprocess.run(base+['get', kind, name, '-o', 'json'], capture_output=True, timeout=25)
        need(result.returncode == 0, 'Kubernetes read refused')
        return A.decode(result.stdout)
    def owner(obj, kind):
        owners = [o for o in obj['metadata'].get('ownerReferences', []) if o.get('controller')]
        need(len(owners) == 1 and owners[0]['kind'] == kind, 'runtime owner chain differs')
        return owners[0]
    pod = get('pod', row['pod']); ref = owner(pod, 'ReplicaSet'); rs = get('replicaset', ref['name'])
    need(rs['metadata']['uid'] == ref['uid'] and not rs['metadata'].get('deletionTimestamp'), 'ReplicaSet changed')
    ref = owner(rs, 'Deployment'); dep = get('deployment', ref['name'])
    need(ref['name'] == row['deployment'] == 'openclaw-runtime' and ref['uid'] == dep['metadata']['uid'] ==
         'baf19cae-4476-4d1c-a9c8-884fd13077d2' and not dep['metadata'].get('deletionTimestamp'), 'runtime Deployment changed')
    need(pod['metadata']['uid'] == row['pod_uid'] and not pod['metadata'].get('deletionTimestamp') and pod['status']['phase'] == 'Running', 'runtime Pod changed')
    endpoint = urlsplit(row['endpoint'])
    need(endpoint.scheme == 'https' and not endpoint.username and not endpoint.password and endpoint.path == '' and not endpoint.query and
         not endpoint.fragment and ipaddress.ip_address(endpoint.hostname) == ipaddress.ip_address(pod['status']['podIP']), 'runtime endpoint differs')
    print('RUNTIME_CAPABILITY_BINDING_VERIFIED', json.dumps({'InstanceID': 1, 'Generation': row['generation'], 'PodUID': row['pod_uid'],
          'GatewayPort': row['port'], 'Deployment': row['deployment'], 'CA_SHA256': agent['CA']['SHA256']}), flush=True)
    context = ssl.create_default_context(cadata=ca.decode()); context.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        with socket.create_connection((endpoint.hostname, endpoint.port or 443), timeout=10) as plain:
            with context.wrap_socket(plain, server_hostname='lite-agent.clawmanager.internal') as secured:
                print('RUNTIME_CAPABILITY_TLS_OK', json.dumps({'TLS': secured.version(), 'NotAfter': secured.getpeercert().get('notAfter')}), flush=True)
                connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port or 443, timeout=10)
                connection.sock = secured
                try:
                    connection.request('GET', '/v1/backup/capabilities?gateway_port='+str(row['port']),
                        headers={'X-ClawManager-Control-Token': token, 'Content-Type': 'application/json'})
                    response = connection.getresponse(); raw = response.read((64 << 10)+1)
                    A.retain(records/'capability.body.private', raw or b'\n')
                    print('RUNTIME_CAPABILITY_HTTP', json.dumps({'Status': response.status, 'BodyBytes': len(raw),
                          'Bounded': len(raw) <= 64 << 10, 'SHA256': hashlib.sha256(raw).hexdigest()}), flush=True)
                    if response.status == 200 and len(raw) <= 64 << 10:
                        print('RUNTIME_CAPABILITY_FIELDS', json.dumps(capability_summary(raw, row)), flush=True)
                finally:
                    connection.close()
    except ssl.SSLCertVerificationError as error:
        print('RUNTIME_CAPABILITY_TLS_REFUSED', json.dumps({'Code': error.verify_code}), flush=True)
    except (OSError, http.client.HTTPException) as error:
        print('RUNTIME_CAPABILITY_CONNECT_ERROR', type(error).__name__, flush=True)
    print('RUNTIME_CAPABILITY_READONLY_DIAGNOSTIC_FINISHED', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('RUNTIME_CAPABILITY_DIAGNOSTIC_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
