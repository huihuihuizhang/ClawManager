#!/usr/bin/env python3
"""Deploy the scheduler retry fix, then verify actual SQL/Kubernetes/Gateway recovery.

Uses the normal application scheduler. No direct SQL DML or Gateway mutation.
Existing image layers/configuration and Deployment fields are preserved.
"""
import base64
import datetime as dt
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from urllib.parse import urlsplit, quote

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
BASE = '10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780'
OLD_UID = 'd995ae33-ff70-4a95-bf2b-37bdbf9937f3'
NEW_UID = 'a384ba3f-984d-4108-ae5d-14eaf19ccea8'
RUNTIME_UIDS = {'hermes-runtime': 'de547f9b-b21a-45b3-9d74-c77ce35ab0d4',
                'openclaw-runtime': 'baf19cae-4476-4d1c-a9c8-884fd13077d2'}
ROWS = """SELECT JSON_OBJECT('id',i.id,'user',i.user_id,'generation',i.runtime_generation,
'binding_generation',b.generation,'instance_state',i.status,'binding_state',b.state,
'gateway',b.gateway_id,'pid',b.gateway_pid,'port',b.gateway_port,'workspace_match',i.workspace_path=b.workspace_path,
'pool',p.id,'pod_uid',p.pod_uid,'pod',p.pod_name,'namespace',p.namespace,'endpoint',p.agent_endpoint,
'deployment',p.deployment_name,'pool_state',p.state,'draining',p.draining,
'heartbeat_age',TIMESTAMPDIFF(SECOND,p.last_seen_at,UTC_TIMESTAMP()))
FROM instances i JOIN instance_runtime_bindings b ON b.instance_id=i.id
JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE i.id IN (1,3,7,8) ORDER BY i.id"""


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def coherent(row):
    return (row['instance_state'] == row['binding_state'] == 'running' and
            row['generation'] == row['binding_generation'] and row['pool_state'] == 'ready' and
            not row['draining'] and row['workspace_match'] == 1 and row['pid'] > 0 and
            0 < row['port'] < 65536 and row['gateway'] == 'gw-%d-%d' % (row['id'], row['generation']) and
            row['heartbeat_age'] is not None and -5 <= row['heartbeat_age'] < 60)


def gateway_matches(value, row):
    return value == {'instance_id': row['id'], 'user_id': row['user'], 'generation': row['generation'],
                     'gateway_id': row['gateway'], 'gateway_pid': row['pid'], 'gateway_port': row['port'], 'state': 'running'}


def main():
    A, W, P = (load(n) for n in ('assemble-p2-installation-candidate', 'inspect-p2-app-backup-wiring', 'publish-p2-execution-candidates'))
    need = A.need
    need(os.name == 'posix', 'Linux operator required')
    os.umask(0o077)
    directory = Path(__file__).resolve().parent
    build = json.loads((directory / 'BUILD_RECEIPT.json').read_bytes())
    need(build['SourceRevision'] == (directory / 'SOURCE_REVISION').read_text().strip(), 'package revision differs')
    records = ROOT / ('runtime-pool-recovery-' + build['SourceRevision'][:8])
    records.mkdir(mode=0o700, exist_ok=True)
    need(records.resolve() == records and records.stat().st_mode & 0o077 == 0, 'private original records required')
    print('RUNTIME_POOL_RECOVERY_RECORDS', records, flush=True)
    selected = A.obj(W.SOURCE)
    now = dt.datetime.now(dt.timezone.utc)
    need(dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00')) > now + dt.timedelta(minutes=10), 'source observation window insufficient; renew before proceeding')
    c = next(v for v in selected['Connections'] if v['Purpose'] == 'control_sql')
    journal = ROOT / 'initial-source-author/configuration-data.result.json'
    inputs = A.obj(A.obj({'File': str(journal), 'SHA256': A.sha(journal.read_bytes())})['AssemblyInputs'])
    need(inputs['ControlDSN'] == c['Credential'], 'original SQL producer changed')
    user, password, account = W.installer_credentials(A.obj(inputs['SQLOperation']), c)
    ca, peer = A.read(c['CA']), urlsplit(c['Endpoint'])
    kube = ['kubectl', '--kubeconfig', W.KUBE, '--request-timeout=20s', '-n', W.NS]

    def call(args, body=None, timeout=35):
        result = subprocess.run(kube + args, input=body, capture_output=True, timeout=timeout)
        stamp = str(time.time_ns())
        A.retain(records / (stamp + '.stdout.private'), result.stdout or b'\n')
        A.retain(records / (stamp + '.stderr.private'), result.stderr or b'\n')
        need(result.returncode == 0, 'Kubernetes operation failed; original private output retained')
        return result.stdout

    def get(kind, name):
        return json.loads(call(['get', kind, name, '-o', 'json']))

    def sql(statement):
        query = "SET SESSION TRANSACTION READ ONLY; START TRANSACTION; SELECT JSON_OBJECT('account',CURRENT_USER(),'database',DATABASE(),'server',@@server_uuid); " + statement + '; COMMIT;'
        raw = call(['exec', '-i', 'deployment/mysql', '-c', 'mysql', '--', 'sh', '-c', W.MYSQL_SHELL,
                    'sbk-recovery-readonly', peer.hostname, str(peer.port or 3306), user, c['Database'], query],
                   password.encode() + b'\n' + base64.b64encode(ca) + b'\n', timeout=50)
        values = [json.loads(line) for line in raw.splitlines()]
        need(values[0] == {'account': account, 'database': c['Database'], 'server': c['ServerUUID']}, 'SQL identity changed')
        return values[1:]

    def bindings(require_complete=True):
        values = sql(ROWS)
        ids = [v['id'] for v in values]
        need(ids == [1,3,7,8] or not require_complete and ids == [1,7,8], 'active Lite binding set changed')
        return values

    def pod_check(row):
        need(row['namespace'] == W.NS and row['deployment'] in RUNTIME_UIDS, 'runtime namespace/deployment changed')
        pod = get('pod', row['pod'])
        need(pod['metadata']['uid'] == row['pod_uid'] and not pod['metadata'].get('deletionTimestamp') and
             pod['status']['phase'] == 'Running' and any(x['type'] == 'Ready' and x['status'] == 'True' for x in pod['status'].get('conditions', [])), 'current runtime Pod not Ready')
        current = pod
        for kind in ('ReplicaSet', 'Deployment'):
            refs = [r for r in current['metadata'].get('ownerReferences', []) if r.get('controller')]
            need(len(refs) == 1 and refs[0]['kind'] == kind, 'runtime owner chain changed')
            current = get(kind.lower(), refs[0]['name'])
            need(current['metadata']['uid'] == refs[0]['uid'] and not current['metadata'].get('deletionTimestamp'), 'runtime owner changed')
        need(current['metadata']['name'] == row['deployment'] and current['metadata']['uid'] == RUNTIME_UIDS[row['deployment']], 'runtime Deployment identity changed')
        endpoint = urlsplit(row['endpoint'])
        need(endpoint.scheme == 'https' and not endpoint.username and not endpoint.password and not endpoint.query and
             not endpoint.fragment and endpoint.path == '' and ipaddress.ip_address(endpoint.hostname) == ipaddress.ip_address(pod['status']['podIP']), 'Agent endpoint not current Pod IP')
        return endpoint

    agent = selected['RuntimeAgent']
    context = ssl.create_default_context(cadata=A.read(agent['CA']).decode())
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    token = A.read(agent['Credential']).decode().strip()
    need(token and not any(c in token for c in '\r\n\0'), 'invalid original Agent credential')

    def gateway(row):
        endpoint = pod_check(row)
        with socket.create_connection((endpoint.hostname, endpoint.port or 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname='lite-agent.clawmanager.internal') as secured:
                connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port or 443, timeout=10)
                connection.sock = secured
                connection.request('GET', '/v1/gateways/' + quote(row['gateway'], safe=''), headers={'X-ClawManager-Control-Token': token})
                response = connection.getresponse()
                raw = response.read(65537)
                need(len(raw) <= 65536, 'bounded Gateway response required')
                return response.status, json.loads(raw) if response.status == 200 else None

    app = get('deployment', 'clawmanager-app')
    need(app['metadata']['uid'] == W.APP_UID and not app['metadata'].get('deletionTimestamp'), 'original app identity required')
    containers = app['spec']['template']['spec']['containers']
    need(len(containers) == 1 and containers[0]['name'] == 'clawmanager-app', 'original app container required')
    initial = bindings()
    if not (records / 'deployment-patch.sent.json').exists():
        need(containers[0]['image'] == BASE, 'expected original app image required')
        for row in initial:
            if row['id'] != 3:
                need(coherent(row), 'another active Lite instance needs recovery')
                status, state = gateway(row)
                need(status == 200 and gateway_matches(state, row), 'unaffected Gateway is not verified')
        old = initial[1]
        need(old['generation'] == old['binding_generation'] == 8 and old['pool'] == 5 and old['pod_uid'] == OLD_UID and
             old['instance_state'] == old['binding_state'] == 'running' and old['pool_state'] == 'unhealthy' and
             old['gateway'] == 'gw-3-8' and old['workspace_match'] == 1 and old['namespace'] == W.NS and
             old['deployment'] == 'hermes-runtime', 'known instance 3 failure changed')
        old_read = call(['get', 'pod', old['pod'], '--ignore-not-found', '-o', 'json'])
        need(not old_read.strip(), 'old Hermes Pod still exists; retain binding')
        replacement = sql("SELECT JSON_OBJECT('pod',pod_name,'pod_uid',pod_uid,'namespace',namespace,'endpoint',agent_endpoint,'deployment',deployment_name,'pool_state',state,'draining',draining,'heartbeat_age',TIMESTAMPDIFF(SECOND,last_seen_at,UTC_TIMESTAMP())) FROM runtime_pods WHERE id=8")
        need(len(replacement) == 1 and replacement[0]['pod_uid'] == NEW_UID and replacement[0]['pool_state'] == 'ready' and
             not replacement[0]['draining'] and -5 <= replacement[0]['heartbeat_age'] < 60, 'current Hermes replacement not ready')
        status, _ = gateway(dict(replacement[0], gateway='gw-3-8'))
        need(status == 404, 'old Gateway may exist on replacement; reconcile before deployment')
        A.retain(records / 'before-deployment.private.json', app)
        A.retain(records / 'before-bindings.private.json', initial)
        print('RUNTIME_POOL_RECOVERY_PREFLIGHT_PASSED', flush=True)
    P.REVISION = build['SourceRevision']
    registry = P.Registry('clawmanager')
    manifest = json.loads(registry.read('manifests', BASE.split('@')[1]))
    P.PROFILES = {'app': ('clawmanager', BASE.split(':')[-1], manifest['config']['digest'].split(':')[1], 'clawreef-server', 'usr/local/bin/clawreef-server')}
    image = P.publish('app', directory, records / 'image', build)
    desired = image['Reference']
    if containers[0]['image'] != desired:
        need(containers[0]['image'] == BASE, 'app changed outside selected recovery')
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': W.APP_UID},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': app['metadata']['resourceVersion']},
                 {'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': BASE},
                 {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': desired}]
        sent = records / 'deployment-patch.sent.json'
        if not sent.exists(): A.retain(sent, {'Image': desired, 'BeforeUID': W.APP_UID})
        call(['patch', 'deployment', 'clawmanager-app', '--type=json', '-p', json.dumps(patch)])
    print('RUNTIME_POOL_RECOVERY_APP_ROLLOUT', flush=True)
    call(['rollout', 'status', 'deployment/clawmanager-app', '--timeout=180s'], timeout=195)
    current = get('deployment', 'clawmanager-app')
    expected = json.loads(json.dumps(A.decode((records / 'before-deployment.private.json').read_bytes())['spec']))
    expected['template']['spec']['containers'][0]['image'] = desired
    need(current['metadata']['uid'] == W.APP_UID and current['spec'] == expected, 'rollout changed other application configuration')
    selector = ','.join(k + '=' + v for k,v in current['spec']['selector']['matchLabels'].items())
    app_pods = json.loads(call(['get', 'pods', '-l', selector, '-o', 'json']))['items']
    active_pods = [p for p in app_pods if not p['metadata'].get('deletionTimestamp')]
    need(len(active_pods) == current['spec']['replicas'] == 2, 'two current application replicas required')
    for p in active_pods:
        statuses = p['status'].get('containerStatuses', [])
        need(len(statuses) == 1 and statuses[0]['ready'] and statuses[0]['imageID'].endswith('@' + desired.split('@')[1]), 'application image not loaded')
        digest = call(['exec', p['metadata']['name'], '-c', 'clawmanager-app', '--', 'sha256sum', '/usr/local/bin/clawreef-server']).decode().split()[0]
        need(digest == build['Binaries']['clawreef-server']['SHA256'], 'loaded application binary differs')
        print('RUNTIME_POOL_RECOVERY_APP_BINARY_VERIFIED', p['metadata']['name'], digest, flush=True)
    for attempt in range(24):
        rows = bindings(False)
        matches = [v for v in rows if v['id'] == 3]
        if not matches:
            print('RUNTIME_POOL_RECOVERY_BINDING_REASSIGNING 3', flush=True)
            if attempt < 23: time.sleep(5)
            continue
        row = matches[0]
        print('RUNTIME_POOL_RECOVERY_PROGRESS', json.dumps({'InstanceID': 3, 'Status': row['instance_state'], 'Generation': row['generation'], 'Pool': row['pool'], 'PoolState': row['pool_state']}), flush=True)
        if all(coherent(v) for v in rows) and row['pod_uid'] == NEW_UID and row['generation'] > 8:
            for item in rows:
                status, state = gateway(item)
                need(status == 200 and gateway_matches(state, item), 'actual Gateway differs from SQL binding')
            final = bindings()
            keys = ('id', 'generation', 'binding_generation', 'gateway', 'pid', 'port', 'pool', 'pod_uid')
            need([{k:v[k] for k in keys} for v in rows] == [{k:v[k] for k in keys} for v in final] and all(coherent(v) for v in final), 'binding changed during Gateway verification')
            result = {'Version': 'p2-runtime-pool-recovered.v1', 'SourceRevision': build['SourceRevision'], 'Image': desired,
                      'InstanceID': 3, 'Generation': row['generation'], 'Pool': row['pool'], 'PodUID': row['pod_uid'],
                      'VerifiedLiteIDs': [1,3,7,8], 'SourceReauthorRequired': True, 'BackupReady': False}
            A.retain(records / 'completed.json', result)
            print('RUNTIME_POOL_RECOVERED_SOURCE_REFRESH_REQUIRED', json.dumps(result), flush=True)
            return
        if attempt < 23: time.sleep(5)
    raise ValueError('scheduler recovery pending; keep new app and original records, do not rewrite SQL')


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        raise SystemExit('RUNTIME_POOL_RECOVERY_UNCONFIRMED ' + (str(exc) if type(exc) is ValueError else type(exc).__name__))
