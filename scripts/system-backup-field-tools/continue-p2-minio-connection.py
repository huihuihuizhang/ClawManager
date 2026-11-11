#!/usr/bin/env python3
"""Complete this validation task's existing MinIO plan and retain source DATA."""
import argparse
import base64
import datetime
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from types import SimpleNamespace
from urllib.parse import quote

WORK = Path('/root/sbk-validation-tls-inspect.7LVU7vpE')
ROOT = Path('/root/sbk/p2-minio-prepare.9vnemhVi')
MINIO = ROOT / 'minio-tls'
PLAN_SHA = '5f0c664f2a694ff997011aa8aa2b9c697dfdea1179438775ecad8a1837c27da3'
CA_SHA = '1ee23762b1a38a93b709641a79191466e45f8b2bda208e0c1901d25018054450'
OPERATION = 'a10011353367ae32b9b7dacb3bfb6a17'
NS = 'clawmanager-sbk-validation-system'
PINS = {
    'system-backup-minio-first-hop-tls.py': 'e1659e3553a7672f9624422f6a678ae824ad0a63a16a8066a1889034463376ad',
    'system-backup-first-page-tls-only.py': '3c83146283440b73ec518c505d7e6bfbccb94c5651ba9c0e3e3d764767d14421',
    'system-backup-minio-app-tls-cutover.py': '08775915c20ec55ea0c470144154243939f1e5c30f2fd395e4f04a10f946d4ce',
}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def private(path, sha=None, maximum=8 << 20):
    need(path.is_absolute() and not path.is_symlink() and path.resolve(strict=True) == path,
         'private material path changed')
    st = path.stat()
    need(path.is_file() and (os.name != 'posix' or st.st_mode & 0o077 == 0) and 0 < st.st_size <= maximum,
         'private material type/mode/size changed')
    raw = path.read_bytes()
    need(sha is None or digest(raw) == sha, 'private material pin changed')
    return raw


def retain(path, raw):
    if path.exists() or path.is_symlink():
        need(private(path) == raw, 'retained material changed: ' + path.name)
    else:
        with path.open('xb') as out:
            os.chmod(path, 0o600)
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
    return {'File': str(path), 'SHA256': digest(raw)}


def latest(path, raw):
    if path.exists() or path.is_symlink():
        private(path, maximum=16 << 20)
    with path.open('wb') as out:
        os.chmod(path, 0o600)
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def module(directory, name):
    file = directory / name
    need(not file.is_symlink() and digest(file.read_bytes()) == PINS[name], 'original helper bytes changed')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def source_arguments():
    return SimpleNamespace(action='apply', kubeconfig_file=WORK / 'operator.kubeconfig.yaml',
        kubeconfig_sha256='152d2049f8b1c3e9e043ed024bae24cf2253aa3b8da19bf1c67f9fa9a9979bde',
        installation_plan_file=WORK / 'fresh-sql-prepare.faa4osWr/fresh-backup-enrollment-r2/native/original-enrollment-plan.json',
        installation_plan_sha256='a0aa44b5a12a453c352a402e73c4f4d42a675b2430d2cb69972a29df1f859752', service='minio')


def signed_list_request(host, bucket, prefix, access, secret, now):
    """One real authenticated, finite, read-only S3 request; no userinfo URL."""
    need(host and bucket and access and secret and '\n' not in access and '\r' not in access,
         'bounded source S3 identity required')
    stamp, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
    uri = '/' + quote(bucket, safe='')
    query = 'list-type=2&max-keys=1&prefix=' + quote(prefix, safe='')
    empty = digest(b'')
    headers = 'host:' + host + '\nx-amz-content-sha256:' + empty + '\nx-amz-date:' + stamp + '\n'
    names = 'host;x-amz-content-sha256;x-amz-date'
    canonical = '\n'.join(['GET', uri, query, headers, names, empty])
    scope = day + '/us-east-1/s3/aws4_request'
    string = 'AWS4-HMAC-SHA256\n' + stamp + '\n' + scope + '\n' + digest(canonical.encode())
    key = ('AWS4' + secret).encode()
    for value in (day, 'us-east-1', 's3', 'aws4_request'):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string.encode(), hashlib.sha256).hexdigest()
    authorization = 'AWS4-HMAC-SHA256 Credential=' + access + '/' + scope + ', SignedHeaders=' + names + ', Signature=' + signature
    request = ('GET ' + uri + '?' + query + ' HTTP/1.1\r\nHost: ' + host + '\r\nX-Amz-Date: ' + stamp +
        '\r\nX-Amz-Content-Sha256: ' + empty + '\r\nAuthorization: ' + authorization + '\r\nConnection: close\r\n\r\n')
    return request.encode()


def authenticated_object_read(m, source, graph, bucket, prefix, access, secret):
    with socket.socket() as pick:
        pick.bind(('127.0.0.1', 0))
        port = pick.getsockname()[1]
    process = subprocess.Popen(source.prefix + ['port-forward', '--address=127.0.0.1',
        'pod/' + graph['pod']['metadata']['name'], str(port) + ':9000'], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=m.native_env())
    try:
        for _ in range(100):
            need(process.poll() is None, 'original S3 forwarding exited')
            try:
                channel = socket.create_connection(('127.0.0.1', port), timeout=10)
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError('original S3 forwarding unavailable')
        host = 'minio.' + NS + '.svc'
        context = ssl.create_default_context(cafile=str(MINIO / 'ca.pem'))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with context.wrap_socket(channel, server_hostname=host) as connection:
            connection.sendall(signed_list_request(host + ':9000', bucket, prefix, access, secret,
                datetime.datetime.now(datetime.timezone.utc)))
            response = http.client.HTTPResponse(connection)
            response.begin()
            body = response.read((2 << 20) + 1)
            need(response.status == 200 and len(body) <= 2 << 20 and b'ListBucketResult' in body,
                 'authenticated finite source S3 read refused; response suppressed')
        return {'state': 'actual_source_s3_list_verified', 'http_status': 200,
            'response_sha256': digest(body), 'tls_ca_sha256': CA_SHA}
    finally:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main(directory):
    os.umask(0o077)
    need(os.name == 'posix' and directory.is_absolute() and directory.resolve(strict=True) == directory,
         'Linux absolute tool directory required')
    for name in PINS:
        need(digest((directory / name).read_bytes()) == PINS[name], 'delivery helper pin differs')
    m = module(directory, 'system-backup-minio-first-hop-tls.py')
    a = module(directory, 'system-backup-minio-app-tls-cutover.py')
    a.m = m
    private(MINIO / 'plan.json', PLAN_SHA)
    private(MINIO / 'ca.pem', CA_SHA)
    records = ROOT / 'connection-continuation'
    if not records.exists():
        records.mkdir(mode=0o700)
    need(not records.is_symlink() and records.stat().st_mode & 0o077 == 0, 'private records directory changed')
    print('P2_REQUIRED_CONNECTION_RECORDS', records, flush=True)
    source = m.Source(source_arguments())
    need(source.ns == NS, 'unexpected installation namespace')
    plan = m.load(source, MINIO, PLAN_SHA)
    need(plan['operation'] == OPERATION and plan['ca_sha256'] == CA_SHA, 'different MinIO operation')
    args = SimpleNamespace(action='prepare', minio_state_directory=MINIO, minio_plan_sha256=PLAN_SHA,
        app_deployment='clawmanager-app', local_admin_password_file=WORK / 'fresh-backup-bootstrap/admin-password',
        state_directory=records / 'app-cutover', service='minio',
        installation_plan_sha256=source.args.installation_plan_sha256)
    app_receipt = records / 'app-preparation.receipt.json'
    if app_receipt.exists():
        prepared = json.loads(private(app_receipt))
    else:
        need(not args.state_directory.exists(), 'partial App preparation retained; inspect before preparing again')
        prepared = a.prepare(source, args)
        retain(app_receipt, encode(prepared))
    app_plan = json.loads(private(args.state_directory / 'plan.json', prepared['plan_sha256']))
    need(app_plan['namespace'] == NS and app_plan['minio_plan_sha256'] == PLAN_SHA
         and app_plan['operation'] == OPERATION and app_plan['installation_plan_sha256'] == source.args.installation_plan_sha256
         and app_plan['deployment']['metadata']['name'] == args.app_deployment, 'App cutover plan binding changed')
    # Native helper journals decide whether a send is original, confirmed, or
    # unknown. A resumed stage is strictly a query of that same operation.
    for name, location, apply in [
        ('minio', MINIO, lambda query: m.apply(source, MINIO, plan, query_only=query)),
        ('app', args.state_directory, lambda query: app_apply(a, source, args, app_plan, query)),
    ]:
        marker = records / (name + '.started.json')
        query = marker.exists()
        retain(marker, encode({'operation': OPERATION, 'minio_plan_sha256': PLAN_SHA,
            'app_plan_sha256': prepared['plan_sha256']}))
        print('P2_CONNECTION_STAGE', name, 'query' if query else 'apply', flush=True)
        try:
            result = apply(query)
        except m.Refused as error:
            if name != 'app' or str(error) != 'no existing archived business object; actual SDK read remains unverified':
                raise
            # Empty source data needs a real authenticated S3 list below. It
            # does not become an assertion that a business SDK download ran.
            result = {'state': 'actual_business_archive_inventory_empty', 'business_sdk_download_verified': False}
        latest(records / (name + '.latest.receipt.json'), encode(result))
        print('P2_CONNECTION_STAGE_RESULT', name, result['state'], flush=True)

    graph = source.graph()
    dep, actors = a.app_source(source, args.app_deployment)
    need(dep['metadata']['uid'] == app_plan['deployment']['metadata']['uid']
         and dep['spec'] == app_plan['desired_spec'], 'App cutover spec changed')
    def loaded(actor, name):
        need(name in {'MINIO_ROOT_USER', 'MINIO_ROOT_PASSWORD', 'OBJECT_STORAGE_ACCESS_KEY',
            'OBJECT_STORAGE_SECRET_KEY', 'OBJECT_STORAGE_ENDPOINT', 'OBJECT_STORAGE_USE_SSL',
            'OBJECT_STORAGE_TLS_CA_SHA256'}, 'unselected environment name')
        return a.app_exec(source, actor, '/bin/sh', '-ceu', 'printf "%s" "${' + name + '-}"')
    minio_actor = (graph['pod'], graph['pod']['spec']['containers'][0], graph['status'])
    access, secret = loaded(minio_actor, 'MINIO_ROOT_USER'), loaded(minio_actor, 'MINIO_ROOT_PASSWORD')
    need(0 < len(access) <= 1024 and 0 < len(secret) <= 4096, 'actual source object credential missing')
    configs = []
    for actor in actors:
        need(loaded(actor, 'OBJECT_STORAGE_ACCESS_KEY') == access and loaded(actor, 'OBJECT_STORAGE_SECRET_KEY') == secret,
             'App loaded object credential differs from source connection')
        need(loaded(actor, 'OBJECT_STORAGE_ENDPOINT') == ('minio.' + NS + '.svc:9000').encode()
             and loaded(actor, 'OBJECT_STORAGE_USE_SSL') == b'true'
             and loaded(actor, 'OBJECT_STORAGE_TLS_CA_SHA256') == CA_SHA.encode(), 'App loaded MinIO TLS binding differs')
        raw = a.app_exec(source, actor, '/usr/local/bin/clawreef-server', '--system-backup-source-config-data')
        lines = raw.splitlines()
        need(lines and all(line.startswith(b'Loading k8s config from: ') for line in lines[:-1]), 'unexpected original config DATA protocol')
        value = json.loads(lines[-1])
        need(value.get('Version') == 'original-application-config-coordinates.v1'
             and value.get('RuntimeQualified') is False and value.get('BackupReady') is False, 'original effective source config DATA required')
        configs.append(value)
    need(configs and all(value == configs[0] for value in configs), 'App effective config differs across replicas')
    config = configs[0]
    bucket, prefix = config['ObjectBucket'], config['ObjectPrefix']
    need(bucket and prefix, 'finite actual source bucket/prefix required')
    actual = authenticated_object_read(m, source, graph, bucket, prefix, access.decode(), secret.decode())
    after = source.graph()
    need(after['pod']['metadata']['uid'] == graph['pod']['metadata']['uid']
         and after['status']['containerID'] == graph['status']['containerID'], 'source process changed during object read')
    source.authority()
    ca = {'File': str(MINIO / 'ca.pem'), 'SHA256': CA_SHA}
    credential = retain(records / 'source-minio-credential.private.json', encode({
        'access_key': access.decode(), 'secret_key': base64.b64encode(secret).decode()}))
    host = 'minio.' + NS + '.svc'
    fragment = {'Version': 'validation-p2-minio-source-data.v1', 'Connection': {'Purpose': 'source_objects',
        'Endpoint': 'https://' + host + ':9000', 'Account': access.decode(), 'ServerUUID': '', 'Database': '',
        'CA': ca, 'Credential': credential, 'IdentitySHA256': '', 'ScopeSHA256': ''},
        'MaterialsObjectsData': {'CredentialFile': credential['File'], 'CredentialSHA256': credential['SHA256'],
            'Objects': {'Address': host + ':9000', 'ServerName': host, 'CAFile': ca['File'], 'CASHA256': CA_SHA}},
        'ObjectBucket': bucket, 'ObjectPrefix': prefix, 'ActualRead': actual,
        'NativeSourceQualified': False, 'BackupReady': False}
    fragment_pin = retain(records / 'minio-source-fragment.json', encode(fragment))
    # Retain private input snapshots needed by the existing complete-source
    # author; these are DATA, not replacement grants or stop acknowledgements.
    for label, argv in [('platform', ['get', 'deployments,services,persistentvolumeclaims,serviceaccounts,configmaps', '-o', 'json']),
        ('nodes', ['get', 'nodes', '-o', 'json']), ('storageclasses', ['get', 'storageclasses', '-o', 'json']),
        ('snapshotclasses', ['get', 'volumesnapshotclasses.snapshot.storage.k8s.io', '-o', 'json'])]:
        raw = source.kube(*argv)
        latest(records / (label + '.latest.private.json'), raw)
    retain(records / 'effective-app-config.json', encode(config))
    print('P2_MINIO_SOURCE_CONNECTION_READY', json.dumps({'fragment': fragment_pin,
        'replicas': len(actors), 's3_http': actual['http_status'], 'backup_ready': False}), flush=True)
    platform = json.loads((records / 'platform.latest.private.json').read_bytes())
    print('P2_PLATFORM_DEPLOYMENTS', json.dumps([{'name': row['metadata']['name'], 'uid': row['metadata']['uid'],
        'replicas': row['spec'].get('replicas', 1), 'images': [c['image'] for c in row['spec']['template']['spec']['containers']]}
        for row in platform['items'] if row.get('kind') == 'Deployment']), flush=True)


def app_apply(a, source, args, plan, query):
    args.action = 'query' if query else 'apply'
    return a.apply(source, args, plan)


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--tool-directory', type=Path, required=True)
        args = parser.parse_args()
        main(args.tool_directory)
    except Exception as error:
        # No raw native stdout, credential, S3 response or env value is printed.
        message = str(error) if type(error) is RuntimeError or type(error).__name__ == 'Refused' else type(error).__name__
        raise SystemExit('P2_REQUIRED_CONNECTION_UNCONFIRMED ' + message)
