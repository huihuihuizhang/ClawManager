#!/usr/bin/env python3
"""This installation only: source API connection, native purpose keys and layout DATA.

No backup task, hold, bootstrap/configuration row or forward grant is created.
The API account already belongs to P1. Its new permissions are read-only and
limited to the selected system/tenant/provider namespaces and observed objects.
"""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit

HELPERS = {
    'continue-p2-minio-connection.py': '13da446e37fd45fd1344a04fe433e6e2306740cc5ede4fffa29745393d1a1b25',
    'retry-p2-writer-selection.py': 'be22ac5d9f5c21c5900a51ee6f17345f282145edb2cdd19c7a2bcc3f15b720b6',
}
APP_IMAGE = '10.130.14.23:5000/clawmanager@sha256:322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca'
APP_UID = '8ebd4d4c-57b6-4a82-b310-fae596681a4e'
TENANT = 'clawmanager-sbk-validation-user-1'
REDIS_FRAGMENT = Path('/root/sbk/p2-redis-connection.b5dQ12Lt/redis-source-fragment.json')
REDIS_SHA = '8451e409dbc331e249b2824ec34be3a0d62c9ceb1de4151f813b9e26f7ffa43d'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def load(directory, name):
    path = directory / name
    need(not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == HELPERS[name],
         'reviewed helper changed: ' + name)
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readonly_rules(provider=False):
    if provider:
        return [dict(apiGroups=['longhorn.io'], resources=['volumes', 'engines', 'replicas', 'nodes', 'sharemanagers'], verbs=['get', 'list'])]
    return [dict(apiGroups=[group], resources=resources, verbs=['get', 'list', 'watch']) for group, resources in (
        ('', ['pods', 'services', 'serviceaccounts', 'configmaps', 'secrets', 'persistentvolumeclaims', 'endpoints']),
        ('apps', ['deployments', 'replicasets', 'statefulsets', 'daemonsets']),
        ('batch', ['jobs', 'cronjobs']), ('autoscaling', ['horizontalpodautoscalers']),
        ('networking.k8s.io', ['ingresses', 'networkpolicies']),
        ('rbac.authorization.k8s.io', ['roles', 'rolebindings']), ('coordination.k8s.io', ['leases']),
        ('snapshot.storage.k8s.io', ['volumesnapshots']))]


def check_review(status, namespace, account, uid):
    user = status.get('user', status.get('userInfo', {}))
    need(status.get('authenticated', True) is True and not status.get('error')
         and user.get('username') == 'system:serviceaccount:' + namespace + ':' + account
         and user.get('uid') == uid, 'source API authenticated identity mismatch')


def check_cluster(cluster, plan):
    endpoint = cluster['server'].rstrip('/')
    parsed = urlsplit(endpoint)
    need(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
         and parsed.path in ('', '/') and not parsed.query and not parsed.fragment
         and not cluster.get('insecure-skip-tls-verify') and not cluster.get('proxy-url')
         and cluster.get('tls-server-name', parsed.hostname) == parsed.hostname
         and endpoint == plan['KubernetesAPI'].rstrip('/'), 'original verified API endpoint changed')
    ca = base64.b64decode(cluster['certificate-authority-data'], validate=True)
    need(b'BEGIN CERTIFICATE' in ca and b'PRIVATE KEY' not in ca
         and hashlib.sha256(ca).hexdigest() == plan['KubernetesCASHA256'], 'original API CA changed')
    return endpoint, ca


def ensure_object(call, kind, namespace, value):
    name = value['metadata']['name']
    args = [] if namespace is None else ['-n', namespace]
    found = call(args + ['get', kind, name, '--ignore-not-found', '-o', 'json'], empty=True)
    if found is None:
        # kubectl validates -f metadata against its effective --namespace.
        # Override the helper's system namespace for tenant/provider objects.
        found = call(args + ['create', '-f', '-', '-o', 'json'], value)
    need(all(found.get(k) == v for k, v in value.items() if k != 'metadata')
         and found['metadata']['name'] == name
         and (namespace is None or found['metadata']['namespace'] == namespace), 'existing source read binding drift')
    return found['metadata']['uid']


def app_owner_chain(pod, replica_set, app):
    def controlled(value, kind):
        refs = [r for r in value['metadata'].get('ownerReferences', []) if r.get('controller')]
        need(len(refs) == 1 and refs[0]['kind'] == kind, 'installed App owner chain changed')
        return refs[0]
    ref = controlled(pod, 'ReplicaSet')
    parent = controlled(replica_set, 'Deployment')
    need(ref['name'] == replica_set['metadata']['name'] and ref['uid'] == replica_set['metadata']['uid']
         and parent['name'] == app['metadata']['name'] and parent['uid'] == app['metadata']['uid'] == APP_UID
         and not pod['metadata'].get('deletionTimestamp') and not replica_set['metadata'].get('deletionTimestamp')
         and len(pod['spec']['containers']) == 1 and pod['spec']['containers'][0]['image'] == APP_IMAGE,
         'installed App owner chain changed')
    states = pod['status'].get('containerStatuses', [])
    need(pod['status'].get('phase') == 'Running' and len(states) == 1 and states[0].get('ready')
         and states[0].get('containerID') and states[0].get('imageID', '').endswith(APP_IMAGE.split('@')[1])
         and 'running' in states[0].get('state', {}), 'installed App process changed')


def main(helpers, records):
    os.umask(0o077)
    need(os.name == 'posix' and helpers.resolve(strict=True) == helpers and records.is_absolute()
         and records.resolve() == records and not records.is_symlink(), 'private Linux directories required')
    c = load(helpers, 'continue-p2-minio-connection.py')
    owner = load(helpers, 'retry-p2-writer-selection.py')
    c.private(REDIS_FRAGMENT, REDIS_SHA)
    c.private(c.ROOT / 'connection-continuation/minio-source-fragment.json',
              'c3b4eae48b3d78c12872742be55e6bc95f11bc9e594c83b8697728edc020ede8')
    if not records.exists():
        records.mkdir(mode=0o700)
    need(records.stat().st_mode & 0o077 == 0, 'records permissions changed')
    print('P2_API_RUNTIME_RECORDS', records, flush=True)
    m = c.module(helpers, 'system-backup-minio-first-hop-tls.py')
    source = m.Source(c.source_arguments())
    ns, plan = c.NS, source.plan
    sequence = 0

    def call(args, body=None, config=None, empty=False):
        nonlocal sequence
        sequence += 1
        base = source.prefix if config is None else ['kubectl', '--kubeconfig', str(config), '--request-timeout=20s']
        p = subprocess.run(base + args, input=None if body is None else c.encode(body),
                           capture_output=True, timeout=45, env=m.native_env())
        # Raw objects/reviews may include tokens and Secrets; never print them.
        c.retain(records / ('api-read-%03d.stdout.private' % sequence), p.stdout or b'\n')
        c.retain(records / ('api-read-%03d.stderr.private' % sequence), p.stderr or b'\n')
        operation = (' '.join(args[:2]) if body is None else
                     str(body.get('kind', 'request')) + ' ' + str(body.get('metadata', {}).get('namespace', '')))
        need(p.returncode == 0 and len(p.stdout) <= 64 << 20,
             'API operation refused at private record %03d (%s)' % (sequence, operation))
        if not p.stdout.strip() and empty:
            return None
        return json.loads(p.stdout)

    # A rerun retains the first exact inputs and uses a new read journal suffix.
    existing = list(records.glob('api-read-*.stdout.private'))
    if existing:
        sequence = max(int(p.name.split('.')[0].rsplit('-', 1)[1]) for p in existing)
    namespace = call(['get', 'namespace', ns, '-o', 'json'])
    need(namespace['metadata']['uid'] == plan['Target']['NamespaceUID'], 'source namespace replaced')
    definition = json.loads(c.private(c.WORK / 'fresh-backup-bootstrap/sources-sa.definition.json'))
    account = call(['get', 'serviceaccount', definition['Name'], '-o', 'json'])
    uid = account['metadata']['uid']
    need(not definition.get('ExistingUID') or definition['ExistingUID'] == uid, 'P1 source account replaced')
    need(account['metadata']['name'] not in ('default', 'kubernetes-admin'), 'dedicated original sources account required')
    c.retain(records / 'source-account.binding.json', c.encode(dict(namespace=ns,
        namespace_uid=namespace['metadata']['uid'], account=account['metadata']['name'], account_uid=uid)))

    coordinates = json.loads(c.private(Path('/root/sbk/p2-materials-1dd1ae71.lVSEBfl2/coordinates/initial-source-coordinates.json'),
        '4fe0083a3546c7a41c302861c65b805eea9ef981f9862e86f4bae043724b7980'))
    need(any(row['ID'] == 2 and row['Namespace'] == TENANT for row in coordinates['Instances']), 'original tenant source changed')
    namespaces = [ns, TENANT]
    pvs, node_names = set(), set()
    layout = {}
    for selected_ns in namespaces:
        objects = {}
        for kind in ('deployments', 'pods', 'services', 'persistentvolumeclaims', 'replicasets', 'serviceaccounts'):
            objects[kind] = call(['-n', selected_ns, 'get', kind, '-o', 'json'])
        for pod in objects['pods']['items']:
            if pod['spec'].get('nodeName'):
                node_names.add(pod['spec']['nodeName'])
        for claim in objects['persistentvolumeclaims']['items']:
            if claim['spec'].get('volumeName'):
                pvs.add(claim['spec']['volumeName'])
        layout[selected_ns] = objects
    # Provider namespace is selected from actual Longhorn Volume objects whose
    # names match the captured PV CSI handles.
    pv_objects = [call(['get', 'pv', name, '-o', 'json']) for name in sorted(pvs)]
    handles = {p['spec'].get('csi', {}).get('volumeHandle') for p in pv_objects
               if p['spec'].get('csi', {}).get('driver') == 'driver.longhorn.io'}
    volumes = call(['get', 'volumes.longhorn.io', '-A', '-o', 'json'])
    provider_names = {v['metadata']['namespace'] for v in volumes['items'] if v['metadata']['name'] in handles}
    need(len(provider_names) == 1, 'one actual Longhorn provider namespace required')
    provider_namespace = provider_names.pop()
    namespaces.append(provider_namespace)
    name = 'sbk-p2-source-read'
    subjects = [dict(kind='ServiceAccount', name=account['metadata']['name'], namespace=ns)]
    bindings = []
    for selected_ns in namespaces:
        role = dict(apiVersion='rbac.authorization.k8s.io/v1', kind='Role',
                    metadata=dict(name=name, namespace=selected_ns), rules=readonly_rules(selected_ns == provider_namespace))
        bindings.append(ensure_object(call, 'role', selected_ns, role))
        bindings.append(ensure_object(call, 'rolebinding', selected_ns, dict(apiVersion=role['apiVersion'], kind='RoleBinding',
            metadata=role['metadata'], subjects=subjects, roleRef=dict(apiGroup='rbac.authorization.k8s.io', kind='Role', name=name))))
    rules = [dict(apiGroups=[''], resources=[resource], resourceNames=names, verbs=['get'])
             for resource, names in [('namespaces', sorted(namespaces)), ('nodes', sorted(node_names)), ('persistentvolumes', sorted(pvs))]]
    rules.append(dict(apiGroups=['storage.k8s.io'], resources=['storageclasses'], verbs=['get', 'list']))
    rules.append(dict(apiGroups=['snapshot.storage.k8s.io'], resources=['volumesnapshotclasses', 'volumesnapshotcontents'], verbs=['get', 'list']))
    cr = dict(apiVersion='rbac.authorization.k8s.io/v1', kind='ClusterRole', metadata=dict(name=name), rules=rules)
    bindings.append(ensure_object(call, 'clusterrole', None, cr))
    bindings.append(ensure_object(call, 'clusterrolebinding', None, dict(apiVersion=cr['apiVersion'], kind='ClusterRoleBinding',
        metadata=dict(name=name), subjects=subjects, roleRef=dict(apiGroup='rbac.authorization.k8s.io', kind='ClusterRole', name=name))))
    config = call(['config', 'view', '--minify', '--flatten', '--raw', '-o', 'json'])
    need(len(config['clusters']) == 1, 'one original API cluster required')
    endpoint, ca = check_cluster(config['clusters'][0]['cluster'], plan)
    ca_pin = c.retain(records / 'source-api-ca.pem', ca)
    token_file = records / 'source-api.jwt'
    token_receipt = records / 'source-api-token.receipt.private.json'
    if not token_file.exists():
        need(not token_receipt.exists(), 'token write interrupted; inspect retained token response before continuation')
        response = call(['create', '--raw', '/api/v1/namespaces/' + ns + '/serviceaccounts/' + account['metadata']['name'] + '/token', '-f', '-'],
                        dict(apiVersion='authentication.k8s.io/v1', kind='TokenRequest', spec=dict(expirationSeconds=86400)))
        c.retain(token_receipt, c.encode(response))
        token = response['status']['token'].encode('ascii')
        c.retain(token_file, token)
    token = c.private(token_file)
    response = json.loads(c.private(token_receipt))
    expiry = datetime.datetime.fromisoformat(response['status']['expirationTimestamp'].replace('Z', '+00:00'))
    need(response['status']['token'].encode('ascii') == token and expiry > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1), 'retained source token expired; explicit successor required')
    review = call(['create', '--raw', '/apis/authentication.k8s.io/v1/tokenreviews', '-f', '-'],
                  dict(apiVersion='authentication.k8s.io/v1', kind='TokenReview', spec=dict(token=token.decode('ascii'))))
    check_review(review['status'], ns, account['metadata']['name'], uid)
    source_config = dict(apiVersion='v1', kind='Config', clusters=[dict(name='source', cluster=dict(server=endpoint, **{'certificate-authority': ca_pin['File']}))],
        users=[dict(name='source', user=dict(tokenFile=str(token_file)))], contexts=[dict(name='source', context=dict(cluster='source', user='source', namespace=ns))], **{'current-context': 'source'})
    source_config_file = records / 'source-api.kubeconfig.private.json'
    c.retain(source_config_file, c.encode(source_config))
    # Match production's typed REST calls. kubectl's generic -f validation
    # downloads OpenAPI schemas, a separate non-resource permission that this
    # source reader does not need. Keep RBAC unchanged and test the actual API.
    identity = call(['create', '--raw', '/apis/authentication.k8s.io/v1/selfsubjectreviews', '-f', '-'],
                    dict(apiVersion='authentication.k8s.io/v1', kind='SelfSubjectReview'), config=source_config_file)
    check_review(identity['status'], ns, account['metadata']['name'], uid)
    for selected_ns in namespaces[:2]:
        for group, resource in [('apis/apps/v1', 'deployments'), ('api/v1', 'pods'), ('api/v1', 'persistentvolumeclaims')]:
            call(['get', '--raw', '/' + group + '/namespaces/' + selected_ns + '/' + resource], config=source_config_file)
    provider_versions = {v['apiVersion'] for v in volumes['items'] if v['metadata']['namespace'] == provider_namespace}
    need(len(provider_versions) == 1 and next(iter(provider_versions)) in ('longhorn.io/v1beta1', 'longhorn.io/v1beta2'),
         'actual Longhorn API version required')
    call(['get', '--raw', '/apis/' + provider_versions.pop() + '/namespaces/' + provider_namespace + '/volumes'], config=source_config_file)
    need(call(['get', 'serviceaccount', account['metadata']['name'], '-o', 'json'])['metadata']['uid'] == uid, 'source account changed during reads')
    fragment = dict(version='p2-original-source-api-connection.v1', connection=dict(Purpose='source_api', Endpoint=endpoint, Account=uid,
        ServerUUID='', Database='', CA=ca_pin, Credential=dict(File=str(token_file), SHA256=c.digest(token)), IdentitySHA256='', ScopeSHA256=''),
        service_account=account['metadata']['name'], service_account_uid=uid, namespaces=namespaces, binding_uids=bindings,
        token_expires_unix=int(expiry.timestamp()), backup_ready=False)
    api_pin = c.retain(records / 'source-api-fragment.json', c.encode(fragment))
    print('P2_SOURCE_API_CONNECTION_READY', json.dumps(dict(fragment=api_pin, namespaces=namespaces, token_expires_unix=int(expiry.timestamp()), backup_ready=False)), flush=True)

    # Preserve actual configuration/layout DATA without projecting it as proof.
    layout['persistentvolumes'] = pv_objects
    layout['nodes'] = [call(['get', 'node', name, '-o', 'json']) for name in sorted(node_names)]
    for kind in ('storageclasses', 'volumesnapshotclasses'):
        layout[kind] = call(['get', kind, '-o', 'json'])
    layout['longhorn_volumes'] = volumes
    c.latest(records / 'source-layout.latest.private.json', c.encode(layout))
    observer = json.loads(c.private(c.WORK / 'fresh-backup-bootstrap/observer-pki.receipt.json'))
    print('P2_OBSERVER_VALIDITY', json.dumps({k: observer.get(k) for k in ('NotBefore', 'NotAfter')}), flush=True)
    controller = [d for d in layout[ns]['deployments']['items'] if d['metadata']['name'] == 'sbk-d4f51b83b57e-controller']
    need(len(controller) == 1, 'original controller deployment required')
    print('P2_CONTROLLER_LAYOUT', json.dumps(dict(deployment=controller[0]['metadata']['name'], uid=controller[0]['metadata']['uid'],
        containers=[dict(name=x['name'], env_names=[v['name'] for v in x.get('env', [])], mounts=x.get('volumeMounts', [])) for x in controller[0]['spec']['template']['spec']['containers']])), flush=True)

    # Use the existing installed native owner. Authenticate the pinned release
    # and bytes before and after copying, then let that owner authenticate SQL,
    # enrollment, administrator and the issuer key independently.
    app = call(['get', 'deployment', 'clawmanager-app', '-o', 'json'])
    need(app['metadata']['uid'] == APP_UID and all(x['image'] == APP_IMAGE for x in app['spec']['template']['spec']['containers']), 'installed App release drift')
    selector = ','.join(k + '=' + v for k, v in sorted(app['spec']['selector']['matchLabels'].items()))
    pods = call(['get', 'pods', '-l', selector, '-o', 'json'])['items']
    pod = next((p for p in pods if not p['metadata'].get('deletionTimestamp') and p['status'].get('phase') == 'Running'
                and len(p['status'].get('containerStatuses', [])) == 1
                and all(x.get('ready') and x.get('imageID', '').endswith(APP_IMAGE.split('@')[1]) for x in p['status'].get('containerStatuses', []))), None)
    need(pod is not None and len(pod['spec']['containers']) == 1, 'one ready installed App container required')
    refs = [r for r in pod['metadata'].get('ownerReferences', []) if r.get('controller') and r.get('kind') == 'ReplicaSet']
    need(len(refs) == 1, 'installed App ReplicaSet required')
    replica_set = call(['get', 'replicaset', refs[0]['name'], '-o', 'json'])
    app_owner_chain(pod, replica_set, app)
    exec_args = ['exec', pod['metadata']['name'], '-c', pod['spec']['containers'][0]['name'], '--']
    native_path = '/usr/local/bin/system-backup-original-enroll'
    def native_sha():
        result = subprocess.run(source.prefix + exec_args + ['sha256sum', native_path], capture_output=True, timeout=35, env=m.native_env())
        need(result.returncode == 0, 'installed native owner unavailable')
        value = result.stdout.split()[0].decode('ascii')
        need(len(value) == 64 and all(x in '0123456789abcdef' for x in value), 'installed owner hash malformed')
        return value
    sha = native_sha()
    binary = records / 'system-backup-original-enroll'
    if not binary.exists():
        with binary.open('xb') as out:
            os.chmod(binary, 0o700)
            result = subprocess.run(source.prefix + exec_args + ['cat', native_path], stdout=out, stderr=subprocess.PIPE, timeout=180, env=m.native_env())
        need(result.returncode == 0, 'native owner copy interrupted; retained file requires inspection')
    raw = c.private(binary, sha, maximum=128 << 20)
    need(raw[:6] == b'\x7fELF\x02\x01' and raw[18:20] == b'\x3e\x00' and native_sha() == sha, 'installed native ELF identity changed')
    after = call(['get', 'pod', pod['metadata']['name'], '-o', 'json'])
    need(after['metadata']['uid'] == pod['metadata']['uid'] and after['status']['containerStatuses'] == pod['status']['containerStatuses'],
         'installed owner source process replaced')
    app_owner_chain(after, replica_set, app)
    c.retain(records / 'native-owner.provenance.json', c.encode(dict(Pod=pod['metadata']['name'], PodUID=pod['metadata']['uid'], Image=APP_IMAGE, SHA256=sha)))
    output = records / 'runtime-issuers'
    manifest = output / 'original-runtime-issuers.json'
    sent = records / 'runtime-issuers.prepare.sent.json'
    common = owner.owner_arguments() + ['--dsn-sha256', '5234fbccc6a44e68bc7bdb10797ca4684e80cae42d32afd594ecb8d5c09c9e2d', '--output-directory', str(output)]
    if not manifest.exists():
        need(not sent.exists() and not output.exists(), 'native purpose-key prepare unconfirmed; retain original directory without replay')
        c.retain(sent, c.encode(dict(native_sha256=sha, output_directory=str(output))))
        args = [str(binary), 'runtime-issuers', '--mode', 'prepare', *common, '--source-issuer-private-file', str(owner.ENR / 'issuer.private')]
    else:
        pin = dict(File=str(manifest), SHA256=c.digest(c.private(manifest)))
        args = [str(binary), 'runtime-issuers', '--mode', 'query', *common, '--material-file', pin['File'], '--material-sha256', pin['SHA256']]
    result = subprocess.run(args, capture_output=True, timeout=160, env=m.native_env())
    c.latest(records / 'runtime-issuers.last.stdout.private', result.stdout or b'\n')
    c.latest(records / 'runtime-issuers.last.stderr.private', result.stderr or b'\n')
    need(result.returncode == 0, 'native purpose-key owner refused; retain private output without prepare replay')
    receipt = json.loads(result.stdout)
    need(receipt['Version'] == 'original-runtime-purpose-issuers-produced.v1' and receipt['GrantsIssued'] is False
         and receipt['ConfigurationMutated'] is False, 'unexpected native purpose-key receipt')
    c.private(Path(receipt['Material']['File']), receipt['Material']['SHA256'])
    c.retain(records / 'runtime-issuers.receipt.json', c.encode(receipt))
    print('P2_NATIVE_RUNTIME_ISSUERS_READY', json.dumps(dict(material=receipt['Material'], grants_issued=False, configuration_mutated=False, backup_ready=False)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper-directory', type=Path, required=True)
    parser.add_argument('--records-directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        main(args.helper_directory, args.records_directory)
    except Exception as error:
        raise SystemExit('P2_API_RUNTIME_INPUTS_UNCONFIRMED ' + str(error))
