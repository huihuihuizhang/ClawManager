#!/usr/bin/env python3
"""Read instance 2's current source identity and tenant mount graph; no mutation."""
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NS = 'clawmanager-sbk-validation-system'
TENANT = 'clawmanager-sbk-validation-user-1'
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'
SELECTION = {'File': '/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-20261113-provider-loaded/source-selection.json',
             'SHA256': 'e868971899c29149296d3a11b5d5fb2063cf7c4994800b770bafa2b434dcf79e'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def emit(label, value):
    print(label, json.dumps(value, ensure_ascii=True), flush=True)


def clean_root(value):
    return isinstance(value, str) and value.startswith('/') and value != '/' and not value.startswith('//') and posixpath.normpath(value) == value and not any(c in value for c in '\\\0\r\n:')


def clean_subpath(value):
    return value == '' or (isinstance(value, str) and not value.startswith('/') and posixpath.normpath(value) == value and value not in ('.', '..') and not value.startswith('../') and not any(c in value for c in '\\\0\r\n:'))


def mount_report(pod, workspace):
    """Expose the existing nil-declaration coverage constraints without granting them."""
    spec = pod['spec']; entries = spec.get('volumes', [])
    volumes = {v.get('name'): v for v in entries}
    issues, rows, primary = [], [], set()
    if len(volumes) != len(entries) or not all(volumes):
        issues.append('volume_names')
    if spec.get('ephemeralContainers'):
        issues.append('ephemeral_containers')
    if not clean_root(workspace):
        issues.append('workspace_path')
    for container in spec.get('containers', []) + spec.get('initContainers', []):
        if container.get('volumeDevices'):
            issues.append('block_device')
        paths = set()
        for mount in container.get('volumeMounts', []):
            volume = volumes.get(mount.get('name'), {})
            path = mount.get('mountPath', '')
            keys = set(volume) - {'name'}
            persistent = bool(keys & {'persistentVolumeClaim', 'hostPath', 'nfs'})
            transient = bool(keys) and keys <= {'emptyDir', 'configMap', 'secret', 'projected', 'downwardAPI'}
            covered = bool(workspace) and (workspace == path or workspace.startswith(path + '/'))
            subpath = mount.get('subPath', '')
            relative = posixpath.relpath(workspace, path) if covered else ''
            derived = subpath if relative == '.' else posixpath.join(subpath, relative)
            valid = covered and clean_root(path) and not mount.get('subPathExpr') and clean_subpath(subpath) and clean_subpath(derived)
            claim = volume.get('persistentVolumeClaim', {}).get('claimName', '')
            if not volume or path in paths:
                issues.append('missing_volume_or_duplicate_path')
            paths.add(path)
            if transient:
                if path == workspace or path.startswith(workspace + '/'):
                    issues.append('workspace_overlay')
                continue
            reasons = []
            if not persistent or not clean_root(path) or mount.get('subPathExpr'):
                reasons.append('unsupported_storage_or_path')
            if persistent and not covered:
                reasons.append('additional_persistent_mount')
            if persistent and (not valid or not claim):
                reasons.append('tenant_primary_mount_mismatch')
            issues.extend(reasons)
            if valid and claim:
                primary.add((claim, derived))
            rows.append({'Container': container.get('name'), 'Volume': mount.get('name'), 'Claim': claim,
                         'WorkspaceCovered': covered, 'ValidWorkspaceSubPath': valid, 'ReadOnly': mount.get('readOnly', False),
                         'StorageKinds': sorted(keys), 'Issues': reasons})
    if len(primary) != 1:
        issues.append('primary_claim_ambiguous_or_missing')
    return {'Issues': sorted(set(issues)), 'Mounts': rows, 'PrimaryClaimCount': len({p[0] for p in primary}),
            'PrimaryMappingCount': len(primary)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    need(os.name == 'posix', 'Linux operator required'); os.umask(0o077)
    spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
    selected = A.obj(SELECTION); core = A.obj(selected['Deployment'])
    now = dt.datetime.now(dt.timezone.utc)
    need(dt.datetime.fromisoformat(selected['NotBefore'].replace('Z', '+00:00')) <= now < dt.datetime.fromisoformat(selected['Until'].replace('Z', '+00:00')), 'source window expired')
    prior = ROOT / 'longhorn-source-20261113-provider-loaded-shared-protocol-repair'
    need(A.decode((prior/'native.exit.json').read_bytes()) == {'ExitCode': 1}, 'prior refusal required')
    refusal = A.decode((prior/'native.stdout.private').read_bytes())
    need(all(refusal.get(k) == v for k, v in {'Status': 'original_mount_author_refused', 'Phase': 'native_writers', 'Step': 'native_tenant_pro', 'Kind': 'Instance', 'Reason': 'read_error', 'InstanceID': 2}.items()), 'instance 2 tenant refusal required')
    need(A.decode((prior/'native.sent.private.json').read_bytes())['SourceSelection'] == SELECTION, 'source pin differs')
    records = Path(tempfile.mkdtemp(prefix='tenant-pro-readback-', dir=ROOT))
    print('TENANT_PRO_RECORDS', records, flush=True)
    emit('TENANT_PRO_SOURCE', {'UTCNow': now.isoformat(), 'Until': selected['Until'], 'InstanceID': 2})
    sqls = [v for v in selected['Connections'] if v['Purpose'] == 'source_sql']; need(len(sqls) == 1, 'one SQL source required')
    sql = sqls[0]; ca = A.read(sql['CA']); dsn = A.read(sql['Credential']).decode().strip()
    creds, sep, address = dsn.rpartition('@tcp('); user, colon, password = creds.partition(':')
    host, end, tail = address.partition(')/'); database = tail.split('?', 1)[0]; peer = urllib.parse.urlsplit(sql['Endpoint'])
    need(sep and colon and end and host == peer.netloc and database == sql['Database'] and sql['Account'].startswith(user+'@') and user.lower() != 'root' and not any(c in password for c in '\r\n\0'), 'source SQL credential shape differs')
    shell = '''set -eu
IFS= read -r MYSQL_PWD
export MYSQL_PWD
IFS= read -r ca
umask 077
f=$(mktemp /tmp/sbk-tenant-read-ca.XXXXXX)
trap 'rm -f -- "$f"' EXIT HUP INT TERM
printf '%s' "$ca" | base64 -d > "$f"
mysql --protocol=TCP --connect-timeout=8 --ssl-mode=VERIFY_IDENTITY --tls-version=TLSv1.3 --ssl-ca="$f" -h "$1" -P "$2" -u "$3" --database="$4" --batch --skip-column-names --raw -e "$5"
'''
    query = """SET SESSION TRANSACTION READ ONLY; START TRANSACTION;
SELECT JSON_OBJECT('account',CURRENT_USER(),'role_none',CURRENT_ROLE()='NONE','database',DATABASE(),'server',@@server_uuid);
SELECT JSON_OBJECT('ID',id,'UserID',user_id,'Mode',instance_mode,'Type',type,'Backend',runtime_type,'OS',os_type,'Status',status,'Generation',runtime_generation,'Pod',COALESCE(pod_name,''),'Namespace',COALESCE(pod_namespace,''),'Workspace',COALESCE(workspace_path,'')) FROM instances WHERE id=2;
COMMIT;"""
    result = subprocess.run(['kubectl', '--kubeconfig', KUBE, '--request-timeout=20s', '-n', NS, 'exec', '-i', 'deployment/mysql', '-c', 'mysql', '--', 'sh', '-c', shell, 'sbk-readonly', peer.hostname, str(peer.port or 3306), user, database, query],
                            input=password.encode()+b'\n'+base64.b64encode(ca)+b'\n', capture_output=True, timeout=45)
    A.retain(records/'sql.stdout.private', result.stdout or b'\n'); A.retain(records/'sql.stderr.private', result.stderr or b'\n')
    need(result.returncode == 0 and len(result.stdout.splitlines()) == 2, 'source SQL read refused')
    identity, source = [A.decode(v) for v in result.stdout.splitlines()]
    need(identity == {'account': sql['Account'], 'role_none': 1, 'database': sql['Database'], 'server': sql['ServerUUID']}, 'SQL identity differs')
    need(source['ID'] == 2 and source['UserID'] == 1 and source['Mode'] == 'pro' and source['Status'] == 'running' and source['Namespace'] == TENANT and source['Pod'], 'current tenant source differs')
    emit('TENANT_PRO_SQL', {**{k: source[k] for k in ('ID', 'UserID', 'Mode', 'Type', 'Backend', 'OS', 'Status', 'Generation')}, 'WorkspaceAbsoluteClean': clean_root(source['Workspace'])})
    apis = [v for v in selected['Connections'] if v['Purpose'] == 'source_api']; need(len(apis) == 1, 'one API source required')
    api = apis[0]; api_ca = A.read(api['CA']); token = A.read(api['Credential']).decode().strip()
    endpoint = urllib.parse.urlsplit(api['Endpoint'])
    need(endpoint.scheme == 'https' and endpoint.hostname and not endpoint.username and not endpoint.query and not endpoint.fragment and endpoint.path in ('', '/') and token and not any(c in token for c in '\r\n\0'), 'source API endpoint differs')
    context = ssl.create_default_context(cadata=api_ca.decode()); context.minimum_version = ssl.TLSVersion.TLSv1_3
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    reads = []
    def get(path):
        try:
            req = urllib.request.Request(api['Endpoint'].rstrip('/')+path, headers={'Authorization': 'Bearer '+token}, method='GET')
            with opener.open(req, timeout=15) as response:
                raw = response.read((8 << 20)+1)
                need(response.status == 200 and 0 < len(raw) <= 8 << 20, 'bounded API success required')
            value = A.decode(raw); A.retain(records/('api-%02d.private.json' % len(reads)), raw)
            reads.append((path, value)); return value
        except urllib.error.HTTPError as error:
            emit('TENANT_PRO_API_REFUSED', {'Path': path, 'Status': error.code}); raise ValueError('API read refused') from None
        except Exception as error:
            emit('TENANT_PRO_API_ERROR', {'Path': path, 'Type': type(error).__name__}); raise
    q = lambda value: urllib.parse.quote(value, safe='')
    prefix = '/api/v1/namespaces/'+TENANT
    ns = get(prefix); pod = get(prefix+'/pods/'+q(source['Pod']))
    def owner(obj, kind):
        refs = [v for v in obj['metadata'].get('ownerReferences', []) if v.get('controller')]
        need(len(refs) == 1 and refs[0]['apiVersion'] == 'apps/v1' and refs[0]['kind'] == kind, 'owner chain shape differs')
        return refs[0]
    pod_ref = owner(pod, 'ReplicaSet'); rs = get('/apis/apps/v1/namespaces/'+TENANT+'/replicasets/'+q(pod_ref['name']))
    rs_ref = owner(rs, 'Deployment'); dep = get('/apis/apps/v1/namespaces/'+TENANT+'/deployments/'+q(rs_ref['name']))
    labels = {'app': 'clawreef', 'managed-by': 'clawreef', 'user-id': '1', 'instance-id': '2'}
    for name, obj, values in [('Namespace', ns, ns['metadata'].get('labels', {})), ('Pod', pod, pod['metadata'].get('labels', {})), ('ReplicaSet', rs, rs['spec']['template']['metadata'].get('labels', {})), ('Deployment', dep, dep['spec']['template']['metadata'].get('labels', {}))]:
        emit('TENANT_PRO_OBJECT', {'Kind': name, 'UIDPresent': bool(obj['metadata'].get('uid')), 'Deleting': bool(obj['metadata'].get('deletionTimestamp')),
                                  'LabelMatches': {k: values.get(k) == v for k, v in labels.items() if name != 'Namespace' or k != 'instance-id'}})
    emit('TENANT_PRO_OWNER', {'ReplicaSetUIDMatches': rs['metadata']['uid'] == pod_ref['uid'], 'DeploymentUIDMatches': dep['metadata']['uid'] == rs_ref['uid'],
         'PodRunning': pod.get('status', {}).get('phase') == 'Running', 'Replicas': dep['spec'].get('replicas'), 'NodePresent': bool(pod['spec'].get('nodeName'))})
    emit('TENANT_PRO_MOUNT_CHECKS', mount_report(pod, source['Workspace']))
    for claim_name in sorted({v['persistentVolumeClaim']['claimName'] for v in pod['spec'].get('volumes', []) if 'persistentVolumeClaim' in v}):
        claim = get(prefix+'/persistentvolumeclaims/'+q(claim_name)); volume = claim['spec'].get('volumeName')
        need(volume, 'unbound claim'); pv = get('/api/v1/persistentvolumes/'+q(volume)); ref = pv['spec'].get('claimRef', {})
        emit('TENANT_PRO_VOLUME', {'Claim': claim_name, 'ClaimUIDPresent': bool(claim['metadata'].get('uid')), 'ClaimDeleting': bool(claim['metadata'].get('deletionTimestamp')),
             'Bound': claim.get('status', {}).get('phase') == 'Bound', 'AccessModes': claim['spec'].get('accessModes'), 'PVUIDPresent': bool(pv['metadata'].get('uid')),
             'PVDeleting': bool(pv['metadata'].get('deletionTimestamp')), 'LonghornCSI': pv['spec'].get('csi', {}).get('driver') == 'driver.longhorn.io',
             'ClaimRefMatches': ref.get('namespace') == TENANT and ref.get('name') == claim_name and ref.get('uid') == claim['metadata']['uid']})
    node_name = pod['spec'].get('nodeName'); need(node_name, 'pod node missing')
    node = get('/api/v1/nodes/'+q(node_name))
    emit('TENANT_PRO_NODE', {'Name': node_name, 'UIDMatches': core['worker_security'].get('node_uids', {}).get(node_name) == node['metadata'].get('uid'),
         'Deleting': bool(node['metadata'].get('deletionTimestamp')), 'Linux': node['metadata'].get('labels', {}).get('kubernetes.io/os') == 'linux'})
    for path, original in list(reads):
        current = get(path)
        emit('TENANT_PRO_RECHECK', {'Kind': original.get('kind'), 'UIDMatches': current['metadata'].get('uid') == original['metadata'].get('uid'),
             'SpecMatches': current.get('spec') == original.get('spec'), 'LabelsMatch': current['metadata'].get('labels') == original['metadata'].get('labels'),
             'OwnersMatch': current['metadata'].get('ownerReferences') == original['metadata'].get('ownerReferences'), 'Deleting': bool(current['metadata'].get('deletionTimestamp'))})
    print('TENANT_PRO_READONLY_DIAGNOSTIC_FINISHED', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('TENANT_PRO_DIAGNOSTIC_UNCONFIRMED '+type(error).__name__)
