#!/usr/bin/env python3
"""Read-only, namespace-pinned metadata and exact-container MinIO version.

No Secret/ConfigMap body, literal env value, args, logs, token or password is
requested in kubectl output. No resource, policy or object is changed. This is
prerequisite collection, not provider permission or backup acceptance evidence.
"""
import itertools
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

CONTEXT = "kubernetes-admin@kubernetes"
NAMESPACE = "clawmanager-zhanghui08-system"
NAMESPACE_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
DEPLOYMENT = SERVICE = CONTAINER = "minio"
MAX_OUTPUT = 512 * 1024
PUBLICATION_ENV = (
    "SYSTEM_BACKUP_PUBLICATION_TARGET_FILE",
    "SYSTEM_BACKUP_PUBLICATION_TARGET_SHA256",
    "SYSTEM_BACKUP_PUBLICATION_SIGNERS_FILE",
    "SYSTEM_BACKUP_PUBLICATION_SIGNERS_SHA256",
    "SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE",
    "SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256",
)
PURPOSES = ("artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append")
_template_ids = itertools.count()


class Refused(Exception):
    """Fixed diagnostic codes only; never include tool output."""


def _q(expression):
    rendered = '{{printf "%q" (printf "%v" .)}}'
    for part in reversed(expression.lstrip('.').split('.')):
        rendered = '{{with .' + part + '}}' + rendered + '{{else}}""{{end}}'
    return rendered


def _number(expression):
    rendered = '{{.}}'
    for part in reversed(expression.lstrip('.').split('.')):
        rendered = '{{with .' + part + '}}' + rendered + '{{else}}0{{end}}'
    return rendered


def _boolean(expression):
    rendered = 'true'
    for part in reversed(expression.lstrip('.').split('.')):
        rendered = '{{with .' + part + '}}' + rendered + '{{else}}false{{end}}'
    return rendered


def _object(**fields):
    return '{' + ','.join(json.dumps(k) + ':' + v for k, v in fields.items()) + '}'


def _array(expression, body, condition=None):
    sep = '$comma' + str(next(_template_ids))
    selected = '{{' + sep + '}}{{' + sep + ' = ","}}' + body
    if condition:
        selected = '{{if ' + condition + '}}' + selected + '{{end}}'
    parts = expression.lstrip('.').split('.')
    rendered = '[{{' + sep + ' := ""}}{{range .' + parts[-1] + '}}' + selected + '{{end}}]'
    for part in reversed(parts[:-1]):
        rendered = '{{with .' + part + '}}' + rendered + '{{else}}[]{{end}}'
    return rendered


def _meta():
    return dict(name=_q('.metadata.name'), uid=_q('.metadata.uid'),
                namespace=_q('.metadata.namespace'), deleting=_boolean('.metadata.deletionTimestamp'))


def _owners():
    return _array('.metadata.ownerReferences', _object(
        kind=_q('.kind'), name=_q('.name'), uid=_q('.uid'), controller=_boolean('.controller')))


def _containers(expression):
    env = _array('.env', _object(
        name=_q('.name'), secret=_q('.valueFrom.secretKeyRef.name'),
        configmap=_q('.valueFrom.configMapKeyRef.name')))
    return _array(expression, _object(
        name=_q('.name'), image=_q('.image'),
        ports=_array('.ports', _object(name=_q('.name'), port=_number('.containerPort'), protocol=_q('.protocol'))),
        env_references=env,
        env_from=_array('.envFrom', _object(secret=_q('.secretRef.name'), configmap=_q('.configMapRef.name'))),
        mounts=_array('.volumeMounts', _object(name=_q('.name'), path=_q('.mountPath'), readonly=_boolean('.readOnly')))))


def _volumes(expression):
    return _array(expression, _object(
        name=_q('.name'), secret=_q('.secret.secretName'), configmap=_q('.configMap.name'),
        pvc=_q('.persistentVolumeClaim.claimName'),
        projected=_array('.projected.sources', _object(
            secret=_q('.secret.name'), configmap=_q('.configMap.name'),
            service_account_token_projection=_boolean('.serviceAccountToken')))))


NS_TEMPLATE = _object(**_meta())
DEPLOYMENT_ITEM = _object(**_meta(), generation=_number('.metadata.generation'),
    observed_generation=_number('.status.observedGeneration'), replicas=_number('.spec.replicas'),
    app_selector=_q('.spec.selector.matchLabels.app'),
    service_account=_q('.spec.template.spec.serviceAccountName'),
    containers=_containers('.spec.template.spec.containers'), volumes=_volumes('.spec.template.spec.volumes'))
DEPLOYMENTS_TEMPLATE = '{{if gt (len .items) 32}}null{{else}}' + _array('.items', DEPLOYMENT_ITEM) + '{{end}}'
RS_TEMPLATE = '{{if gt (len .items) 16}}null{{else}}' + _array('.items', _object(**_meta(), owners=_owners())) + '{{end}}'
POD_ITEM = _object(**_meta(), owners=_owners(), phase=_q('.status.phase'),
    service_account=_q('.spec.serviceAccountName'), node=_q('.spec.nodeName'),
    containers=_containers('.spec.containers'), volumes=_volumes('.spec.volumes'),
    statuses=_array('.status.containerStatuses', _object(
        name=_q('.name'), image_id=_q('.imageID'), container_id=_q('.containerID'),
        ready=_boolean('.ready'), running=_boolean('.state.running'),
        restarts=_number('.restartCount'))))
PODS_TEMPLATE = '{{if gt (len .items) 16}}null{{else}}' + _array('.items', POD_ITEM) + '{{end}}'
SA_TEMPLATE = _object(**_meta())
SERVICE_TEMPLATE = _object(**_meta(), app_selector=_q('.spec.selector.app'),
    service_type=_q('.spec.type'), cluster_ip=_q('.spec.clusterIP'),
    ports=_array('.spec.ports', _object(name=_q('.name'), port=_number('.port'),
        target_port=_q('.targetPort'), protocol=_q('.protocol'), app_protocol=_q('.appProtocol'))))


def _bounded_tree(value, depth=0):
    if depth > 16:
        raise Refused('metadata_shape_limit')
    if isinstance(value, str):
        if len(value) > 2048 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise Refused('metadata_string_shape')
    elif isinstance(value, list):
        if len(value) > 128:
            raise Refused('metadata_list_limit')
        for item in value:
            _bounded_tree(item, depth + 1)
    elif isinstance(value, dict):
        if len(value) > 32:
            raise Refused('metadata_object_limit')
        for key, item in value.items():
            _bounded_tree(key, depth + 1)
            _bounded_tree(item, depth + 1)
    elif value is not None and not isinstance(value, (bool, int)):
        raise Refused('metadata_scalar_shape')


class Collector:
    def __init__(self, runner=subprocess.run):
        self.runner = runner
        self.deadline = time.monotonic() + 180

    def _command(self, arguments):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Refused('collection_deadline')
        command = ['kubectl', '--context=' + CONTEXT, '--request-timeout=15s', *arguments]
        try:
            result = self.runner(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=min(25, remaining), check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused('kubectl_unavailable_or_timeout') from None
        if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT:
            raise Refused('bounded_kubectl_read_failed')
        # stderr is discarded, never captured, parsed or printed.
        return result.stdout

    def _get(self, resource, template, *, name=None, selector=False, cluster=False):
        arguments = [] if cluster else ['--namespace=' + NAMESPACE]
        arguments += ['get', resource]
        if name is not None:
            if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', name):
                raise Refused('metadata_name_shape')
            arguments.append(name)
        if selector:
            arguments += ['--selector=app=minio']
        arguments += ['-o', 'go-template=' + template]
        try:
            value = json.loads(self._command(arguments))
        except (ValueError, UnicodeError):
            raise Refused('projected_metadata_json_invalid') from None
        _bounded_tree(value)
        return value

    def namespace(self):
        ns = self._get('namespace', NS_TEMPLATE, name=NAMESPACE, cluster=True)
        if not isinstance(ns, dict) or ns.get('name') != NAMESPACE or ns.get('uid') != NAMESPACE_UID or ns.get('deleting'):
            raise Refused('namespace_identity_changed')
        return ns

    @staticmethod
    def _items(items, maximum):
        if not isinstance(items, list) or len(items) > maximum:
            raise Refused('resource_list_shape_or_limit')
        for item in items:
            if not isinstance(item, dict) or item.get('namespace') != NAMESPACE or not item.get('uid'):
                raise Refused('resource_namespace_or_uid_changed')
        return items

    @staticmethod
    def _owned(item, kind, uid):
        owners = [o for o in item.get('owners', []) if o.get('controller')]
        return len(owners) == 1 and owners[0].get('kind') == kind and owners[0].get('uid') == uid

    @staticmethod
    def _fingerprint(pod):
        statuses = [s for s in pod.get('statuses', []) if s.get('name') == CONTAINER]
        containers = [c for c in pod.get('containers', []) if c.get('name') == CONTAINER]
        if pod.get('namespace') != NAMESPACE or pod.get('deleting') or pod.get('phase') != 'Running' or len(statuses) != 1 or len(containers) != 1:
            raise Refused('exact_minio_container_unavailable')
        status = statuses[0]
        if not status.get('running') or not status.get('ready') or not status.get('image_id') or not status.get('container_id'):
            raise Refused('exact_minio_container_unavailable')
        return (pod.get('uid'), pod.get('service_account'), containers[0].get('image'),
                status['image_id'], status['container_id'], status.get('restarts'))

    def version(self, pod):
        self.namespace()
        before = self._get('pod', POD_ITEM, name=pod['name'])
        expected = self._fingerprint(pod)
        if self._fingerprint(before) != expected:
            raise Refused('minio_container_changed_before_exec')
        raw = self._command(['--namespace=' + NAMESPACE, 'exec', 'pod/' + pod['name'],
                             '--container=' + CONTAINER, '--', 'minio', '--version'])
        # kubectl exec offers no atomic UID precondition. Recheck the original
        # Pod/container identity afterwards and discard version on any change.
        self.namespace()
        after = self._get('pod', POD_ITEM, name=pod['name'])
        if self._fingerprint(after) != expected:
            raise Refused('minio_container_changed_during_exec')
        try:
            lines = raw.decode('utf-8', 'strict').splitlines()
        except UnicodeError:
            raise Refused('version_output_shape_unknown') from None
        matches = []
        for line in lines:
            match = re.fullmatch(r'minio version ((?:RELEASE|DEVELOPMENT)\.[A-Za-z0-9._:+-]{1,96}) \(commit-id=([0-9a-f]{7,64})\)', line)
            if match:
                matches.append(match)
        if len(matches) != 1:
            raise Refused('version_output_shape_unknown')
        return {'status': 'observed', 'version': matches[0][1], 'commit_id': matches[0][2],
                'container_identity_checked_before_and_after': True,
                'atomic_exec_uid_precondition': False}

    def collect(self):
        report = {'schema_version': 'system-backup-minio-prerequisites.v1',
                  'context': CONTEXT, 'namespace': NAMESPACE, 'namespace_uid': NAMESPACE_UID,
                  'observed_at_utc': datetime.now(timezone.utc).isoformat(),
                  'provider_permissions': 'unknown', 'tls_verified': False,
                  'admin_api_profile': 'unknown_requires_version_matched_adapter',
                  'principal_material_sources': {p: {'status': 'unknown', 'reason': 'principal_binding_and_authority_contents_not_read'} for p in PURPOSES}}
        self.namespace()
        deployments = self._items(self._get('deployments', DEPLOYMENTS_TEMPLATE), 32)
        selected = [d for d in deployments if d.get('name') == DEPLOYMENT and not d.get('deleting')]
        if len(selected) != 1 or selected[0].get('app_selector') != 'minio':
            raise Refused('exact_minio_deployment_unavailable')
        deployment = selected[0]
        report['deployment'] = deployment
        report['publication_configuration_signals'] = [
            {'deployment': d['name'], 'deployment_uid': d['uid'], 'container': c['name'],
             'declared_env_name': e['name'], 'secret_reference': e.get('secret', ''),
             'configmap_reference': e.get('configmap', ''), 'material_contents_verified': False}
            for d in deployments for c in d.get('containers', []) for e in c.get('env_references', [])
            if e.get('name') in PUBLICATION_ENV]
        report['configuration_reference_candidates'] = [
            {'deployment': d['name'], 'deployment_uid': d['uid'], 'volume_references': d.get('volumes', []),
             'containers': [{'name': c['name'], 'env_from_references': c.get('env_from', []),
                             'mounts': c.get('mounts', [])} for c in d.get('containers', [])]}
            for d in deployments]
        report['configuration_source_search_scope'] = 'reference names/mount metadata and allowlisted locator env names only; args and material bodies not inspected; absence is unknown'
        replicasets = self._items(self._get('replicasets', RS_TEMPLATE, selector=True), 16)
        owned_rs = {r['uid'] for r in replicasets if not r.get('deleting') and self._owned(r, 'Deployment', deployment['uid'])}
        pods = self._items(self._get('pods', PODS_TEMPLATE, selector=True), 16)
        candidates = [p for p in pods if any(self._owned(p, 'ReplicaSet', uid) for uid in owned_rs)
                      and not p.get('deleting') and p.get('phase') == 'Running']
        report['minio_pods'] = candidates
        if len(candidates) != 1:
            raise Refused('minio_pod_selection_ambiguous_or_missing')
        pod = candidates[0]
        self._fingerprint(pod)
        sa = self._get('serviceaccount', SA_TEMPLATE, name=pod['service_account'])
        if sa.get('namespace') != NAMESPACE or sa.get('name') != pod['service_account'] or not sa.get('uid') or sa.get('deleting'):
            raise Refused('service_account_identity_unavailable')
        report['service_account'] = sa
        service = self._get('service', SERVICE_TEMPLATE, name=SERVICE)
        if service.get('namespace') != NAMESPACE or service.get('name') != SERVICE or not service.get('uid') or service.get('deleting') or service.get('app_selector') != 'minio':
            raise Refused('exact_minio_service_unavailable')
        for port in service.get('ports', []):
            if type(port.get('port')) is not int or not 1 <= port['port'] <= 65535:
                raise Refused('service_port_shape')
        report['service'] = service
        report['endpoint_candidates'] = [{'host': SERVICE + '.' + NAMESPACE + '.svc',
            'port': p['port'], 'port_name': p['name'], 'scheme': 'unknown', 'reachability': 'not_tested'} for p in service.get('ports', [])]
        report['tls_mount_candidates'] = [m for c in pod.get('containers', []) if c.get('name') == CONTAINER
            for m in c.get('mounts', []) if any(tag in (m.get('name', '') + '/' + m.get('path', '')).lower() for tag in ('tls', 'cert'))]
        report['tls_mount_interpretation'] = 'candidate metadata only; certificate contents, termination and transport not checked'
        try:
            report['minio_version'] = self.version(pod)
        except Refused as exc:
            if str(exc) not in ('bounded_kubectl_read_failed', 'kubectl_unavailable_or_timeout', 'version_output_shape_unknown'):
                raise
            report['minio_version'] = {'status': 'unknown', 'reason': str(exc)}
            report['status'] = 'prerequisites_observed_version_unknown'
            return report
        report['status'] = 'prerequisites_observed_not_permission_or_backup_acceptance'
        return report


def main():
    if len(sys.argv) != 1:
        print(json.dumps({'status': 'refused', 'reason': 'no_cli_overrides_allowed'}))
        return 2
    try:
        report = Collector().collect()
    except Refused as exc:
        # Exceptions contain our fixed codes only; never kubectl stderr/output.
        print(json.dumps({'schema_version': 'system-backup-minio-prerequisites.v1',
            'context': CONTEXT, 'namespace': NAMESPACE, 'namespace_uid': NAMESPACE_UID,
            'status': 'refused', 'reason': str(exc), 'provider_permissions': 'unknown'}))
        return 2
    except Exception:
        print(json.dumps({'status': 'refused', 'reason': 'unexpected_collection_shape', 'provider_permissions': 'unknown'}))
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 0 if report['minio_version']['status'] == 'observed' else 1


if __name__ == '__main__':
    sys.exit(main())
