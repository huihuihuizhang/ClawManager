#!/usr/bin/env python3
"""Read-only observations for the zhanghui08 deployment window; no installation."""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone


class Refused(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', default='kubernetes-admin@kubernetes')
    parser.add_argument('--namespace', default='clawmanager-zhanghui08-system')
    parser.add_argument('--namespace-uid', default='337cfe30-2c17-4b8e-b32a-760778b8098e')
    parser.add_argument('--app-deployment-uid', default='ed2c80de-9d24-4ca6-8f9c-877a990ac933')
    args = parser.parse_args()
    base = ['kubectl', '--context=' + args.context]
    ns = ['--namespace=' + args.namespace]
    report = dict(schema_version='supervisor-live-deployment-preflight.v1',
                  read_only=True, installation_authorization=False,
                  observed_at=datetime.now(timezone.utc).isoformat(),
                  context=args.context, namespace=args.namespace,
                  namespace_uid=args.namespace_uid, observations_atomic=False,
                  page_acceptance=False, dr_qualified=False)

    def call(argv, stage, limit=16 * 1024 * 1024):
        try:
            result = subprocess.run(base + argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused(stage + ':command_unavailable_or_timeout') from None
        if result.returncode or len(result.stdout) > limit:
            raise Refused(stage + ':command_failed_or_output_limit')
        return result.stdout

    def get(resource, name=None):
        tail = ['get', resource] + ([name] if name else []) + ['-o', 'json']
        try:
            return json.loads(call(ns + tail, 'get_' + resource))
        except (ValueError, TypeError):
            raise Refused('get_' + resource + ':invalid_json') from None

    def controller(obj):
        refs = [x for x in obj.get('metadata', {}).get('ownerReferences', [])
                if x.get('controller') is True]
        return refs[0] if len(refs) == 1 else None

    def pod_identity(pod):
        return dict(uid=pod['metadata']['uid'], node=pod.get('spec', {}).get('nodeName'),
                    phase=pod.get('status', {}).get('phase'),
                    deleting=bool(pod['metadata'].get('deletionTimestamp')),
                    containers=[dict(name=x.get('name'), image=x.get('image'),
                                     image_id=x.get('imageID'), container_id=x.get('containerID'),
                                     ready=x.get('ready'))
                                for x in pod.get('status', {}).get('containerStatuses', [])])

    try:
        actual_context = call(['config', 'current-context'], 'context', 4096).decode().strip()
        if actual_context != args.context:
            raise Refused('context_changed')
        namespace = get('namespace', args.namespace)
        if namespace['metadata']['uid'] != args.namespace_uid:
            raise Refused('namespace_identity_changed')
        deployments = get('deployments')['items']
        replicasets = get('replicasets')['items']
        pods = get('pods')['items']
        app = [x for x in deployments if x['metadata']['name'] == 'clawmanager-app']
        if len(app) != 1 or app[0]['metadata']['uid'] != args.app_deployment_uid:
            raise Refused('app_workload_identity_changed')
        report['deployments'] = [dict(name=x['metadata']['name'], uid=x['metadata']['uid'],
                                      replicas=x.get('spec', {}).get('replicas'),
                                      ready=x.get('status', {}).get('readyReplicas', 0),
                                      images=[c['image'] for c in x['spec']['template']['spec']['containers']])
                                 for x in deployments]
        report['pods'] = [dict(name=p['metadata']['name'], **pod_identity(p)) for p in pods]
        versions = []
        for deployment_name, program in [('mysql', 'mysqld'), ('minio', 'minio'),
                                          ('clawmanager-team-redis', 'redis-server'),
                                          ('sbk-transit-zh-977a1b9a', 'vault')]:
            matching = [d for d in deployments if d['metadata']['name'] == deployment_name]
            if len(matching) != 1:
                versions.append(dict(deployment=deployment_name, status='not_observed'))
                continue
            deployment = matching[0]
            rs_uids = {r['metadata']['uid'] for r in replicasets
                       if controller(r) and controller(r).get('kind') == 'Deployment'
                       and controller(r).get('uid') == deployment['metadata']['uid']}
            selected = [p for p in pods if controller(p)
                        and controller(p).get('kind') == 'ReplicaSet'
                        and controller(p).get('uid') in rs_uids
                        and p.get('status', {}).get('phase') == 'Running'
                        and not p['metadata'].get('deletionTimestamp')]
            if len(selected) != 1 or len(selected[0]['spec']['containers']) != 1:
                versions.append(dict(deployment=deployment_name, status='ambiguous_live_container'))
                continue
            pod = selected[0]
            before = pod_identity(pod)
            container_name = pod['spec']['containers'][0]['name']
            status = [c for c in before['containers'] if c['name'] == container_name]
            if len(status) != 1 or not status[0]['ready'] or not status[0]['image_id']:
                versions.append(dict(deployment=deployment_name, status='container_not_ready'))
                continue
            try:
                raw = call(ns + ['exec', pod['metadata']['name'], '-c', container_name,
                                 '--', program, '--version' if program != 'vault' else 'version'],
                           'version_' + deployment_name, 8192)
                after = get('pod', pod['metadata']['name'])
                current_deployment = get('deployment', deployment_name)
                if pod_identity(after) != before or current_deployment['metadata']['uid'] != deployment['metadata']['uid']:
                    raise Refused('version_' + deployment_name + ':identity_changed')
                value = raw.decode('utf-8', errors='strict').strip()
                if any(ord(c) < 32 and c not in '\n\t' for c in value):
                    raise Refused('version_' + deployment_name + ':unexpected_output')
                versions.append(dict(deployment=deployment_name, pod_uid=before['uid'],
                                     image_id=status[0]['image_id'], version=value,
                                     output_sha256=hashlib.sha256(raw).hexdigest(), status='observed'))
            except (Refused, UnicodeError) as error:
                versions.append(dict(deployment=deployment_name, status='unavailable',
                                     reason=str(error) if isinstance(error, Refused) else 'invalid_encoding'))
        report['versions'] = versions
        if get('namespace', args.namespace)['metadata']['uid'] != args.namespace_uid:
            raise Refused('namespace_identity_changed_after_read')
        if get('deployment', 'clawmanager-app')['metadata']['uid'] != args.app_deployment_uid:
            raise Refused('app_workload_identity_changed_after_read')
        report['status'] = 'OBSERVATIONS_ONLY_NOT_INSTALLATION_OR_SCHEDULER_ACCEPTANCE'
    except (Refused, KeyError, TypeError) as error:
        report['status'] = 'refused'
        report['reason'] = str(error) if isinstance(error, Refused) else 'unexpected_kubernetes_response'
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
