"""Offline source tests; never kubectl, MinIO, SSH, SQL or provider acceptance.

The projection test uses local Go text/template (stdlib only) to exercise the
actual kubectl templates. Its Go source/cache live in a TemporaryDirectory and
are removed on exit, including failure. The user-facing collector needs only
Python 3 and kubectl; Go is a root-side test dependency only.
"""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).with_name('system-backup-c-minio-prerequisites.py')
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('minio_prerequisites', PATH)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
CANARY = 'FIXTURE_SECRET_VALUE_NEVER_PRINT'


def meta(name, uid):
    return dict(name=name, uid=uid, namespace=tool.NAMESPACE, deleting=False)


def fixture():
    container = dict(name='minio', image='registry.invalid/minio@sha256:' + '1' * 64,
        ports=[dict(name='api', port=9000, protocol='TCP')],
        env_references=[dict(name='MINIO_ROOT_PASSWORD', secret='original-secret-name', configmap='')],
        env_from=[], mounts=[dict(name='minio-tls', path='/root/.minio/certs', readonly=True)])
    deployment = dict(**meta('minio', 'original-deployment'), generation=2, observed_generation=2,
        replicas=1, app_selector='minio', service_account='minio-observer-sa',
        containers=[copy.deepcopy(container)], volumes=[])
    platform = dict(**meta('original-platform', 'original-platform-uid'), containers=[dict(
        name='platform', env_references=[dict(name='SYSTEM_BACKUP_PUBLICATION_TARGET_FILE',
        secret='', configmap='original-publication-materials')])])
    rs = dict(**meta('original-minio-rs', 'original-rs'), owners=[dict(
        kind='Deployment', name='minio', uid=deployment['uid'], controller=True)])
    pod = dict(**meta('original-minio-pod', 'original-pod'), owners=[dict(
        kind='ReplicaSet', name=rs['name'], uid=rs['uid'], controller=True)],
        phase='Running', service_account='original-minio-sa', node='original-node',
        containers=[copy.deepcopy(container)], volumes=[], statuses=[dict(
        name='minio', image_id='containerd://sha256:' + '2' * 64,
        container_id='containerd://original-container', ready=True, running=True, restarts=0)])
    return dict(namespace=dict(**meta(tool.NAMESPACE, tool.NAMESPACE_UID)),
        deployments=[deployment, platform], replicasets=[rs], pods=[pod], pod=pod,
        serviceaccount=meta(pod['service_account'], 'original-sa-uid'),
        service=dict(**meta('minio', 'original-service'), app_selector='minio', service_type='ClusterIP',
        cluster_ip='10.0.0.9', ports=[dict(name='api', port=9000, target_port='9000', protocol='TCP', app_protocol='')]))


class FakeKubectl:
    def __init__(self, data=None):
        self.data = data or fixture()
        self.calls = []
        self.namespace_reads = self.pod_reads = 0
        self.namespace_change_at = None
        self.pod_change_at = None
        self.stdout = b'minio version RELEASE.2025-04-22T22-12-26Z (commit-id=1234567890abcdef)\n'
        self.exec_failure = False

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if command[:3] != ['kubectl', '--context=' + tool.CONTEXT, '--request-timeout=15s']:
            raise AssertionError('context changed')
        if 'exec' in command:
            expected = ['--namespace=' + tool.NAMESPACE, 'exec', 'pod/' + self.data['pod']['name'],
                        '--container=minio', '--', 'minio', '--version']
            if command[3:] != expected:
                raise AssertionError('unexpected exec command')
            return subprocess.CompletedProcess(command, 1 if self.exec_failure else 0,
                stdout=self.stdout, stderr=CANARY.encode())
        index = command.index('get')
        resource = command[index + 1]
        if resource not in ('namespace', 'deployments', 'replicasets', 'pods', 'pod', 'serviceaccount', 'service'):
            raise AssertionError('unapproved resource read')
        if '-o' not in command or not command[-1].startswith('go-template='):
            raise AssertionError('raw metadata output requested')
        projection = command[-1]
        for forbidden in ('.args', '.command', '.annotations', '.data', '.stringData'):
            if forbidden in projection:
                raise AssertionError('sensitive field requested')
        if resource != 'namespace' and '--namespace=' + tool.NAMESPACE not in command:
            raise AssertionError('namespace changed')
        value = copy.deepcopy(self.data[resource])
        if resource == 'namespace':
            self.namespace_reads += 1
            if self.namespace_reads == self.namespace_change_at:
                value['uid'] = 'replacement-namespace'
        if resource == 'pod':
            self.pod_reads += 1
            if self.pod_reads == self.pod_change_at:
                value['statuses'][0]['container_id'] = 'replacement-container'
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(value).encode(), stderr=CANARY.encode())


class PrerequisitesTests(unittest.TestCase):
    def test_exact_scope_identity_and_unknown_principals(self):
        fake = FakeKubectl()
        report = tool.Collector(fake).collect()
        encoded = json.dumps(report)
        self.assertNotIn(CANARY, encoded)
        self.assertEqual(report['namespace_uid'], tool.NAMESPACE_UID)
        self.assertEqual(report['minio_pods'][0]['statuses'][0]['image_id'], fixture()['pod']['statuses'][0]['image_id'])
        self.assertEqual(report['service_account']['uid'], 'original-sa-uid')
        self.assertEqual(report['endpoint_candidates'][0]['scheme'], 'unknown')
        self.assertFalse(report['tls_verified'])
        self.assertEqual(report['admin_api_profile'], 'unknown_requires_version_matched_adapter')
        self.assertEqual(report['minio_version']['commit_id'], '1234567890abcdef')
        self.assertFalse(report['minio_version']['atomic_exec_uid_precondition'])
        self.assertTrue(all(v['status'] == 'unknown' for v in report['principal_material_sources'].values()))
        self.assertEqual(len(report['publication_configuration_signals']), 1)
        self.assertEqual(sum('exec' in call for call in fake.calls), 1)
        self.assertTrue(all('get' in call or 'exec' in call for call in fake.calls))

    def test_wrong_namespace_stops_before_other_reads(self):
        fake = FakeKubectl()
        fake.namespace_change_at = 1
        with self.assertRaisesRegex(tool.Refused, '^namespace_identity_changed$'):
            tool.Collector(fake).collect()
        self.assertEqual(len(fake.calls), 1)

    def test_namespace_replacement_before_exec(self):
        fake = FakeKubectl()
        fake.namespace_change_at = 2
        with self.assertRaisesRegex(tool.Refused, '^namespace_identity_changed$'):
            tool.Collector(fake).collect()
        self.assertFalse(any('exec' in c for c in fake.calls))

    def test_namespace_replacement_during_exec_discards_version(self):
        fake = FakeKubectl()
        fake.namespace_change_at = 3
        with self.assertRaisesRegex(tool.Refused, '^namespace_identity_changed$'):
            tool.Collector(fake).collect()

    def test_exact_container_replaced_before_or_during_exec(self):
        for when, reason in ((1, 'before'), (2, 'during')):
            with self.subTest(when=when):
                fake = FakeKubectl()
                fake.pod_change_at = when
                with self.assertRaisesRegex(tool.Refused, '^minio_container_changed_' + reason + '_exec$'):
                    tool.Collector(fake).collect()
                self.assertEqual(sum('exec' in c for c in fake.calls), 0 if when == 1 else 1)

    def test_ambiguous_or_unowned_pod_never_executes(self):
        for mode in ('ambiguous', 'unowned'):
            with self.subTest(mode=mode):
                fake = FakeKubectl()
                if mode == 'ambiguous':
                    fake.data['pods'].append(copy.deepcopy(fake.data['pod']))
                else:
                    fake.data['pods'][0]['owners'][0]['uid'] = 'other-replicaset'
                with self.assertRaisesRegex(tool.Refused, '^minio_pod_selection_ambiguous_or_missing$'):
                    tool.Collector(fake).collect()
                self.assertFalse(any('exec' in c for c in fake.calls))

    def test_resource_list_limit_never_executes(self):
        fake = FakeKubectl()
        fake.data['deployments'] *= 17
        with self.assertRaisesRegex(tool.Refused, '^resource_list_shape_or_limit$'):
            tool.Collector(fake).collect()
        self.assertFalse(any('exec' in c for c in fake.calls))

    def test_missing_or_unready_exact_container_never_executes(self):
        for mode in ('missing', 'unready', 'not-running', 'missing-image-id'):
            with self.subTest(mode=mode):
                fake = FakeKubectl()
                status = fake.data['pods'][0]['statuses'][0]
                if mode == 'missing': status['name'] = 'sidecar'
                if mode == 'unready': status['ready'] = False
                if mode == 'not-running': status['running'] = False
                if mode == 'missing-image-id': status['image_id'] = ''
                with self.assertRaisesRegex(tool.Refused, '^exact_minio_container_unavailable$'):
                    tool.Collector(fake).collect()
                self.assertFalse(any('exec' in c for c in fake.calls))

    def test_version_parser_never_prints_unselected_output(self):
        fake = FakeKubectl()
        fake.stdout += ('password=' + CANARY + '\n').encode()
        self.assertNotIn(CANARY, json.dumps(tool.Collector(fake).collect()))
        for stdout in (CANARY.encode(), b'minio version unknown (commit-id=not-a-commit)\n'):
            fake = FakeKubectl()
            fake.stdout = stdout
            report = tool.Collector(fake).collect()
            self.assertEqual(report['minio_version']['status'], 'unknown')
            self.assertNotIn(CANARY, json.dumps(report))

    def test_exec_denial_preserves_only_filtered_metadata(self):
        fake = FakeKubectl()
        fake.exec_failure = True
        fake.stdout = CANARY.encode()
        report = tool.Collector(fake).collect()
        self.assertEqual(report['minio_version']['status'], 'unknown')
        self.assertIn('image_id', report['minio_pods'][0]['statuses'][0])
        self.assertNotIn(CANARY, json.dumps(report))

    def test_no_scope_overrides_or_raw_tool_error(self):
        output = io.StringIO()
        with mock.patch.object(tool.sys, 'argv', [str(PATH), '--context=other']), mock.patch.object(tool.sys, 'stdout', output):
            self.assertEqual(tool.main(), 2)
        self.assertEqual(json.loads(output.getvalue())['reason'], 'no_cli_overrides_allowed')
        def failed(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, stdout=CANARY.encode(), stderr=CANARY.encode())
        with self.assertRaisesRegex(tool.Refused, '^bounded_kubectl_read_failed$'):
            tool.Collector(failed).collect()

    def test_projection_with_real_go_template_never_reads_sensitive_fields(self):
        # No network/dependencies: only the Go standard library; all products
        # and its isolated build cache are removed with this temporary folder.
        go_source = '''package main
import("encoding/json";"os";"text/template";"bytes")
type Request struct { Template string; Object any }
func main(){var requests []Request; if e:=json.NewDecoder(os.Stdin).Decode(&requests);e!=nil{panic(e)}
out:=[]json.RawMessage{}; for _,r:=range requests {t,e:=template.New("projection").Parse(r.Template);if e!=nil{panic(e)}
var b bytes.Buffer;if e=t.Execute(&b,r.Object);e!=nil{panic(e)}; if !json.Valid(b.Bytes()){panic("invalid projected JSON")};out=append(out,append([]byte(nil),b.Bytes()...))};if e:=json.NewEncoder(os.Stdout).Encode(out);e!=nil{panic(e)}}
'''
        metadata = dict(name='minio', namespace=tool.NAMESPACE, uid='original',
                        annotations={'last-applied': CANARY})
        original = dict(metadata=metadata, spec=dict(serviceAccountName='original-sa',
            selector=dict(matchLabels=dict(app='minio'), app='minio'), replicas=1,
            containers=[dict(name='minio', image='minio:original', args=[CANARY], command=[CANARY],
                env=[dict(name='INLINE_PASSWORD', value=CANARY),
                     dict(name='SYSTEM_BACKUP_PUBLICATION_TARGET_FILE', value='/private/' + CANARY),
                     dict(name='REF', valueFrom=dict(secretKeyRef=dict(name='safe-reference', key='key-name-only')))],
                volumeMounts=[dict(name='tls', mountPath='/certs', readOnly=True)])],
            ports=[dict(name='api', port=9000, targetPort=9000, protocol='TCP')],
            volumes=[dict(name='tls', secret=dict(secretName='safe-tls-reference', items=[dict(key=CANARY, path=CANARY)])),
                     dict(name='projected', projected=dict(sources=[dict(serviceAccountToken=dict(path=CANARY, audience=CANARY))]))]),
            status=dict(phase='Running', containerStatuses=[dict(name='minio', ready=True, imageID='sha256:original', containerID='containerd://original', state=dict(running=dict(startedAt='2026-11-02T00:00:00Z')))]))
        original['spec']['template'] = dict(spec=copy.deepcopy(original['spec']))
        requests = [dict(Template=tool.NS_TEMPLATE, Object=original),
            dict(Template=tool.DEPLOYMENTS_TEMPLATE, Object=dict(items=[original])),
            dict(Template=tool.RS_TEMPLATE, Object=dict(items=[original])),
            dict(Template=tool.PODS_TEMPLATE, Object=dict(items=[original])),
            dict(Template=tool.POD_ITEM, Object=original),
            dict(Template=tool.SA_TEMPLATE, Object=original),
            dict(Template=tool.SERVICE_TEMPLATE, Object=original),
            dict(Template=tool.DEPLOYMENTS_TEMPLATE, Object=dict(items=[original] * 33))]
        with tempfile.TemporaryDirectory(prefix='c-minio-projection-test-') as directory:
            source = Path(directory) / 'main.go'
            source.write_text(go_source, encoding='utf-8')
            environment = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', GOCACHE=str(Path(directory) / 'cache'))
            result = subprocess.run(['go', 'run', str(source)], input=json.dumps(requests).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False, cwd=directory, env=environment)
            self.assertEqual(result.returncode, 0, 'local Go projection validation failed: ' + result.stderr.decode(errors='replace'))
            self.assertNotIn(CANARY.encode(), result.stdout)
            projected = json.loads(result.stdout)
            self.assertEqual(projected[6]['ports'][0]['target_port'], '9000')
            self.assertIsNone(projected[7])
            self.assertEqual(projected[4]['containers'][0]['env_references'][2]['secret'], 'safe-reference')
            self.assertTrue(projected[4]['volumes'][1]['projected'][0]['service_account_token_projection'])


if __name__ == '__main__':
    unittest.main()
