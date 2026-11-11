import base64
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('p2_api_runtime', Path(__file__).with_name('prepare-p2-api-runtime-inputs.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ActualAPIAndInstalledOwner(unittest.TestCase):
    def test_source_account_cannot_borrow_other_identity(self):
        user = dict(username='system:serviceaccount:system:source', uid='original-uid')
        m.check_review(dict(authenticated=True, user=user), 'system', 'source', 'original-uid')
        for status in [dict(authenticated=False, user=user), dict(user=dict(user, uid='replacement')),
                       dict(user=dict(user, username='system:serviceaccount:system:controller'))]:
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                m.check_review(status, 'system', 'source', 'original-uid')

    def test_api_connection_requires_original_tls_and_endpoint(self):
        ca = b'-----BEGIN CERTIFICATE-----\nselected-original-ca\n-----END CERTIFICATE-----'
        cluster = {'server': 'https://original-api:6443', 'certificate-authority-data': base64.b64encode(ca).decode()}
        plan = dict(KubernetesAPI=cluster['server'], KubernetesCASHA256=hashlib.sha256(ca).hexdigest())
        self.assertEqual(m.check_cluster(cluster, plan), (cluster['server'], ca))
        for changed in [dict(cluster, server='https://other-api:6443'), dict(cluster, **{'insecure-skip-tls-verify': True}),
                        dict(cluster, **{'proxy-url': 'http://proxy'}), dict(cluster, **{'tls-server-name': 'other-api'}),
                        dict(cluster, **{'certificate-authority-data': base64.b64encode(ca+b'other').decode()})]:
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                m.check_cluster(changed, plan)

    def test_metadata_permissions_never_allow_source_or_task_mutation(self):
        for provider in [False, True]:
            for rule in m.readonly_rules(provider):
                self.assertLessEqual(set(rule['verbs']), {'get', 'list', 'watch'})
                self.assertNotIn('*', rule['resources'])
                self.assertNotIn('*', rule['apiGroups'])
                self.assertNotIn('pods/exec', rule['resources'])
                self.assertNotIn('serviceaccounts/token', rule['resources'])

    def test_label_matched_foreign_pod_cannot_supply_executable(self):
        app = dict(metadata=dict(name='app', uid=m.APP_UID))
        rs = dict(metadata=dict(name='app-rs', uid='original-rs', ownerReferences=[dict(controller=True, kind='Deployment', name='app', uid=m.APP_UID)]))
        pod = dict(metadata=dict(name='app-pod', uid='original-pod', ownerReferences=[dict(controller=True, kind='ReplicaSet', name='app-rs', uid='original-rs')]),
            spec=dict(containers=[dict(image=m.APP_IMAGE)]), status=dict(phase='Running', containerStatuses=[dict(ready=True, containerID='containerd://original', imageID=m.APP_IMAGE, state=dict(running={}))]))
        m.app_owner_chain(pod, rs, app)
        for mode in ['parent', 'image', 'not-ready', 'restarted']:
            changed = copy.deepcopy(pod)
            if mode == 'parent': changed['metadata']['ownerReferences'][0]['uid'] = 'foreign-rs'
            elif mode == 'image': changed['spec']['containers'][0]['image'] = 'foreign-image'
            elif mode == 'not-ready': changed['status']['containerStatuses'][0]['ready'] = False
            else: changed['status']['containerStatuses'][0]['state'] = dict(waiting={})
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                m.app_owner_chain(changed, rs, app)


if __name__ == '__main__':
    unittest.main(verbosity=2)
