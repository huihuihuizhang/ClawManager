"""Local mocked safety checks for the exact reviewed operator-run installer."""
import hashlib, json, types, unittest
from pathlib import Path
from unittest.mock import patch

P=Path('scripts/system-backup-d-transit-install.py')
raw=P.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='6f8c97707ee9dc2fc3823b061116e8ecdfdebae80b3f9db2ddff89809c969f5b'
m=types.ModuleType('installer_under_review')
exec(compile(raw,str(P),'exec'),m.__dict__)
m.IMAGE='verified-private-repo@sha256:'+'a'*64

def owner():
    o=m.Owner.__new__(m.Owner)
    o.state={'prefix':'sbk-transit-zh-01234567','run':'0123456789abcdef','node':'k8s-master','storage_class':'longhorn','resources':{},'pending':None,'jwt_mount':'exact-jwt','signing':{'capture':{'key_name':'capture','public_key':'public'}}}
    o.save=lambda:None
    o.read=lambda name,json_value=True: {'root_token':'mock-only'} if json_value else b'public-or-mock-tls'
    return o

class Review(unittest.TestCase):
    def test_namespace_replacement_refused(self):
        data={'kind':'Namespace','apiVersion':'v1','metadata':{'name':m.NAMESPACE,'uid':'replacement'}}
        with patch.object(m,'kube',return_value=json.dumps(data).encode()):
            with self.assertRaisesRegex(m.Refused,'namespace_identity_changed'): m.guard()

    def test_delete_replacement_refused_before_mutation(self):
        o=owner(); name=o.state['prefix']; o.state['resources']['pods/'+name]='original'
        with patch.object(m,'guard'), patch.object(m,'get',return_value={'metadata':{'uid':'replacement','labels':{m.LABEL:o.state['run']}}}), patch.object(m,'kube') as k:
            with self.assertRaisesRegex(m.Refused,'deletion_uid_or_owner_changed'): o.delete('pods',name)
            k.assert_not_called()

    def test_delete_sends_exact_uid_precondition(self):
        o=owner(); name=o.state['prefix']; o.state['resources']['pods/'+name]='original'
        with patch.object(m,'guard'), patch.object(m,'get',return_value={'metadata':{'uid':'original','labels':{m.LABEL:o.state['run']}}}), patch.object(m,'kube') as k:
            o.delete('pods',name)
            self.assertEqual(json.loads(k.call_args.kwargs['data'])['preconditions'],{'uid':'original'})

    def test_create_existing_resource_refused_before_mutation(self):
        o=owner()
        with patch.object(m,'guard'),patch.object(m,'get',return_value={'metadata':{'uid':'foreign'}}),patch.object(m,'kube') as k:
            with self.assertRaisesRegex(m.Refused,'resource_name_already_exists'): o.create({'metadata':{'name':o.state['prefix']}},'secrets')
            k.assert_not_called()

    def test_manifest_nondev_new_pvc_and_no_root_material(self):
        o=owner(); objects=dict(m.manifests(o,'longhorn'))
        pod=objects['deployments']['spec']['template']['spec']; c=pod['containers'][0]
        self.assertEqual(c['command'],['/bin/vault','server','-config=/config/server.json'])
        self.assertEqual(c['image'],m.IMAGE)
        self.assertTrue(pod['securityContext']['runAsNonRoot'])
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(objects['persistentvolumeclaims']['spec']['storageClassName'],'longhorn')
        self.assertEqual(objects['persistentvolumeclaims']['spec']['accessModes'],['ReadWriteOnce'])
        self.assertEqual([v['persistentVolumeClaim']['claimName'] for v in pod['volumes'] if 'persistentVolumeClaim' in v],[o.state['prefix']+'-data'])
        self.assertNotIn('root_token',json.dumps(objects)); self.assertNotIn('init-material',json.dumps(objects))

    def test_generate_role_bound_to_actual_pod_and_context(self):
        o=owner(); calls=[]; name=o.state['prefix']+'-generate'
        def call(method,path,body=None,token=None,**kwargs):
            calls.append((method,path,body))
            return {'auth':{'token_type':'batch','renewable':False,'policies':[name],'lease_duration':20,'client_token':'mock-batch','metadata':{'role':name,'namespace':m.NAMESPACE,'service_account_uid':'sa-uid','pod_uid':'pod-uid'}}}
        def get(resource,name):
            return {'metadata':{'uid':'sa-uid'}} if resource=='serviceaccounts' else {'metadata':{'uid':'pod-uid','labels':{m.LABEL:o.state['run']}},'spec':{'serviceAccountName':'actual-sa'}}
        with patch.object(m,'get',side_effect=get),patch.object(m,'kube',return_value=b'mock-jwt'):
            self.assertEqual(m.bind_identity(o,types.SimpleNamespace(call=call),'generate','actual-pod','actual-sa','exact-context'),'mock-batch')
        role=next(body for method,path,body in calls if '/role/' in path)
        self.assertEqual(role['bound_claims']['/kubernetes.io/pod/uid'],'pod-uid')
        self.assertEqual(role['bound_claims']['/kubernetes.io/serviceaccount/uid'],'sa-uid')
        self.assertEqual([role[x] for x in ('clock_skew_leeway','expiration_leeway','not_before_leeway')],[-1,-1,-1])
        policy=json.loads(calls[0][2]['policy'])['path']
        self.assertEqual(list(policy),['transit/datakey/plaintext/'+o.state['prefix']+'-kek'])
        self.assertEqual(next(iter(policy.values()))['allowed_parameters']['context'],['exact-context'])

    def restart(self,same=False):
        o=owner(); name=o.state['prefix']; o.state['resources']['deployments/'+name]='deployment-uid'
        old=types.SimpleNamespace(close=lambda:None)
        new=types.SimpleNamespace(close=unittest.mock.Mock(),call=lambda *a,**k:{'data':{'keys':{'1':{'public_key':'public'}}}})
        pods=[{'metadata':{'name':'old-pod','uid':'old'}},{'metadata':{'name':'new-pod','uid':'old' if same else 'new'}}]
        def smoke(o,api): o.state['original_ciphertext_readback_passed']=True
        with patch.object(m,'pvc_binding') as pv,patch.object(m,'provider_pod',side_effect=pods),patch.object(m,'guard'),patch.object(m,'kube') as k,patch.object(m,'API',return_value=new),patch.object(m,'unseal'),patch.object(m,'smoke',side_effect=smoke):
            if same:
                with self.assertRaisesRegex(m.Refused,'provider_restart_not_observed'): m.persistence(o,old)
                new.close.assert_called_once()
            else:
                self.assertIs(m.persistence(o,old),new)
                patches=[json.loads(c.args[-1]) for c in k.call_args_list if 'patch' in c.args]
                self.assertEqual([p[0] for p in patches],[{'op':'test','path':'/metadata/uid','value':'deployment-uid'}]*2)
                self.assertEqual([p[1]['value'] for p in patches],[0,1])
                self.assertTrue(o.state['persistence_restart_verified']); self.assertEqual(pv.call_count,2)

    def test_restart_replacement_pod_is_required(self): self.restart(True)
    def test_restart_preserves_deployment_uid_and_readback_gate(self): self.restart(False)

if __name__=='__main__': unittest.main(verbosity=2)
