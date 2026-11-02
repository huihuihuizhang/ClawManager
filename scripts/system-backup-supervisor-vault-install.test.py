"""Local mocked safety checks for the exact reviewed operator-run installer."""
import copy, hashlib, json, tempfile, types, unittest
from pathlib import Path
from unittest.mock import patch

P=Path('scripts/system-backup-d-transit-install.py')
raw=P.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='9de074926dd3b262cd3cf4e7d7915be689ba5bf6af2fa16dd4efd07a70c683b6'
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

    def resume_case(self,fault=None):
        o=owner()
        o.state.pop('jwt_mount'); o.state.pop('signing')
        o.state.update(schema_version='d-transit-owned-install.v1',context=m.CONTEXT,namespace=m.NAMESPACE,namespace_uid=m.NAMESPACE_UID,node_uid=m.NODES['k8s-master'],image=m.IMAGE)
        objects={}
        for i,(resource,obj) in enumerate(m.manifests(o,'longhorn'),1):
            obj=copy.deepcopy(obj); name=obj['metadata']['name']
            uid='00000000-0000-0000-0000-'+str(i).zfill(12)
            obj['metadata'].update(uid=uid,namespace=m.NAMESPACE,labels={m.LABEL:o.state['run']})
            objects[(resource,name)]=obj
            o.state['resources'][resource+'/'+name]=uid
        reason=None
        if fault=='pending': o.state['pending']='provider-init'; reason='original_install_state_unknown'
        if fault=='uid': objects[('deployments',o.state['prefix'])]['metadata']['uid']='replacement'; reason='original_owned_resource_changed'
        if fault=='tls': objects[('secrets',o.state['prefix']+'-tls')]['data']['server.pem']='changed'; reason='original_tls_or_server_config_changed'
        def kube(*args,**kwargs):
            if args[:2]==('get','node'): return json.dumps({'metadata':{'uid':m.NODES['k8s-master']},'status':{'nodeInfo':{'architecture':'amd64'}}}).encode()
            if args[:2]==('get','storageclass'): return json.dumps({'metadata':{},'provisioner':'driver.longhorn.io'}).encode()
            raise AssertionError('unexpected external operation')
        with tempfile.TemporaryDirectory(prefix='vault-resume-mock-') as directory:
            o.directory=Path(directory)
            if fault=='initialized': (o.directory/'init-material.json').write_text('mock'); reason='initialization_already_started_do_not_repeat'
            with patch.object(m,'guard'),patch.object(m,'get',side_effect=lambda resource,name:objects.get((resource,name))),patch.object(m,'kube',side_effect=kube),patch.object(m,'pvc_binding') as pv:
                if reason:
                    with self.assertRaisesRegex(m.Refused,reason): m.resume_install_owner(o)
                    pv.assert_not_called()
                else:
                    m.resume_install_owner(o); pv.assert_called_once_with(o)

    def test_resume_exact_existing_install_does_not_recreate(self): self.resume_case()
    def test_resume_pending_initialization_refused(self): self.resume_case('pending')
    def test_resume_replaced_resource_refused(self): self.resume_case('uid')
    def test_resume_changed_tls_refused(self): self.resume_case('tls')
    def test_resume_existing_initialization_material_refused(self): self.resume_case('initialized')

    def test_missing_raft_parent_prepared_without_root_or_extra_mount(self):
        o=owner(); pod=dict(m.manifests(o,'longhorn'))['deployments']['spec']['template']['spec']
        init=pod['initContainers'][0]
        self.assertTrue(pod['securityContext']['runAsNonRoot'])
        self.assertEqual(pod['securityContext']['runAsUser'],65532)
        self.assertIn('mkdir -p /data/raft',init['command'][-1])
        self.assertEqual(init['volumeMounts'],[{'name':'data','mountPath':'/data'}])
        self.assertFalse(init['securityContext']['allowPrivilegeEscalation'])
        self.assertEqual(init['securityContext']['capabilities'],{'drop':['ALL']})
        self.assertNotIn('env',init)

    def initializer(self,existing=None):
        o=owner(); name=o.state['prefix']; o.state['resources']['deployments/'+name]='deployment-uid'
        deployment=dict(m.manifests(o,'longhorn'))['deployments']
        deployment['metadata'].update(uid='deployment-uid',resourceVersion='7')
        if existing is None: deployment['spec']['template']['spec'].pop('initContainers')
        else: deployment['spec']['template']['spec']['initContainers']=existing
        return o,deployment

    def test_initializer_patch_changes_only_original_uid_rv_template(self):
        o,deployment=self.initializer()
        with patch.object(m,'guard'),patch.object(m,'kube') as k:
            m.ensure_provider_data_initializer(o,deployment)
            args=k.call_args.args; data=json.loads(args[args.index('-p')+1])
            self.assertEqual(data[:2],[{'op':'test','path':'/metadata/uid','value':'deployment-uid'},{'op':'test','path':'/metadata/resourceVersion','value':'7'}])
            self.assertEqual(data[2],{'op':'add','path':'/spec/template/spec/initContainers','value':[m.provider_data_initializer()]})
            k.assert_called_once()

    def test_existing_initializer_with_explicit_defaults_does_not_patch(self):
        o,deployment=self.initializer([m.provider_data_initializer()])
        with patch.object(m,'kube') as k:
            m.ensure_provider_data_initializer(o,deployment); k.assert_not_called()

    def test_foreign_initializer_refused_before_patch(self):
        init=m.provider_data_initializer(); init['env']=[{'name':'foreign','value':'mock'}]
        o,deployment=self.initializer([init])
        with patch.object(m,'kube') as k:
            with self.assertRaisesRegex(m.Refused,'original_provider_init_containers_changed'): m.ensure_provider_data_initializer(o,deployment)
            k.assert_not_called()

if __name__=='__main__': unittest.main(verbosity=2)
