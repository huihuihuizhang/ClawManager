import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class CredentialsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.C=load('continue-p2-nov14');self.A=load('assemble-p2-installation-candidate');self.N=load('renew-p2-source-preparation')
        self.C.ROOT=self.root
        def pin(label):return self.A.retain(self.root/label,label.encode())
        self.pin=pin
        def observer(prefix):
            d={k:pin(prefix+'-'+k) for k in ('CA','ClientCertificate','ClientKey')};d['Endpoints']=[]
            for node in ('k8s-master','node1'):
                for kind in ('whole','gateway','stopped-pro','shared'):
                    e={'Node':node,'Kind':kind,'NodeUID':node+'-uid','MachineID':node+'-machine','BootID':node+'-boot','Endpoint':{'URL':node+'/'+kind}}
                    e.update({k:pin(prefix+'-'+node+'-'+kind+'-'+k) for k in ('Certificate','PrivateKey','AnchorKey')});d['Endpoints'].append(e)
            return d
        self.old=observer('old');self.new=observer('new');self.old_agent={'CA':pin('old-agent')};self.agent={'CA':pin('new-agent'),'NotAfter':'2026-11-15T10:12:19Z'}
        real_obj=self.A.obj
        def obj(p):
            if '/renewal-20261113/' in p['File'].replace('\\','/'):
                return self.old_agent if 'runtime-unique' in p['File'] else self.old
            return real_obj(p)
        self.A.obj=obj

    def test_rebinds_pins_and_materialized_aliases_without_changing_scope(self):
        alias=self.root/'materialized-ca';alias.write_bytes(Path(self.old['CA']['File']).read_bytes())
        original={'CAFile':'/materialized-ca','CASHA256':self.old['CA']['SHA256'],'ClientKey':self.old['ClientKey'],
                  'AgentCA':self.old_agent['CA'],'Endpoints':self.old['Endpoints'],'scope':{'running':[1,2,3,7,8],'deferred':[4,5,6]}}
        before=copy.deepcopy(original);read=self.A.read
        def translated_read(pin,*args):
            return read({**pin,'File':str(alias)} if pin['File']=='/materialized-ca' else pin,*args)
        with patch.object(self.N,'Path',side_effect=lambda value:alias if value=='/materialized-ca' else Path(value)),patch.object(self.A,'read',side_effect=translated_read):
            result=self.C.renewed_source(self.A,self.N,original,self.new,self.agent)
        self.assertEqual(result['CAFile'],self.new['CA']['File']);self.assertEqual(result['CASHA256'],self.new['CA']['SHA256'])
        self.assertEqual(result['ClientKey'],self.new['ClientKey']);self.assertEqual(result['AgentCA'],self.agent['CA'])
        self.assertEqual(result['Endpoints'],self.new['Endpoints']);self.assertEqual(result['scope'],original['scope']);self.assertEqual(original,before)

    def test_changed_node_identity_refuses_credential_rebinding(self):
        self.new['Endpoints'][0]['BootID']='other-boot'
        with self.assertRaisesRegex(ValueError,'observer identity changed'):self.C.renewed_source(self.A,self.N,{},self.new,self.agent)

    def relay_fixture(self):
        old={'DeploymentUID':'controller','ServiceUID':'service','Endpoint':'https://relay'}
        new={**old,'Version':'original-relay-pki-result.v1','State':'original_relay_pki_material_issued_service_tls_not_yet_verified','Until':'2099-01-01T00:00:00Z'}
        for key in ('Manifest','Signature','CA','IssuerKey','ServerCertificate','ServerKey','ClientCertificate','ClientKey'):
            old[key]=self.pin('relay-old-'+key);new[key]=self.pin('relay-new-'+key)
        return old,new

    def test_relay_signed_files_rebound_without_changing_business_scope(self):
        old,new=self.relay_fixture()
        original={'issuer_certificate':old['CA']['File'],'issuer_certificate_sha256':old['CA']['SHA256'],
                  'Manifest':old['Manifest'],'Signature':old['Signature'],'scope':[1,2,3,7,8]}
        with patch.object(self.A,'obj',side_effect=[old,new]):
            result=self.C.renewed_relay(self.A,self.N,original)
        self.assertEqual(result,{'issuer_certificate':new['CA']['File'],'issuer_certificate_sha256':new['CA']['SHA256'],
                                 'Manifest':new['Manifest'],'Signature':new['Signature'],'scope':[1,2,3,7,8]})

    def test_relay_expiry_and_identity_drift_refuse_reuse(self):
        for key,value,reason in [('Until','2000-01-01T00:00:00Z','window insufficient'),('ServiceUID','other','identity differs')]:
            old,new=self.relay_fixture();new[key]=value
            with patch.object(self.A,'obj',side_effect=[old,new]),self.assertRaisesRegex(ValueError,reason):
                self.C.renewed_relay(self.A,self.N,{})

    def proofs(self):
        root=self.root/self.C.RENEWAL;root.mkdir()
        def put(name,value):
            p=self.A.retain(root/name,value);return name,p['SHA256']
        self.C.CERTIFICATES=(put('observer.json',self.new),put('agent.json',self.agent))
        self.values=[{'Version':'p2-observer-certificate-rotation-completed.v1','Node':n,'CA':self.new['CA']['SHA256'],'DurableRecordsPreserved':True} for n in ('k8s-master','node1')]
        self.values.append({'Version':'p2-runtime-certificate-rotation.v1','CA':self.agent['CA'],'ImagesPreserved':True,'NotAfter':self.agent['NotAfter']})
        self.C.ROTATIONS=tuple(put('proof-'+str(i),v) for i,v in enumerate(self.values))

    def test_issued_but_not_loaded_credentials_are_rejected(self):
        self.proofs();(self.root/self.C.RENEWAL/'proof-1').unlink()
        with self.assertRaises((ValueError,OSError)):self.C.renewed_credentials(self.A)

    def test_both_nodes_and_runtime_proofs_required_before_reuse(self):
        self.proofs();self.assertEqual(self.C.renewed_credentials(self.A),(self.new,self.agent))
        self.values[1]['CA']='wrong'
        pin=self.A.retain(self.root/self.C.RENEWAL/'mismatch',self.values[1]);self.C.ROTATIONS=(self.C.ROTATIONS[0],('mismatch',pin['SHA256']),self.C.ROTATIONS[2])
        with self.assertRaisesRegex(ValueError,'observer rotation differs'):self.C.renewed_credentials(self.A)

if __name__=='__main__':unittest.main()
