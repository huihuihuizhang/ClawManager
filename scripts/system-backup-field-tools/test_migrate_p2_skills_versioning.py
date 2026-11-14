import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

s=importlib.util.spec_from_file_location('migration',Path(__file__).with_name('migrate-p2-skills-versioning.py'))
M=importlib.util.module_from_spec(s);s.loader.exec_module(M)

class S3:
    def __init__(self):
        self.objects={};self.enabled=False;self.puts=0;self.deletes=0;self.lose_put=False;self.lose_delete=False;self.corrupt=False
        for n in range(115):self.objects['skills/'+str(n)]={'null':b'original'}
    def get_paginator(self,_):return self
    def paginate(self,**kwargs):
        yield {'Versions':[{'Key':key,'VersionId':version,'ETag':'etag','Size':len(body),'IsLatest':version==list(values)[-1]} for key,values in self.objects.items() for version,body in values.items()]}
    def get_bucket_versioning(self,**kwargs):return {'Status':'Enabled'} if self.enabled else {}
    def put_bucket_versioning(self,**kwargs):self.enabled=True
    def get_object(self,Bucket,Key,VersionId):
        raw=self.objects[Key][VersionId];return {'Body':io.BytesIO(raw),'ContentLength':len(raw),'ContentType':'application/zip','Metadata':{'owner':'original'}}
    def get_object_tagging(self,**kwargs):return {'TagSet':[{'Key':'tag','Value':'value'}]}
    def put_object(self,**kwargs):
        self.puts+=1;version='v'+str(self.puts);self.objects[kwargs['Key']][version]=b'corrupt' if self.corrupt else kwargs['Body']
        if self.lose_put:self.lose_put=False;raise TimeoutError()
        return {'VersionId':version}
    def delete_object(self,Bucket,Key,VersionId):
        assert VersionId=='null';assert self.puts==115
        self.deletes+=1;del self.objects[Key][VersionId]
        if self.lose_delete:self.lose_delete=False;raise TimeoutError()

class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.p=patch.object(M,'ROOT',self.root);self.p.start();self.addCleanup(self.p.stop)
        self.d=patch.object(M,'drained');self.d.start();self.addCleanup(self.d.stop)
        self.s3=S3();objects=[]
        for row in M.inventory(self.s3):
            raw,meta,tags=M.fetch(self.s3,row['Key'],'null');pin=M.retain(self.root/M.sha(row['Key'].encode()),raw)
            objects.append({**row,'Original':pin,'Metadata':meta,'Tags':tags})
        self.snap={'Objects':objects,'Inventory':M.inventory(self.s3)};M.retain(self.root/'snapshot.json',self.snap)
    def test_success_preserves_all_originals_and_metadata(self):
        M.migrate(self.s3,self.snap)
        self.assertEqual((self.s3.puts,self.s3.deletes),(115,115))
        self.assertTrue((self.root/'migration.completed.json').exists())
        for row in self.snap['Objects']:self.assertEqual(Path(row['Original']['File']).read_bytes(),b'original')
    def test_lost_put_response_is_adopted_without_duplicate_put(self):
        self.s3.lose_put=True
        with self.assertRaises(TimeoutError):M.migrate(self.s3,self.snap)
        self.assertEqual(self.s3.deletes,0)
        M.migrate(self.s3,self.snap);self.assertEqual(self.s3.puts,115)
    def test_corrupt_copy_prevents_every_original_deletion(self):
        self.s3.corrupt=True
        with self.assertRaisesRegex(ValueError,'content metadata or tags'):M.migrate(self.s3,self.snap)
        self.assertEqual(self.s3.deletes,0)
        self.assertTrue(all('null' in versions for versions in self.s3.objects.values()))
    def test_lost_delete_response_resumes_only_with_original_intent(self):
        self.s3.lose_delete=True
        with self.assertRaises(TimeoutError):M.migrate(self.s3,self.snap)
        M.migrate(self.s3,self.snap);self.assertEqual((self.s3.puts,self.s3.deletes),(115,115))
    def test_foreign_version_without_intent_is_not_adopted(self):
        self.s3.enabled=True;M.retain(self.root/'enable-versioning.intent.json',{'existing':'fixture'})
        self.s3.objects['skills/0']['foreign']=b'original'
        with self.assertRaisesRegex(ValueError,'unknown version creation'):M.migrate(self.s3,self.snap)
        self.assertEqual((self.s3.puts,self.s3.deletes),(0,0))
    def test_deployment_restore_refuses_template_drift(self):
        name='clawmanager-app';uid,count=M.WRITERS[name]
        original={'metadata':{'name':name,'uid':uid},'spec':{'replicas':count,'template':{'image':'original'}}}
        current=copy.deepcopy(original);current['metadata']['resourceVersion']='7';current['spec']['replicas']=0
        self.assertEqual(M.guarded_spec(original,current,count)[-1]['value'],count)
        current['spec']['template']['image']='foreign'
        with self.assertRaisesRegex(ValueError,'specification changed'):M.guarded_spec(original,current,count)

if __name__=='__main__':unittest.main()
