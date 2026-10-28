import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

function setup(post) {
 const exports={};
 const source=ts.transpileModule(readFileSync(new URL('./teamDataBackupService.ts',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022,esModuleInterop:true}}).outputText;
 runInNewContext(source,{exports,require:name=>{assert.equal(name,'./api');return {post}}});
 return exports;
}

test('retry keeps the original request identity after an uncertain response',async()=>{
 const calls=[];
 const original='sdr_012345678901234567890123456789ab';
 const child={public_id:'sdr_abcdef01234567890123456789012345',operation:'cleanup',status:'pending',phase:'queued'};
 const {teamDataBackupService:service}=setup(async(...args)=>{calls.push(args);if(calls.length===1)throw Error('response lost');return {data:{data:child}}});
 await assert.rejects(service.retry(original,'retry-same-request-key'),/response lost/);
 assert.equal((await service.retry(original,'retry-same-request-key')).public_id,child.public_id);
 for(const [path,body,options] of calls){assert.equal(path,`/admin/system-backup/team-data/jobs/${original}/retry`);assert.equal(JSON.stringify(body),'{}');assert.equal(options.headers['Idempotency-Key'],'retry-same-request-key')}
});

test('restore continuation keeps polling until its child or explicit failure',()=>{
 const {teamDataActive:active}=setup(()=>{});
 for(const status of ['pending','running','canceling'])assert.equal(active({status,phase:'queued'}),true);
 assert.equal(active({status:'succeeded',phase:'retry_pending'}),true);
 for(const phase of ['retry_started','retry_blocked','retry_stopped','complete'])assert.equal(active({status:'succeeded',phase}),false);
 assert.equal(active({status:'failed',phase:'publishing'}),false);
});

test('catalog restore submission uses the provided key and original backup',async()=>{
 const calls=[];
 const {teamDataBackupService:service}=setup(async(...args)=>{calls.push(args);return {data:{data:{public_id:'restore-attempt'}}}});
 await service.create('restore','restore-same-request-key','sbk_original');
 const [path,body,options]=calls[0];
 assert.equal(path,'/admin/system-backup/team-data/jobs');
 assert.equal(JSON.stringify(body),'{"operation":"restore","source_backup_id":"sbk_original"}');
 assert.equal(options.headers['Idempotency-Key'],'restore-same-request-key');
});
