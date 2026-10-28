// Actual React pages in Chrome. HTTP is a fixture; this is UI acceptance only.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';
import { createServer } from '../frontend/node_modules/vite/dist/node/index.js';

const frontend=path.resolve('../frontend'), temp=fs.mkdtempSync(path.join(os.tmpdir(),'backup-pages-'));
const source=p=>'/@fs/'+path.join(frontend,'src',p).replaceAll('\\','/');
process.chdir(frontend);
let server,browser,mutations=0;
try {
  fs.writeFileSync(path.join(temp,'fixture.tsx'),`import React from 'react';import{createRoot}from'react-dom/client';import{MemoryRouter,Routes,Route}from'react-router-dom';import{AuthProvider}from${JSON.stringify(source('contexts/AuthContext.tsx'))};import{I18nProvider}from${JSON.stringify(source('contexts/I18nContext.tsx'))};import Teams from${JSON.stringify(source('pages/admin/backups/TeamDataBackupsPage.tsx'))};import Tasks from${JSON.stringify(source('pages/admin/backups/BackupsPage.tsx'))};import Records from${JSON.stringify(source('pages/admin/backups/SystemBackupsPage.tsx'))};import${JSON.stringify(source('index.css'))};const target=new URLSearchParams(location.search).get('target')||'/admin/backups';createRoot(document.getElementById('root')).render(<I18nProvider><AuthProvider><MemoryRouter initialEntries={[target]}><Routes><Route path="/admin/backups" element={<Teams/>}/><Route path="/admin/backups/system" element={<Tasks/>}/><Route path="/admin/backups/records" element={<Records/>}/></Routes></MemoryRouter></AuthProvider></I18nProvider>);`);
  server=await createServer({root:frontend,configFile:path.join(frontend,'vite.config.ts'),define:{'import.meta.env.VITE_SYSTEM_BACKUP_LIVE_READ':JSON.stringify('0')},server:{host:'127.0.0.1',port:0,fs:{allow:[frontend,temp]}},plugins:[{name:'backup-page-acceptance',configureServer(s){s.middlewares.use('/__backup__',async(req,res)=>{res.setHeader('Content-Type','text/html');res.end(await s.transformIndexHtml('/__backup__',`<html><body style="margin:0"><div id="root"></div><script type="module" src="/@fs/${path.join(temp,'fixture.tsx').replaceAll('\\','/')}"></script></body></html>`))})}}]});
  await server.listen();
  browser=await chromium.launch({channel:'chrome',headless:true});
  const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{localStorage.setItem('access_token','synthetic-browser-token');localStorage.setItem('clawmanager_locale','zh')});
  await page.route('**/api/v1/**',route=>{
    const req=route.request(),u=new URL(req.url());if(req.method()!=='GET')mutations++;
    let data;
    if(u.pathname.endsWith('/auth/me'))data={id:1,username:'synthetic-admin',email:'test@fixture.invalid',role:'admin'};
    else if(u.pathname.endsWith('/team-data/overview'))data={configured:false};
    else if(u.pathname.endsWith('/system-backup/overview'))data={permissions:['system_backup.read','system_backup.operate'],readiness:{enabled:false,can_create:false,config_version:0,recovery_point_count:0,checks:[]}};
    else if(u.pathname.endsWith('/tasks'))data={items:[]};
    else return route.fulfill({status:503,json:{code:'not_ready'}});
    return route.fulfill({json:{success:true,data}});
  });
  const url=`http://127.0.0.1:${server.httpServer.address().port}/__backup__`;
  await page.goto(url);
  await page.getByRole('link',{name:'完整系统备份与执行状态',exact:true}).click();
  await page.getByRole('heading',{name:'任务记录',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'创建备份',exact:true}).isDisabled(),true);
  await page.goto(url);
  await page.getByRole('link',{name:'控制历史与验证记录',exact:true}).click();
  await page.getByRole('heading',{name:'备份与恢复准备',exact:true}).waitFor();
  await page.getByRole('heading',{name:'系统备份尚未接入',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'创建备份',exact:true}).isDisabled(),true);
  assert.equal(await page.locator('body').innerText().then(t=>t.includes('systemBackup.')),false);
  await page.getByRole('button',{name:'查看示例',exact:true}).first().click();
  await page.locator('p:visible').filter({hasText:'所有记录与状态均为示例，不代表当前安装；操作不会执行。'}).first().waitFor();
  for(const width of [1440,390]) {
    await page.setViewportSize({width,height:900});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false,`overflow ${width}`);
  }
  assert.equal(mutations,0,'navigation or preview issued a mutation');
  assert.deepEqual(errors,[]);
  console.log('PASS actual backup pages: preserved Team data entry, legacy task route, read-only versioned records, explicit demo isolation, translation, desktop/mobile, zero mutations. API fixture only.');
} finally {
  await browser?.close();await server?.close();
  assert.equal(path.dirname(path.resolve(temp)),path.resolve(os.tmpdir()));assert.ok(path.basename(temp).startsWith('backup-pages-'));
  fs.rmSync(temp,{recursive:true,force:true});
}
