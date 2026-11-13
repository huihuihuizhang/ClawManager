#!/usr/bin/env python3
"""Read writer resources using the exact renewed source credential."""
import importlib.util
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request

def main():
    os.umask(0o077)
    spec=importlib.util.spec_from_file_location('assembly',Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
    selected=A.obj({'File':'/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-20261113-runtime-scope-final-retry/source-selection.json',
        'SHA256':'a323dc03ada6b3ef8863ee4e0126f2ea7549fd8aecc9f182d7d8a49946db9565'})
    c=next(v for v in selected['Connections'] if v['Purpose']=='source_api')
    A.read(c['CA']);token=A.read(c['Credential']).decode().strip()
    context=ssl.create_default_context(cafile=c['CA']['File'])
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    def get(path):
        try:
            req=urllib.request.Request(c['Endpoint'].rstrip('/')+path,headers={'Authorization':'Bearer '+token})
            with opener.open(req,timeout=12) as response:
                raw=response.read((16<<20)+1)
                if len(raw)>16<<20:raise ValueError('response too large')
                return json.loads(raw)
        except urllib.error.HTTPError as e:print('API_REFUSED',path,e.code,flush=True)
        except Exception as e:print('API_READ_FAILED',path,type(e).__name__,flush=True)
        return None
    kinds=[('apis/apps/v1',k) for k in ['deployments','replicasets','statefulsets','daemonsets']]
    kinds += [('apis/batch/v1',k) for k in ['jobs','cronjobs']]
    kinds += [('apis/autoscaling/v2','horizontalpodautoscalers'),('api/v1','pods'),('api/v1','persistentvolumeclaims')]
    for ns in ['clawmanager-sbk-validation-system','clawmanager-sbk-validation-user-1']:
        namespace=get('/api/v1/namespaces/'+ns)
        if namespace:
            m=namespace['metadata'];labels=m.get('labels',{})
            print('NAMESPACE_CHECK',ns,json.dumps({'UIDPresent':bool(m.get('uid')),'Deleting':bool(m.get('deletionTimestamp')),
                'Labels':{k:labels.get(k) for k in ['app','managed-by','user-id']}}),flush=True)
        for group,kind in kinds:
            items=[];cursor='';version=None;seen=set()
            for page in range(100):
                value=get('/'+group+'/namespaces/'+ns+'/'+kind+'?'+urllib.parse.urlencode({'limit':1000,'continue':cursor}))
                if value is None:break
                metadata=value.get('metadata',{});current=metadata.get('resourceVersion')
                if not current or version is not None and current!=version:
                    print('LIST_VERSION_CHANGED',ns,kind,flush=True);break
                version=current;items.extend(value.get('items',[]));cursor=metadata.get('continue','')
                if not cursor:break
                if cursor in seen:raise ValueError('repeated continuation')
                seen.add(cursor)
            else:raise ValueError('page bound exceeded')
            if value is None:continue
            print('LIST_READ',ns,kind,len(items),flush=True)
            for obj in items:
                m=obj['metadata'];name=m.get('name');body=obj.get('spec',{})
                bad=[]
                if not m.get('uid'):bad.append('uid_missing')
                if m.get('deletionTimestamp'):bad.append('deleting')
                if kind=='deployments' and body.get('replicas') is None:bad.append('replicas_missing')
                if len(json.dumps(body,separators=(',',':')).encode())>1<<20:bad.append('spec_size_over_limit')
                if bad:print('WRITER_OBJECT_REFUSAL',ns,kind,name,json.dumps(bad),flush=True)
                if kind!='persistentvolumeclaims':continue
                volume=body.get('volumeName')
                if not volume:print('PVC_VOLUME_MISSING',ns,name,flush=True);continue
                pv=get('/api/v1/persistentvolumes/'+urllib.parse.quote(volume,safe=''))
                if pv is None:continue
                ref=pv.get('spec',{}).get('claimRef',{});pm=pv['metadata']
                matches=bool(pm.get('uid')) and not pm.get('deletionTimestamp') and ref.get('namespace')==ns and ref.get('name')==name and ref.get('uid')==m.get('uid')
                print('PV_BINDING',ns,name,json.dumps({'Matches':bool(matches),'PV':volume}),flush=True)
    print('WRITER_API_READONLY_DIAGNOSTIC_FINISHED',flush=True)

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('WRITER_API_DIAGNOSTIC_UNCONFIRMED '+type(e).__name__)
