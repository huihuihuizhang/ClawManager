import os,json,copy,importlib.util,datetime as dt,subprocess,argparse
from pathlib import Path
os.umask(0o077)
parser=argparse.ArgumentParser();parser.add_argument('--source-attempt',type=int,required=True);args=parser.parse_args()
package=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('C',package/'continue-p2-nov14.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
A,L,H,R,N,D,F,T=[C.load(n) for n in ('assemble-p2-installation-candidate','load-p2-formal-vault','prepare-p2-longhorn-provider-loaded','resume-p2-recovered-source','renew-p2-source-preparation','p2-source-dns','p2-vault-local-forward','resume-p2-tenant-team-source')]
build=A.decode((package/'BUILD_RECEIPT.json').read_bytes())
for name in ('system-backup-source-registries','system-backup-first-install-materials'):
 A.read({'File':str(package/name),'SHA256':build['Binaries'][name]['SHA256']},256<<20)
C.select_attempt(A,args.source_attempt)
j=C.ROOT/'p2-team-credential-renewal-20261115';api=j/('source-'+str(args.source_attempt)+'-api');api.mkdir(mode=0o700,exist_ok=True);site=L.Site(api,A)
loaded=A.decode((j/'loaded.json').read_bytes());plan=A.decode((j/'delivery-plan.private.json').read_bytes());desired=A.obj(plan['DesiredSpec']);secret=A.obj(plan['Secret'])
fresh,pod=C.controller_ref(A,site,L,loaded,desired);L.verify_secret(site.get('secret',secret['metadata']['name']),secret)
minted=A.decode((j/'mint/native.receipt.private.json').read_bytes());native=A.obj(minted['Observer']);token=A.read({'File':native['TokenFile'],'SHA256':native['TokenSHA256']})
L.verify_metadata(A,F,site,api,native,token,minted['Workload'],dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=35))
parent=A.decode((T.PARENT/'completed.json').read_bytes());A.need(parent['Receipt']['SHA256']==T.RECEIPT_SHA and parent['Definition']['SHA256']==T.DEFINITION_SHA and parent['SourceSelection']['SHA256']==T.SELECTION_SHA,'parent pins differ');A.read(parent['Receipt'])
original=A.obj(parent['Definition']);selected=A.obj(parent['SourceSelection']);observer,agent=C.renewed_credentials(A)
original=C.renewed_source(A,N,original,observer,agent);original=C.renewed_team_writer(A,original);original=C.capture_resource_types(A,original);original=C.renewed_scope(A,original)
old=A.obj({'File':str(C.ROOT/'controller-relay/relay-pki.receipt.private.json'),'SHA256':'ce9ad004c051b52969c52c632c29e74bffc9fba617c52316c288662bd58cfc0a'})
new=A.obj({'File':str(C.ROOT/'controller-relay-renewal-20261115/relay-pki.receipt.private.json'),'SHA256':'fc9a11b7f149b8bf86f014b27fb8aedc7cc4842808bf16341cedd596f9b75969'})
A.need(new['Version']=='original-relay-pki-result.v1' and new['State']=='original_relay_pki_material_issued_service_tls_not_yet_verified' and all(new[k]==old[k] for k in ('DeploymentUID','ServiceUID','Endpoint')) and N.moment(new['Until'])>dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=45),'relay identity/window differs')
replacements={};digest_paths={}
for key in ('Manifest','Signature','CA','IssuerKey','ServerCertificate','ServerKey','ClientCertificate','ClientKey'):
 before,after=old[key],new[key];A.read(before);A.read(after);digest_paths[before['SHA256']]=after['File']
 for field in ('File','SHA256'):
  A.need(before[field] not in replacements or replacements[before[field]]==after[field],'ambiguous relay replacement');replacements[before[field]]=after[field]
N.replace_materialized_aliases(A,original,digest_paths,replacements);original=N.replace_pinned_values(original,replacements)
done=C.refresh(A,L,H,R,N,D,F,T,site,package,parent,original,selected,fresh,pod,desired,secret,plan,minted,observer,agent)
build=A.decode((package/'BUILD_RECEIPT.json').read_bytes())
A.read({'File':str(package/'system-backup-source-registries'),'SHA256':build['Binaries']['system-backup-source-registries']['SHA256']},256<<20)
C.mount(A,L,H,R,D,site,package,done,fresh,pod,desired)
print('P2_NOV15_MOUNT_CONFIRMED',flush=True)
run=subprocess.run(['python3',str(package/'produce-p2-source-facts.py'),'--source-attempt',str(args.source_attempt)],stdin=subprocess.DEVNULL)
print('P2_NOV15_FACTS_EXIT',run.returncode,flush=True)

if run.returncode: raise SystemExit(run.returncode)
