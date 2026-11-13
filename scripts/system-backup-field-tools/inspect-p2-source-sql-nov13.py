#!/usr/bin/env python3
"""Bounded read-only diagnosis; never issues or changes backup materials."""
import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NS = 'clawmanager-sbk-validation-system'
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'

def need(ok, why):
    if not ok: raise ValueError(why)

def receive(sock, size):
    raw = b''
    while len(raw)<size:
        chunk = sock.recv(size-len(raw)); need(chunk,'MySQL greeting EOF'); raw += chunk
    return raw

def census_spec(value):
    found = []
    def visit(v):
        if isinstance(v,dict):
            if v.get('schema_version')=='mysql-full-schema-census.v1': found.append(v)
            for item in v.values(): visit(item)
        elif isinstance(v,list):
            for item in v: visit(item)
    visit(value)
    need(len(found)==1,'one pinned schema census required')
    return found[0]

def scope_comparison(scope, rows):
    if scope is None: return {'Present':False}
    # ASCII, bounded integer records have identical sorted compact JSON/JCS.
    need(all(isinstance(v,str) and v.isascii() or type(v) is int and abs(v)<2**53
             for row in rows for v in row.values()),'scope digest requires ASCII bounded projection')
    digest = lambda v: hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    aliases = copy.deepcopy(rows)
    changed = []
    for row in aliases:
        if row['OS']==row['Type']:
            changed.append(row['ID']); row['OS']='linux'
    deferred = scope['Deferred']
    return {'Present':True,'Version':scope['Version'],'RawProjectionMatches':digest(rows)==scope['OriginalInstancesSHA256'],
        'LinuxAliasCandidateMatches':digest(aliases)==scope['OriginalInstancesSHA256'],'AliasCandidateIDs':changed,
        'DeferredIDs':[r['ID'] for r in deferred],
        'DeferredCandidateMatches':all(any(r==v for r in aliases) for v in deferred),
        'CurrentGenerations':[{'ID':r['ID'],'Generation':r['Generation'],'Status':r['Status']} for r in rows]}

def tls_probe(connection):
    peer = urlsplit(connection['Endpoint'])
    context = ssl.create_default_context(cafile=connection['CA']['File'])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((peer.hostname,peer.port or 3306),timeout=8) as sock:
        header = receive(sock,4); size = int.from_bytes(header[:3],'little')
        need(0<size<65536,'bounded MySQL greeting required')
        greeting = receive(sock,size); need(greeting[0]==10,'MySQL protocol 10 required')
        offset = greeting.index(b'\0',1)+1+4+8+1
        capabilities = int.from_bytes(greeting[offset:offset+2],'little')
        need(capabilities & 2048,'MySQL SSL capability absent')
        request = struct.pack('<IIB23s',1|4|512|2048|8192|32768,1<<24,45,b'')
        sock.sendall(len(request).to_bytes(3,'little')+b'\1'+request)
        with context.wrap_socket(sock,server_hostname=peer.hostname) as secured:
            print('SOURCE_SQL_TLS_OK',json.dumps({'TLS':secured.version(),'NotAfter':secured.getpeercert().get('notAfter')}),flush=True)

def main():
    need(os.name=='posix','Linux operator required'); os.umask(0o077)
    spec = importlib.util.spec_from_file_location('assembly',Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
    selected = A.obj({'File':'/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-20261113-ca-alias/source-selection.json',
        'SHA256':'bf23877e281b5b44669f285bee4943d26a100d713e1247884b3530c650ba5d62'})
    matches = [c for c in selected['Connections'] if c['Purpose']=='source_sql']; need(len(matches)==1,'one selected source SQL required')
    c = matches[0]; ca = A.read(c['CA']); dsn = A.read(c['Credential']).decode().strip()
    census = census_spec(A.obj(selected['MaterialsTemplate']))
    scope = A.obj(selected['Deployment'])['runtime_sources'].get('runtime_test_scope')
    records = Path(tempfile.mkdtemp(prefix='source-sql-diagnostic-',dir=ROOT))
    print('SOURCE_SQL_DIAGNOSTIC_RECORDS',records,flush=True)
    print('UTC_NOW',dt.datetime.now(dt.timezone.utc).isoformat(),flush=True)
    print('SOURCE_WINDOW',json.dumps({k:selected[k] for k in ('NotBefore','Until')}),flush=True)
    try: tls_probe(c)
    except ssl.SSLCertVerificationError as e:
        print('SOURCE_SQL_TLS_REFUSED',json.dumps({'Code':e.verify_code,'Message':e.verify_message}),flush=True)
    except Exception as e: print('SOURCE_SQL_CONNECT_ERROR',type(e).__name__,flush=True)
    creds, sep, address = dsn.rpartition('@tcp('); user, colon, password = creds.partition(':')
    host, end, tail = address.partition(')/'); database = tail.split('?',1)[0]; peer = urlsplit(c['Endpoint'])
    need(sep and colon and end and host==peer.netloc and database==c['Database'] and c['Account'].startswith(user+'@') and
         user.lower()!='root' and not any(v in password for v in '\r\n\0'),'original source DSN shape required')
    shell = '''set -eu
IFS= read -r MYSQL_PWD
export MYSQL_PWD
IFS= read -r ca
umask 077
f=$(mktemp /tmp/sbk-source-sql-ca.XXXXXX)
trap 'rm -f -- "$f"' EXIT HUP INT TERM
printf '%s' "$ca" | base64 -d > "$f"
mysql --protocol=TCP --connect-timeout=8 --ssl-mode=VERIFY_IDENTITY --tls-version=TLSv1.3 --ssl-ca="$f" -h "$1" -P "$2" -u "$3" --database="$4" --batch --skip-column-names --raw -e "$5"
'''
    queries = {
        'identity': "SELECT JSON_OBJECT('account',CURRENT_USER(),'role_none',CURRENT_ROLE()='NONE','database',DATABASE(),'server',@@server_uuid,'clock',UTC_TIMESTAMP(6))",
        'grants': 'SHOW GRANTS FOR CURRENT_USER',
        'instances': "SET SESSION TRANSACTION READ ONLY; START TRANSACTION; SELECT JSON_OBJECT('id',id,'status',status,'generation',runtime_generation,'error_code',COALESCE(runtime_error_code,'')) FROM instances ORDER BY id; COMMIT;",
        'runtime_scope': "SET SESSION TRANSACTION READ ONLY; START TRANSACTION; SELECT JSON_OBJECT('ID',id,'UserID',user_id,'Mode',instance_mode,'Type',type,'Backend',runtime_type,'Variant',COALESCE(runtime_variant,''),'OS',os_type,'Status',status,'Generation',runtime_generation,'Pod',COALESCE(pod_name,''),'Namespace',COALESCE(pod_namespace,''),'Workspace',COALESCE(workspace_path,'')) FROM instances ORDER BY id; COMMIT;",
        'census_identity': "SELECT JSON_OBJECT('Definer',DEFINER,'DefinitionSHA256',SHA2(ROUTINE_DEFINITION,256),'Security',SECURITY_TYPE,'Access',SQL_DATA_ACCESS,'PartialRevokes',@@GLOBAL.partial_revokes) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME='system_backup_source_schema_census' AND ROUTINE_TYPE='PROCEDURE'",
        'census_objects': 'SET SESSION TRANSACTION READ ONLY; START TRANSACTION; CALL `system_backup_source_schema_census`(); COMMIT;'
    }
    census_verified = False
    for label, query in queries.items():
        if label=='census_objects' and not census_verified:
            print('SOURCE_SQL_CENSUS_CALL_SKIPPED_UNVERIFIED',flush=True); continue
        args = ['kubectl','--kubeconfig',KUBE,'--request-timeout=20s','-n',NS,'exec','-i','deployment/mysql','-c','mysql','--',
            'sh','-c',shell,'sbk-source-readonly',peer.hostname,str(peer.port or 3306),user,database,query]
        result = subprocess.run(args,input=password.encode()+b'\n'+base64.b64encode(ca)+b'\n',capture_output=True,timeout=45)
        A.retain(records/(label+'.stdout.private'),result.stdout or b'\n'); A.retain(records/(label+'.stderr.private'),result.stderr or b'\n')
        if result.returncode:
            text = result.stderr.decode(errors='replace').lower()
            print('SOURCE_SQL_QUERY_REFUSED',label,json.dumps({'ExitCode':result.returncode,'MySQLErrorNumbers':re.findall(r'error (\d+)',text),
                'Classes':{word:word in text for word in ['expired','certificate','access denied','denied','timeout','unknown column','doesn\'t exist','unknown host']}}),flush=True)
            continue
        if label=='identity':
            row = json.loads(result.stdout)
            print('SOURCE_SQL_IDENTITY',json.dumps({'AccountMatches':row['account']==c['Account'],'RoleNone':row['role_none']==1,
                'DatabaseMatches':row['database']==c['Database'],'ServerMatches':row['server']==c['ServerUUID'],'DatabaseUTC':row['clock']}),flush=True)
        elif label=='grants':
            grants = result.stdout.decode().splitlines()
            print('SOURCE_SQL_GRANTS',json.dumps({'Count':len(grants),'SHA256':hashlib.sha256(result.stdout).hexdigest(),
                'Shapes':sorted(set(re.sub(r' TO .*','',g) for g in grants if not g.startswith('GRANT SELECT ON ')))}),flush=True)
        elif label=='runtime_scope':
            print('SOURCE_SQL_RUNTIME_SCOPE',json.dumps(scope_comparison(scope,[json.loads(line) for line in result.stdout.splitlines()])),flush=True)
        elif label=='census_identity':
            rows = result.stdout.splitlines()
            need(len(rows)==1,'exact census procedure metadata row required')
            row = json.loads(rows[0])
            checks = {key:row[key]==census[key] for key in ('Definer','DefinitionSHA256','PartialRevokes')}
            checks.update(Security=row['Security']=='DEFINER',Access=row['Access']=='READS SQL DATA')
            census_verified = all(checks.values())
            print('SOURCE_SQL_CENSUS_IDENTITY',json.dumps(checks),flush=True)
        elif label=='census_objects':
            rows = [line.split('\t') for line in result.stdout.decode().splitlines()]
            need(all(len(row)==3 for row in rows),'census column count differs')
            print('SOURCE_SQL_CENSUS_OBJECTS',json.dumps({'Count':len(rows),'Exceptions':[row for row in rows if row[1:]!=['BASE TABLE','InnoDB']]}),flush=True)
        else:
            for line in result.stdout.splitlines(): print('SOURCE_SQL_INSTANCE',json.dumps(json.loads(line)),flush=True)
    print('SOURCE_SQL_READONLY_DIAGNOSTIC_FINISHED',flush=True)

if __name__=='__main__':
    try: main()
    except Exception as e: raise SystemExit('SOURCE_SQL_DIAGNOSTIC_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
