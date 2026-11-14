#!/usr/bin/env python3
"""Retire this P2 read-only consumer after operator-confirmed recovery/retirement."""
import argparse
import importlib.util
import json
import os
import time
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def cleanup(A,L,T,journal,args):
    A.need(args.confirm_business_restored and args.confirm_source_disabled and args.task_id.strip(),
           'explicit operator recovery and source-retirement confirmation with actual task ID required')
    stem='longhorn-source-20261114-team-attachment'
    attempts=[p for p in journal.parent.glob(stem+'*') if p.is_dir() and (p.name==stem or p.name[len(stem):].lstrip('-').isdigit())]
    latest=max(attempts,key=lambda p:1 if p.name==stem else int(p.name[len(stem)+1:]))
    A.need(journal==latest,'newer source attempt exists; retire that source before deleting shared attachment')
    complete=A.decode((journal/'completed.json').read_bytes());A.read(complete['Receipt'])
    original=A.decode((journal/'team-attachment.created.private.json').read_bytes())
    evidence={'TaskID':args.task_id,'RecoveryEvidence':{'File':args.recovery_evidence_file,'SHA256':args.recovery_evidence_sha256},
              'SourceRetirementEvidence':{'File':args.source_retirement_evidence_file,'SHA256':args.source_retirement_evidence_sha256}}
    for k in ('RecoveryEvidence','SourceRetirementEvidence'):A.read(evidence[k])
    # These are operator attestations with preserved evidence, not a native proof verifier.
    evidence.update(OperatorConfirmedBusinessRestored=True,OperatorConfirmedSourceDisabled=True,PodUID=original['metadata']['uid'],SourceSelection=complete['SourceSelection'])
    site=L.Site(journal,A)
    def read(path):return A.decode(site.call(['get','--raw',path]))
    base='/api/v1/namespaces/'+T.NS
    def binding():T.check_binding(read('/api/v1/namespaces/'+T.NS),read(base+'/persistentvolumeclaims/'+T.CLAIM),read('/api/v1/persistentvolumes/'+T.PV))
    def drained():
        dep=site.get('deployment',A.CONTROLLER)
        A.need(dep['metadata']['uid']==A.CONTROLLER_UID and dep['spec'].get('replicas')==0 and not dep['metadata'].get('deletionTimestamp'),
               'exact controller must be scaled to zero after source retirement')
        selector=','.join(k+'='+v for k,v in dep['spec']['selector']['matchLabels'].items())
        pods=T.complete_items(A.decode(site.call(['get','pods','-l',selector,'-o','json'])))
        A.need(not pods,'controller Pods still present; wait for retirement/drain')
    binding();drained()
    pods=T.complete_items(read(base+'/pods'))
    others=[p for p in pods if p['metadata']['name']!=T.POD and any(v.get('persistentVolumeClaim',{}).get('claimName')==T.CLAIM for v in p['spec'].get('volumes',[]))]
    A.need(not others,'another team PVC consumer exists; reconcile before cleanup')
    matches=[p for p in pods if p['metadata']['name']==T.POD]
    A.retain(journal/'team-attachment.retirement-confirmation.private.json',evidence)
    if matches:
        current=matches[0];T.check_recorded_attachment(current,original)
        if not current['metadata'].get('deletionTimestamp'):
            options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Orphan','preconditions':{'uid':current['metadata']['uid'],'resourceVersion':current['metadata']['resourceVersion']}}
            drained()
            site.send('team-attachment-retire',['delete','--raw',base+'/pods/'+T.POD,'-f','-'],json.dumps(options).encode())
        deadline=time.monotonic()+90
        while True:
            remaining=[p for p in T.complete_items(read(base+'/pods')) if p['metadata']['name']==T.POD]
            if not remaining:break
            T.check_recorded_attachment(remaining[0],original)
            A.need(time.monotonic()<deadline,'attachment deletion pending; rerun same cleanup with same evidence');time.sleep(2)
    else:
        A.need((journal/'team-attachment-retire.sent.private.json').exists(),'Pod absent without this cleanup journal; reconcile disappearance')
    binding();drained()
    A.retain(journal/'team-attachment.retired.json',{'TaskID':args.task_id,'PodUID':original['metadata']['uid'],'PVCPreserved':True,'SourceSelection':complete['SourceSelection']})
    print('P2_TEAM_ATTACHMENT_RETIRED_PVC_PRESERVED',json.dumps({'TaskID':args.task_id,'PodUID':original['metadata']['uid']}),flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-attempt',type=int,default=1);p.add_argument('--task-id',required=True)
    for label in ('recovery-evidence','source-retirement-evidence'):
        p.add_argument('--'+label+'-file',required=True);p.add_argument('--'+label+'-sha256',required=True)
    p.add_argument('--confirm-business-restored',action='store_true');p.add_argument('--confirm-source-disabled',action='store_true');args=p.parse_args()
    os.umask(0o077);A=load('assemble-p2-installation-candidate');A.need(1<=args.source_attempt<=99,'source-attempt must be 1..99')
    suffix='' if args.source_attempt==1 else '-'+str(args.source_attempt)
    journal=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')/('longhorn-source-20261114-team-attachment'+suffix)
    cleanup(A,load('load-p2-formal-vault'),load('prepare-p2-team-attachment'),journal,args)
if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_TEAM_RETIREMENT_UNCONFIRMED '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
