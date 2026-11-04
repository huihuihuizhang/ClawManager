import copy
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
spec=importlib.util.spec_from_file_location("native_original198",HERE/"system-backup-original-upgrade198.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ARCHIVE=ROOT/"artifacts/system-backup-upgrade198-copy-diagnostic-v3-linux-amd64-20261104.tar.gz"

# This operator is Linux-only. Windows cannot open directory FDs for fsync;
# model only that OS primitive, preserving actual exclusive files/file fsync
# and every production transition. Linux runs the unmodified real primitive.
# No Windows result is advertised as native durable-directory verification.
if os.name=="nt":
    original_open=m.os.open
    def windows_directory_fd(path,flags,*args,**kwargs):
        if flags==os.O_RDONLY and Path(path).is_dir():
            return original_open(Path(path)/".windows-directory-fsync-model",os.O_CREAT|os.O_RDWR,0o600)
        return original_open(path,flags,*args,**kwargs)
    m.os.open=windows_directory_fd


class Fixture(m.OriginalUpgrade):
    def __init__(self,path,action="apply"):
        super().__init__(types.SimpleNamespace(operation_directory=path,context="original",action=action))
        self.state={"operation":"a"*32,"user":"cm_upg_"+"a"*24,"remote":"/tmp/sbk-original-upgrade-"+"a"*32,"users":[{"user":"root","host":"localhost","plugin":"caching_sha2_password","authentication":"original-hash","locked":"N","grants":["original-root-grants"]}],"kube_lock_uid":"original-kube-uid","persisted":"","application":{"metadata":{"uid":m.APP_UID},"spec":{"replicas":1}}}
        self.rows={"preservation_sha256":"b"*64,"tables":[{"name":"original","rows":3,"sha256":"c"*64,"full_sha256":"d"*64}],"expected_ledger_rows":198,"upgraded_schema_sha256":"e"*64}
        self.ddl=[];self.events=[];self.fault=None;self.fences=[]
        self.app={"metadata":{"uid":m.APP_UID,"resourceVersion":"1","generation":1},"spec":{"replicas":0},"status":{"readyReplicas":0,"observedGeneration":1}}
    def load(self):pass
    def identity(self):pass
    def barrier(self,**kw):pass
    def append(self,event,details=None):self.events.append(event)
    def proof(self,*args):return copy.deepcopy(self.rows)
    def exclusive_sql(self,body,*args,**kw):
        self.ddl.append(body)
        if self.fault=="rename" or self.fault=="upgrade" and len(self.ddl)==2:raise RuntimeError("injected_unknown_native_DDL")
    def fence_pending_native(self,**kwargs):self.fences.append(kwargs)
    def verify_upgrade(self):self.events.append("actual_readback_called")
    def cleanup_owned_schemas(self):self.events.append("owned_schemas_cleaned_before_unlock")
    def sql(self,query,**kw):return ""
    def obj(self,*args):return copy.deepcopy(self.app)
    def k(self,*args,**kw):return b"{}"
    def original_sql_state_readback(self):
        if self.fault=="readback":raise RuntimeError("native_readback_failed")


class ActualScriptTests(unittest.TestCase):
    def seeded(self,path):
        tool=Fixture(path)
        with tarfile.open(ARCHIVE,"r:gz") as t:
            for n in ("rename.sql","upgrade.sql"):m.write_new(path/n,t.extractfile("upgrade198-copy/inputs/"+n).read())
        raw=b"SAVED_ORIGINAL_FULL_SQL_FILE"
        m.write_new(path/"original-full.sql",raw)
        m.save_json(path/"backup-verified.json",{"file":"original-full.sql","sha256":m.digest(raw)})
        m.save_json(path/"original-before.json",tool.rows)
        return tool

    def test_exact_passed_sql_wrapper_only(self):
        with tarfile.open(ARCHIVE,"r:gz") as t:
            for n,sha in (("rename.sql",m.RENAME),("upgrade.sql",m.UPGRADE)):
                raw=t.extractfile("upgrade198-copy/inputs/"+n).read()
                self.assertEqual(m.strip_copy_guard(raw,sha),raw[len(m.GUARD):])
                with self.assertRaises(RuntimeError):m.strip_copy_guard(raw+b" ",sha)

    def test_apply_exact_35_aliases_then_101_body_and_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=self.seeded(Path(tmp));t.apply()
            self.assertEqual(len(t.ddl),2)
            self.assertEqual(t.ddl[1].count(b"SELECT 'MIGRATION:"),101)
            self.assertNotIn(m.GUARD,t.ddl[0]);self.assertIn("actual_readback_called",t.events)
            with self.assertRaisesRegex(RuntimeError,"already_attempted"):t.apply()
            self.assertEqual(len(t.ddl),2)

    def test_no_partial_ddl_retry_even_lost_reply_after_execution(self):
        for fault in ("rename","upgrade"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                t=self.seeded(Path(tmp));t.fault=fault
                with self.assertRaises(RuntimeError):t.apply()
                count=len(t.ddl);self.assertTrue((Path(tmp)/"original-ddl.send-unknown.json").exists())
                with self.assertRaisesRegex(RuntimeError,"already_attempted"):t.apply()
                self.assertEqual(len(t.ddl),count)

    def test_corrupt_saved_backup_blocks_original_ddl(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=self.seeded(Path(tmp));(Path(tmp)/"original-full.sql").write_bytes(b"corrupt")
            with self.assertRaisesRegex(RuntimeError,"backup_changed"):t.apply()
            self.assertFalse(t.ddl)

    def test_release_completion_waits_for_actual_native_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);t=self.seeded(path)
            m.save_json(path/"original-ddl.send-unknown.json",{})
            m.save_json(path/"original-upgraded-readback.json",{})
            t.fault="readback"
            with self.assertRaisesRegex(RuntimeError,"native_readback_failed"):t.release()
            self.assertTrue((path/"release.send-unknown.json").exists())
            self.assertFalse((path/"released.json").exists())
            self.assertLess(t.events.index("owned_schemas_cleaned_before_unlock"),t.events.index("release_original_sql_accounts_send_unknown_keep_application_stopped"))

    def test_early_owned_lock_cancel_before_original_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);t=Fixture(path,"early-cancel")
            m.save_json(path/"initial-kube-exclusion.json",t.state)
            calls=[]
            t.sql=lambda q,**kw: m.SERVER+"\troot@localhost\n" if "CURRENT_USER" in q else "0\n"
            t.native=lambda script,*a,**kw:calls.append(script) or b""
            lock={"metadata":{"uid":"original-kube-uid","resourceVersion":"native-rv"}}
            def k(*args,**kw):
                if args[0]=="get":return json.dumps(lock).encode()
                options=json.loads(kw["data"])
                self.assertEqual(options["preconditions"],{"uid":"original-kube-uid","resourceVersion":"native-rv"})
                return b"{}"
            t.k=k;t.early_cancel();t.log.close()
            self.assertTrue((path/"early-cancel-completed.json").exists())
            self.assertFalse((path/"original-state.json").exists())
            self.assertEqual(len(calls),1)

    def test_early_cancel_refuses_if_any_native_mutation_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);t=Fixture(path,"early-cancel")
            m.save_json(path/"initial-kube-exclusion.json",t.state)
            m.save_json(path/"event-000000.json",{"event":"create_private_native_recovery_identity_send_unknown"})
            with self.assertRaisesRegex(RuntimeError,"intent_present"):t.early_cancel()
            t.log.close()

    def test_native_original35_identity_missing_prevents_live_drop(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=Fixture(Path(tmp));t.state["original_control_tables"]=[{"name":"system_backups","alias":"dlegacy_35_system_backups","table_id":"100"}]
            schema="cm_native_"+t.state["operation"]
            t.sql=lambda q,**kw: "clawmanager\n"+schema+"\n" if q=="SHOW DATABASES;" else "101\tclawmanager/dlegacy_35_system_backups\n"
            with self.assertRaisesRegex(RuntimeError,"missing_or_replaced"):t.preserve_original_control_tables()
            self.assertFalse(t.ddl)


class BarrierTests(unittest.TestCase):
    def test_actual_native_barrier_refuses_each_missing_fact(self):
        for fault in ("none","readonly","persist","foreign_user","changed_auth","grants","other_session","replication","app","uuid"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp);t=Fixture(path)
                original=t.state["users"][0]
                root={k:v for k,v in original.items() if k!="grants"};root["locked"]="Y"
                own={"user":t.state["user"],"host":"localhost","plugin":"caching_sha2_password","authentication":"private-native-hash","locked":"N"}
                current=[root,own]
                m.save_json(path/"recovery-account.json",{"row":own,"grants":["private-native-grants"]})
                if fault=="foreign_user":current.append(dict(own,user="foreign"))
                if fault=="changed_auth":current[0]["authentication"]="changed"
                t.user_rows=lambda:copy.deepcopy(current)
                def sql(q,**kw):
                    if "@@server_uuid" in q:return ("wrong" if fault=="uuid" else m.SERVER)+"\tmysql\t"+t.state["user"]+"@localhost\t"+("0" if fault=="readonly" else "1")+"\t1\n"
                    if "persisted_variables" in q:return "OFF\n" if fault=="persist" else "ON\n"
                    if "SHOW GRANTS" in q:return "changed\n" if fault=="grants" else ("private-native-grants\n" if t.state["user"] in q else "original-root-grants\n")
                    if "PROCESSLIST" in q:return "32\tother\n" if fault=="other_session" else ""
                    if "replication_connection" in q:return "1\t0\t0\n" if fault=="replication" else "0\t0\t0\n"
                    self.fail("unrecognized real barrier SQL")
                t.sql=sql
                if fault=="app":t.app["spec"]["replicas"]=1
                call=lambda:m.OriginalUpgrade.barrier(t)
                if fault=="none":call()
                else:
                    with self.assertRaises(RuntimeError):call()

class NativeEpochTests(unittest.TestCase):
    def test_late_command_credential_path_is_immutable_and_original_auth_unchanged(self):
        for lost in (False,True):
            with self.subTest(reply_lost=lost),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp);t=Fixture(path)
                old=b"old-original-operation-private-password";m.write_new(path/"recovery-password",old)
                before=copy.deepcopy(t.state["users"]);queries=[];uploads=[]
                def sql(q,**kw):
                    queries.append((t.auth_directory(),q))
                    if "@@server_uuid" in q:return m.SERVER+"\t"+t.state["user"]+"@localhost\n"
                    if q.startswith("ALTER USER") and lost:raise RuntimeError("injected_password_reply_loss")
                    if q=="SELECT CURRENT_USER();":return t.state["user"]+"@localhost\n"
                    if "PROCESSLIST" in q:return "42\n"
                    return ""
                t.sql=sql;t.native=lambda script,*args,**kw:uploads.append((args,kw.get("data"))) or b""
                t.save_recovery_account=lambda name:m.save_json(path/name,{"fixture":"actual native auth readback separately qualified"})
                if lost:
                    with self.assertRaises(RuntimeError):m.OriginalUpgrade.fence_pending_native(t)
                    self.assertFalse((path/"auth-000001.confirmed.json").exists())
                else:
                    m.OriginalUpgrade.fence_pending_native(t)
                    self.assertEqual(t.auth_directory(),t.state["remote"]+"/auth-000001")
                    self.assertTrue((path/"auth-000001.confirmed.json").exists())
                    self.assertIn((t.auth_directory(),"KILL CONNECTION 42;"),queries)
                self.assertEqual((path/"recovery-password").read_bytes(),old)
                self.assertEqual(t.state["users"],before)
                self.assertTrue((path/"auth-000001.intent.json").exists())
                alters=[q for _,q in queries if q.startswith("ALTER USER")]
                self.assertEqual(len(alters),1)
                self.assertIn(t.state["user"],alters[0]);self.assertNotIn("'root'",alters[0])

class RecoveryPodTests(unittest.TestCase):
    def test_recovery_resolves_actual_original_pv_owner_not_caller_pod(self):
        for fault in ("none","pv_replaced","deployment_changed","image_changed","uuid_changed","two_pods","partial_prepare","release_in_progress"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp);a=types.SimpleNamespace(operation_directory=path,context="original",action="recover-controller")
                t=m.OriginalUpgrade(a)
                mysql_spec={"replicas":1,"template":{"spec":{"serviceAccountName":"mysql-sa"}}}
                pod={"metadata":{"name":"mysql-new","uid":"new-actual-pod","ownerReferences":[{"controller":True,"kind":"ReplicaSet","name":"mysql-new-rs","uid":"new-rs-uid"}]},"spec":{"nodeName":"old-worker","serviceAccountName":"mysql-sa","volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"mysql-data"}}]},"status":{"containerStatuses":[{"name":"mysql","ready":True,"imageID":"original-immutable-image","containerID":"new-actual-container"}]}}
                pv={"metadata":{"name":"original-pv","uid":"original-pv-uid"},"spec":{"claimRef":{"uid":"original-claim-uid","namespace":m.NS,"name":"mysql-data"},"hostPath":{"path":"/native/mysql"}}}
                claim={"metadata":{"uid":"original-claim-uid"},"spec":{"volumeName":"original-pv"},"status":{"phase":"Bound"}}
                operation="a"*32
                lock={"metadata":{"uid":"lock-uid"},"data":{"operation":operation,"server_uuid":m.SERVER,"namespace_uid":m.NS_UID}}
                def obj(kind,name):
                    if kind=="namespace":return {"metadata":{"uid":m.NS_UID}}
                    if kind=="deployment":return {"metadata":{"uid":m.MYSQL_UID},"spec":dict(mysql_spec,replicas=2) if fault=="deployment_changed" else mysql_spec}
                    if kind=="replicaset":return {"metadata":{"uid":"new-rs-uid","ownerReferences":[{"controller":True,"kind":"Deployment","uid":m.MYSQL_UID}]}}
                    if kind=="persistentvolumeclaim":return claim
                    if kind=="persistentvolume":
                        value=copy.deepcopy(pv)
                        if fault=="pv_replaced":value["metadata"]["uid"]="foreign-pv-uid"
                        return value
                    if kind=="node":return {"metadata":{"uid":"old-worker-uid"}}
                    if kind=="serviceaccount":return {"metadata":{"uid":"same-sa-uid"}}
                    if kind=="pod":return pod
                    self.fail("unrecognized Kube object "+kind)
                t.obj=obj
                storage=[{"volume":"data","claim":"mysql-data","claim_uid":"original-claim-uid","claim_spec_sha256":m.digest(json.dumps(claim["spec"],sort_keys=True).encode()),"pv":"original-pv","pv_uid":"original-pv-uid","pv_spec_sha256":m.digest(json.dumps(pv["spec"],sort_keys=True).encode()),"local_node":"old-worker","local_node_uid":"old-worker-uid"}]
                proof=b"original-reviewed-readonly-proof"
                state={"operation":operation,"remote":"/tmp/sbk-original-upgrade-"+operation,"pod":"old-pod","pod_uid":"old-pod-uid","container_id":"old-container","user":"cm_upg_"+operation[:24],"storage":storage,"mysql_spec_sha256":m.digest(json.dumps(mysql_spec,sort_keys=True).encode()),"mysql_images":{"mysql":"original-immutable-image"},"mysql_service_account":"mysql-sa","mysql_service_account_uid":"same-sa-uid","kube_lock_uid":"lock-uid","original_proof_sha256":m.digest(proof),"users":[{"user":"root","host":"localhost","plugin":"caching_sha2_password","authentication":"original-root-hash","locked":"N","grants":["original-root-grants"]}]}
                m.save_json(path/"original-state.json",state)
                m.write_new(path/"original-proof",proof);m.write_new(path/"recovery-password",b"original-private-secret")
                for n in ("inventory.json","rename.sql","upgrade.sql","profile.json"):m.write_new(path/n,b"retained-source")
                if fault!="partial_prepare":m.save_json(path/"sql-held.json",{})
                m.save_json(path/"recovery-account.json",{"grants":["same-native-grants"]})
                if fault=="release_in_progress":m.save_json(path/"release.send-unknown.json",{"operation":operation,"original_result_readback_completed":True})
                if fault=="image_changed":pod["status"]["containerStatuses"][0]["imageID"]="other-image"
                calls=[];fences=[]
                t.k=lambda *args,**kw:json.dumps({"items":[pod,pod] if fault=="two_pods" else [pod]} if args[1]=="pods" else lock).encode()
                t.native=lambda script,*args,**kw:calls.append(script) or b""
                t.upload=lambda name,raw:calls.append("upload-"+name)
                t.sql=lambda q,**kw:"original-root-grants\n" if "SHOW GRANTS" in q else ("foreign-server" if fault=="uuid_changed" else m.SERVER)+"\t"+state["user"]+"@localhost\n"
                t.user_rows=lambda:[{k:v for k,v in state["users"][0].items() if k!="grants"},{"user":state["user"],"host":"localhost","plugin":"caching_sha2_password","authentication":"own","locked":"N"}]
                t.barrier=lambda **kw:None
                t.fence_pending_native=lambda **kw:fences.append(kw)
                if fault in ("none","partial_prepare","release_in_progress"):
                    t.recover_controller()
                    binding=json.loads(next(path.glob("controller-recovery-*.json")).read_bytes())
                    self.assertEqual(binding["pod_uid"],"new-actual-pod")
                    self.assertEqual(binding["storage"],storage)
                    self.assertEqual(json.loads((path/"original-state.json").read_bytes())["pod_uid"],"old-pod-uid")
                    self.assertEqual(fences,[] if fault=="release_in_progress" else [{"partial_prepare":fault=="partial_prepare"}])
                else:
                    with self.assertRaises(RuntimeError):t.recover_controller()
                    self.assertFalse(list(path.glob("controller-recovery-*.json")))
                if t.log:t.log.close()

class DiagnosticsTests(unittest.TestCase):
    def test_probes_do_not_strand_locked_root_with_sql_select_healthchecks(self):
        for command,want in ((["mysqladmin","ping","-uroot","-p$MYSQL_ROOT_PASSWORD"],True),(["sh","-c","mysqladmin ping -h 127.0.0.1 -uroot -p${MYSQL_ROOT_PASSWORD}"],True),(["sh","-c","mysql -uroot -e 'SELECT 1'"],False),(["mysqladmin","ping","shutdown"],False),(["sh","-c","mysqladmin ping && mysql -e 'SELECT 1'"],False)):
            with self.subTest(command=command):self.assertEqual(m.account_lock_safe_probe({"exec":{"command":command}}),want)
        self.assertTrue(m.account_lock_safe_probe({"tcpSocket":{"port":3306}}))
    def test_safe_reason_is_static_literal_allowlist_not_regex_or_raw_exception(self):
        for code in ("namespace_replaced","native_background_sql_writer_present","original_rows_changed"):
            self.assertEqual(m.safe_reason(RuntimeError(code)),code)
        for error in (RuntimeError("secret_lowercase_token"),ValueError("original_rows_changed"),RuntimeError("password=PRIVATE"),OSError("private host/DSN/SQL")):
            self.assertEqual(m.safe_reason(error),"private_native_or_custody_error")
        tree=ast.parse((HERE/"system-backup-original-upgrade198.py").read_text(encoding="utf-8"))
        actual={n.args[0].value for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="RuntimeError" and n.args and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str)}
        self.assertEqual(actual,m.SAFE_REASON_CODES)

    def test_safe_migration_progress_does_not_echo_error_or_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);m.save_json(path/"profile.json",{"pending":["001_original.sql"]})
            log=path/"private.log";log.write_bytes(b"MIGRATION:001_original.sql\nERROR 1054 PRIVATE_ROW_AND_PASSWORD\nMIGRATION:999_not_in_fixed_catalog.sql\n")
            result=m.safe_failure_coordinates(path,log)
            self.assertEqual(result,{"mysql_code":1054,"last_observed_migration_marker":"001_original.sql"})
            self.assertNotIn("PRIVATE",json.dumps(result))



class NativeAuthenticationSnapshotTests(unittest.TestCase):
    def test_control_delimiter_bytes_empty_and_full_byte_range_roundtrip(self):
        for native in (b"$A$005$TAB\tLF\nCR\rNUL\0slash\\END", bytes(range(256)), b""):
            with self.subTest(native_length=len(native)):
                encoded = native.hex().upper()
                raw = "root\tlocalhost\tcaching_sha2_password\t"+encoded+"\tN\n"
                rows = m.parse_native_account_snapshot(raw)
                self.assertEqual(bytes.fromhex(rows[0]["authentication"]), native)
                self.assertEqual(rows[0]["authentication"], encoded)
                self.assertEqual(rows[0]["locked"], "N")
        self.assertEqual(m.ACCOUNT_AUTHENTICATION_ENCODING, "mysql_hex_bytes_v1")

    def test_prepare_and_readback_share_exact_hex_query_and_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Fixture(Path(tmp)); queries=[]
            t.sql=lambda query,**kw: queries.append(query) or "root\tlocalhost\tcaching_sha2_password\t090A0D005C\tN\n"
            row=m.OriginalUpgrade.user_rows(t)[0]
            self.assertEqual(row["authentication"], "090A0D005C")
            self.assertEqual(queries,[m.ACCOUNT_SNAPSHOT_SQL])
        tree=ast.parse((HERE/"system-backup-original-upgrade198.py").read_text(encoding="utf-8"))
        prepare=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=="prepare")
        queries=[n for n in ast.walk(prepare) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="sql" and n.args and isinstance(n.args[0],ast.Name) and n.args[0].id=="ACCOUNT_SNAPSHOT_SQL"]
        self.assertEqual(len(queries),1)
        self.assertEqual(next(k.value.value for k in queries[0].keywords if k.arg=="recovery"),False)
        self.assertEqual(m.ACCOUNT_SNAPSHOT_SQL.count("HEX(authentication_string)"),1)

    def test_nonhex_odd_lowercase_or_delimited_auth_fails_closed(self):
        for encoded in ("0", "GG", "aa", "09\t0A", "09\n0A", "NULL", "hash-secret"):
            with self.subTest(encoded=encoded):
                with self.assertRaises(RuntimeError):
                    m.parse_native_account_snapshot("root\tlocalhost\tcaching_sha2_password\t"+encoded+"\tN\n")


class CleanupAndFailedSnapshotTests(unittest.TestCase):
    def cleanup_fixture(self, path, fault=None, absent=False):
        t=Fixture(path,"cleanup");m.save_json(path/"released.json",{})
        t.app["spec"]["replicas"]=1;t.app["status"]["readyReplicas"]=1
        state={"locked":False,"present":not absent,"sessions":["81"],"events":[],"lock":True}
        def rows():
            return [{"user":t.state["user"],"host":"localhost","locked":"Y" if state["locked"] and fault!="lock_readback" else "N"}] if state["present"] else []
        t.user_rows=rows
        def sql(query,**kw):
            self.assertFalse(kw.get("recovery",False))
            if "CURRENT_USER" in query:return m.SERVER+"\troot@localhost\n"
            if query.startswith("ALTER USER"):
                state["events"].append("lock");state["locked"]=True;return ""
            if "PROCESSLIST" in query:
                state["events"].append("eof" if not state["sessions"] else "peers")
                if state["present"]:self.assertTrue(state["locked"],"new login race must close BEFORE peer enumeration")
                return "".join(i+"\n" for i in state["sessions"])
            if query.startswith("KILL CONNECTION"):
                state["events"].append("kill")
                if fault!="peer_remains":state["sessions"].remove(query.split()[-1].rstrip(";"))
                return ""
            if query.startswith("DROP USER"):
                self.assertFalse(state["sessions"]);state["events"].append("drop");state["present"]=False
                if fault=="post_drop_peer":state["sessions"]=["99"]
                return ""
            self.fail("unexpected cleanup SQL")
        t.sql=sql
        t.native=lambda *a,**kw:state["events"].append("scratch_removed") or b""
        def k(*args,**kw):
            if args[0]=="get":return json.dumps({"metadata":{"uid":"original-kube-uid","resourceVersion":"same-rv"}}).encode() if state["lock"] else b""
            self.assertEqual(json.loads(kw["data"])["preconditions"],{"uid":"original-kube-uid","resourceVersion":"same-rv"})
            self.assertFalse(state["present"]);self.assertFalse(state["sessions"])
            state["lock"]=False;state["events"].append("exclusion_deleted");return b"{}"
        t.k=k
        return t,state

    def test_cleanup_locks_before_kill_and_checks_eof_before_and_after_drop(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);t,state=self.cleanup_fixture(path)
            t.cleanup()
            self.assertEqual(state["events"],["lock","peers","kill","eof","drop","eof","scratch_removed","exclusion_deleted"])
            self.assertTrue((path/"cleanup-completed.json").exists())

    def test_cleanup_refuses_marker_and_resource_deletion_until_final_eof(self):
        for fault in ("lock_readback","peer_remains","post_drop_peer"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp);t,state=self.cleanup_fixture(path,fault)
                with self.assertRaises(RuntimeError):t.cleanup()
                self.assertFalse((path/"cleanup-completed.json").exists())
                self.assertNotIn("scratch_removed",state["events"]);self.assertTrue(state["lock"])
                if fault!="post_drop_peer":self.assertNotIn("drop",state["events"])

    def test_cleanup_retry_absent_account_still_kills_and_proves_old_session_eof(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);t,state=self.cleanup_fixture(path,absent=True)
            t.cleanup();self.assertNotIn("lock",state["events"])
            self.assertEqual(state["events"],["peers","kill","eof","drop","eof","scratch_removed","exclusion_deleted"])

    def test_rollback_partial_failed_dump_retries_fresh_file_before_any_ddl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);t=ActualScriptTests().seeded(path)
            m.save_json(path/"original-ddl.send-unknown.json",{})
            m.write_new(path/"failed-original-full.sql",b"OLD_UNSEALED_PARTIAL")
            t.state["database_defaults"]=["utf8mb4","utf8mb4_unicode_ci"]
            t.sql=lambda q,**kw:"1\n"
            attempts=[]
            def native(script,*args,**kw):
                self.assertIn("mysqldump",script)
                attempts.append(kw["output"].name)
                kw["output"].write(b"PARTIAL" if len(attempts)==1 else b"COMPLETE_FAILED_SNAPSHOT")
                if len(attempts)==1:raise TimeoutError("modeled_native_dump_timeout")
                return b""
            t.native=native
            t.dump=lambda n:m.OriginalUpgrade.dump(t,n)
            t.preserve_original_control_tables=lambda:"cm_native_"+t.state["operation"]
            t.restore_original_control_tables=lambda schema:None
            old_usage=m.shutil.disk_usage
            try:
                m.shutil.disk_usage=lambda p:types.SimpleNamespace(free=10**15)
                with self.assertRaises(TimeoutError):t.rollback()
                self.assertFalse(t.ddl);self.assertFalse((path/"failed-original-preserved.json").exists())
                self.assertEqual(Path(attempts[0]).read_bytes(),b"PARTIAL")
                old_exec=t.exclusive_sql
                def guarded_exec(*args,**kw):
                    self.assertTrue((path/"failed-original-preserved.json").exists())
                    return old_exec(*args,**kw)
                t.exclusive_sql=guarded_exec
                t.rollback()
            finally:m.shutil.disk_usage=old_usage
            self.assertEqual(len(set(attempts)),2)
            self.assertEqual((path/"failed-original-full.sql").read_bytes(),b"OLD_UNSEALED_PARTIAL")
            self.assertEqual(Path(attempts[0]).read_bytes(),b"PARTIAL")
            seal=json.loads((path/"failed-original-preserved.json").read_bytes())
            self.assertEqual((path/seal["file"]).read_bytes(),b"COMPLETE_FAILED_SNAPSHOT")
            self.assertEqual(len(list(path.glob("failed-original-*.intent.json"))),2)
            self.assertTrue((path/"original-rollback-readback.json").exists())

    def test_completed_unsealed_failed_dump_is_retained_and_new_attempt_sealed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);t=Fixture(path);files=[]
            def dump(name):
                files.append(name);m.write_new(path/name,b"FULL_FAILED_SNAPSHOT")
                return {"file":name,"sha256":m.file_hash(path/name),"bytes":(path/name).stat().st_size}
            t.dump=dump
            original_save=m.save_json
            try:
                def interrupted_save(p,value):
                    if p.name=="failed-original-preserved.json":raise OSError("modeled_crash_before_seal")
                    original_save(p,value)
                m.save_json=interrupted_save
                with self.assertRaises(OSError):t.preserve_failed_original()
            finally:m.save_json=original_save
            self.assertFalse((path/"failed-original-preserved.json").exists())
            seal=t.preserve_failed_original()
            self.assertEqual(len(set(files)),2);self.assertEqual(seal["file"],files[1])
            self.assertEqual((path/files[0]).read_bytes(),b"FULL_FAILED_SNAPSHOT")
            self.assertEqual(t.preserve_failed_original(),seal);self.assertEqual(len(files),2)

if __name__=="__main__":unittest.main(verbosity=2)
