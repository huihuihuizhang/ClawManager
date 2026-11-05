import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("operator_entry", HERE / "system-backup-zhanghui08-operator.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OperatorEntryTests(unittest.TestCase):
    def fixture(self, path):
        root = path / "release"; root.mkdir()
        run = path / "run"; run.mkdir(mode=0o700)
        kube = run / "operator.kubeconfig.json"; m.create(kube, b"original-private-kubeconfig")
        a = types.SimpleNamespace(release_directory=root, run_directory=run, sql_account_host=None, allow_wildcard_host=False, copy_receipts_directory=None)
        t = m.Operator(a); t.kube = kube
        t.pins = {"files": {"bin/system-backup-source-tls-bootstrap": "a" * 64, "bin/system-backup-original-enroll": "b" * 64}}
        t.open = lambda: {"cluster_uid": "actual-kube-system-uid", "app_replicas": 0}
        early = patch.object(m, "early_preflight_module", return_value=types.SimpleNamespace(require_early_shapes=lambda actual: None))
        early.start(); self.addCleanup(early.stop)
        t.upgraded_released = t.open
        # Native current-runtime refusal is covered by the separate wiring suite.
        t.require_current_runtime_qualification = lambda: None
        password = run / "password"; m.create(password, b"existing-private-password")
        return t, password

    def recorded(self, t, stage, value):
        p = t.run / (stage + ".stdout.private"); m.save(p, value)
        m.save(t.run / (stage + ".readback.json"), {"stage": stage, "stdout": str(p), "stdout_sha256": m.sha(p)})
        return p

    def test_db_prepare_uses_only_fixed_native_operation_and_actual_release_pins(self):
        with tempfile.TemporaryDirectory() as temp:
            t, _ = self.fixture(Path(temp)); calls=[]
            t.a.copy_receipts_directory = t.run / "actual-copy199-receipts"
            t.invoke=lambda stage,argv,**kw: calls.append((stage,argv,kw)) or ({"state":"native-held"},t.run/"receipt")
            t.db("prepare")
            stage,argv,kw=calls[0]
            self.assertEqual(stage,"db-prepare")
            self.assertEqual(argv[2],t.root/m.NATIVE)
            self.assertEqual(argv[3],"prepare")
            self.assertEqual(argv[argv.index("--operation-directory")+1],t.run/"original199")
            self.assertEqual(argv[-1],m.PROOF_SHA)
            self.assertEqual(argv[argv.index("--copy-receipts-directory")+1],t.a.copy_receipts_directory)
            self.assertEqual(kw["env"]["KUBECONFIG"],str(t.kube))
            self.assertFalse(kw["repeat"])

    def test_db_prepare_without_fresh_copy_receipts_never_dispatches(self):
        with tempfile.TemporaryDirectory() as temp:
            t, _ = self.fixture(Path(temp)); calls=[]
            t.invoke=lambda *a,**kw: calls.append((a,kw))
            with self.assertRaisesRegex(m.Stop,"fresh_copy199_native_receipts_directory_required"):
                t.db("prepare")
            self.assertEqual(calls,[])

    def test_timeout_retains_exact_dispatch_and_refuses_second_forward_send(self):
        with tempfile.TemporaryDirectory() as temp:
            t, _=self.fixture(Path(temp));calls=[]
            def timeout(*args,**kw):
                calls.append(args);kw["stdout"].write(b"PARTIAL_PRIVATE_RESULT")
                raise subprocess.TimeoutExpired("native-tool",1)
            with patch.object(m.subprocess,"run",timeout):
                with self.assertRaises(subprocess.TimeoutExpired):t.invoke("db-apply",["native","apply"])
                with self.assertRaisesRegex(m.Stop,"already_sent"):t.invoke("db-apply",["native","apply"])
            self.assertEqual(len(calls),1)
            self.assertTrue((t.run/"db-apply.send-unknown.json").exists())
            self.assertFalse((t.run/"db-apply.readback.json").exists())
            self.assertEqual((t.run/"db-apply.stdout.private").read_bytes(),b"PARTIAL_PRIVATE_RESULT")

    def test_repeated_explicit_query_has_fresh_receipts_same_native_operation(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_=self.fixture(Path(temp));calls=[]
            def run(argv,**kw):
                calls.append(argv);kw["stdout"].write(b'{"state":"same-operation-read"}')
                return types.SimpleNamespace(returncode=0)
            with patch.object(m.subprocess,"run",run):
                t.db("query");t.db("query")
            self.assertEqual(calls[0],calls[1])
            self.assertEqual(len(list(t.run.glob("db-query-*.readback.json"))),2)
            self.assertFalse((t.run/"db-apply.send-unknown.json").exists())

    def test_modified_retained_producer_receipt_blocks_consumption(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_=self.fixture(Path(temp));p=self.recorded(t,"tls-inspect",{"PlanFile":"original"})
            p.write_bytes(b'{"PlanFile":"changed"}')
            with self.assertRaisesRegex(m.Stop,"receipt_changed"):t.completed("tls-inspect")

    def test_tls_apply_derives_original_admin_and_plan_not_default_name(self):
        with tempfile.TemporaryDirectory() as temp:
            t,password=self.fixture(Path(temp));plan=t.run/"original-tls-plan.json"
            m.save(plan,{"AdminUsername":"actual-bcrypt-selected-user"})
            self.recorded(t,"tls-inspect",{"PlanFile":str(plan),"PlanSHA256":m.sha(plan),"Operation":"original-tls-operation"})
            calls=[]
            t.invoke=lambda stage,argv,**kw: calls.append(argv) or ({"OperatorSQLTLSVerified":True,"State":"native-verified"},t.run/"receipt")
            with patch.object(m,"PASSWORD",password):t.tls("apply")
            argv=calls[0]
            self.assertEqual(argv[argv.index("--local-admin-username")+1],"actual-bcrypt-selected-user")
            self.assertEqual(argv[argv.index("--operation")+1],"original-tls-operation")
            self.assertEqual(argv[argv.index("--local-admin-password-file")+1],password)
            self.assertNotIn(password.read_text(),[str(x) for x in argv])

    def sql_fixture(self,path):
        t,password=self.fixture(path)
        self.recorded(t,"tls-apply",{"OperatorSQLTLSVerified":True})
        self.recorded(t,"sql-inspect",{"inventory_sha256":"c"*64})
        # Model the retained v4/199 operation-file contract with real private
        # bytes and hashes. Native SQL/account validation stays in its suite.
        operation_directory = t.run/"sql-accounts"; operation_directory.mkdir(mode=0o700)
        operation = operation_directory/"operation.json"
        m.save(operation,{"Version":"original-c1-minio-metadata-sql-accounts-operation.v4",
            "Operation":"0123456789abcdef0123456789abcdef",
            "ServerUUID":"11111111-2222-3333-4444-555555555555","Database":"clawmanager",
            "LedgerSHA256":"c"*64,"KubeconfigSHA256":m.sha(t.kube)})
        operation_pin = {"operation_file":str(operation),"operation_sha256":m.sha(operation)}
        native_prepare = operation_directory/"prepare.native.private.json"
        m.save(native_prepare,{"state":"original_c1_sql_accounts_prepared_no_sql_mutation",**operation_pin})
        self.recorded(t,"sql-prepare",{"state":"original_c1_sql_accounts_prepared_no_sql_mutation",
            "receipt_file":str(native_prepare),"receipt_sha256":m.sha(native_prepare),**operation_pin})
        return t,password

    def test_sql_inspect_uses_actual_scope_and_tls_output_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            t,password=self.sql_fixture(Path(temp));calls=[]
            t.invoke=lambda stage,argv,**kw: calls.append(argv) or ({"state":"inventory"},t.run/"receipt")
            with patch.object(m,"PASSWORD",password):t.sql("inspect")
            argv=calls[0]
            self.assertEqual(argv[3],"inspect")
            self.assertEqual(argv[argv.index("--cluster-uid")+1],"actual-kube-system-uid")
            file=argv[argv.index("--tls-receipt-file")+1]
            self.assertEqual(argv[argv.index("--tls-receipt-sha256")+1],m.sha(file))
            self.assertNotIn("--local-admin-username",argv)

    def test_sql_host_is_explicit_and_percent_never_silently_selected(self):
        with tempfile.TemporaryDirectory() as temp:
            t,password=self.sql_fixture(Path(temp));calls=[]
            t.invoke=lambda *a,**kw:calls.append(a)
            with patch.object(m,"PASSWORD",password):
                with self.assertRaisesRegex(m.Stop,"no_default_percent"):t.sql("prepare")
            self.assertFalse(calls)
            self.assertFalse((t.run/"sql-account-host-selection.json").exists())

    def test_sql_enroll_consumes_native_prepare_and_unique_original_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            t,password=self.sql_fixture(Path(temp));calls=[]
            m.save(t.run/"sql-account-host-selection.json",{"host":"actual-host","allow_wildcard_host":False})
            t.invoke=lambda stage,argv,**kw:calls.append(argv) or ({"state":"enrolled"},t.run/"receipt")
            with patch.object(m,"PASSWORD",password):t.sql("enroll")
            argv=calls[0]
            self.assertEqual(argv[argv.index("--prepare-receipt-sha256")+1],m.sha(t.run/"sql-accounts/prepare.native.private.json"))
            self.assertEqual(argv[argv.index("--prepare-receipt-file")+1],str(t.run/"sql-accounts/prepare.native.private.json"))
            self.assertEqual(argv[argv.index("--runtime-profile")+1],"public-runtime-c1-minio-metadata-read.v1")
            self.assertEqual(argv[argv.index("--enrollment-output-directory")+1],t.run/"original-enrollment")
            self.assertEqual(argv[argv.index("--pre-enroll-query-receipt-file")+1],t.run/"enrollment-pre-query.private.json")
            self.assertNotIn("--local-admin-username",argv)

    def test_sql_rollback_intent_blocks_later_apply_and_enrollment(self):
        with tempfile.TemporaryDirectory() as temp:
            t,password=self.sql_fixture(Path(temp));m.save(t.run/"sql-rollback-123.send-unknown.json",{});calls=[]
            t.invoke=lambda *a,**kw:calls.append((a,kw))
            with patch.object(m,"PASSWORD",password):
                for action in ("apply","enroll"):
                    with self.subTest(action=action),self.assertRaisesRegex(m.Stop,"rollback_started"):t.sql(action)
            self.assertEqual(calls,[])



class OperatorDownstreamTests(OperatorEntryTests):
    # Reuse helpers, without inheriting/rerunning the original test methods.
    def downstream_fixture(self,path):
        t,password=self.fixture(path)
        selected=t.run/"actual-source-selection.json";m.save(selected,{"Controller":{"Pod":"actual-controller"}})
        writer=t.run/"actual-writer-selection.json";m.save(writer,{"Version":"original-writer-set-selection.v1"})
        binding={"source_selection":{"File":str(selected),"SHA256":m.sha(selected)},"writer_selection":{"File":str(writer),"SHA256":m.sha(writer)},"identity":{"controller":{"uid":"original-controller"}}}
        t.owner_common=lambda:["-original-authenticated-input","pinned-file"]
        t.final_binding=lambda:binding
        t.check_final_identity=lambda b:None
        return t,password,binding

    def test_adopt_query_uses_original_disabled_owner_query_never_new_adopt_or_issuer(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_,binding=self.downstream_fixture(Path(temp));calls=[]
            m.save(t.run/"adopt.send-unknown.json",{})
            binary=t.root/"production-entry-fixture";m.create(binary,b"explicit model, not an executable")
            t.pins["files"]["bin/system-backup-first-adoption-production"]=m.sha(binary)
            t.deployment_stages=lambda:types.SimpleNamespace(binary=lambda name:binary)
            source=t.run/"owner-query-input.json";m.save(source,{"fixture":"original typed input locations"})
            self.recorded(t,"adopt-prepare-inputs",{"Version":"original-first-adoption-input-receipt.v1","DisabledInitializationQuery":{"File":str(source),"SHA256":m.sha(source)}})
            value={"State":"disabled_v1_committed_exact_readback_dependencies_unverified","CurrentHealth":"unknown","KEKAdmission":"absent","Result":{"version":1,"operation_public_id":"op_original_fixture"}}
            t.invoke=lambda stage,argv,**kw:calls.append((stage,argv,kw)) or (value,t.run/"receipt")
            result=t.adoption("adopt-query")
            self.assertEqual(calls[0][1][:3],[binary,"--action","query-disabled-initialization"])
            self.assertEqual(calls[0][1][calls[0][1].index("--inputs-file")+1],str(source))
            self.assertEqual(calls[0][1][calls[0][1].index("--inputs-sha256")+1],m.sha(source))
            self.assertNotIn("run",calls[0][1]);self.assertNotIn("-issuer-definition-file",calls[0][1])
            self.assertTrue(calls[0][2]["repeat"])
            self.assertFalse(result["source_recovery_verified"]);self.assertFalse(result["resubmit_allowed"])
            self.assertFalse(result["backup_ready"])

    def test_adopt_query_without_original_dispatch_never_creates_or_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_,_=self.downstream_fixture(Path(temp));calls=[]
            t.invoke=lambda *a,**kw:calls.append((a,kw))
            with self.assertRaisesRegex(m.Stop,"no_original_adoption_dispatch_to_query"):
                t.adoption("adopt-query")
            self.assertEqual(calls,[])

    def test_adopt_identity_drift_blocks_before_any_native_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_,_=self.downstream_fixture(Path(temp));calls=[]
            t.check_final_identity=lambda b:m.require(False,"controller_drift")
            t.invoke=lambda *a,**kw:calls.append(a)
            with self.assertRaisesRegex(m.Stop,"controller_drift"):t.adoption("adopt")
            self.assertFalse(calls)

    def test_commit_only_query_cannot_satisfy_adoption_before_composition(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_,_=self.downstream_fixture(Path(temp))
            self.recorded(t,"adopt",{"State":"original_adoption_commit_verified_only_source_recovery_not_claimed","SourceRecoveryVerified":False})
            with self.assertRaisesRegex(m.Stop,"actual_same_process_production_adoption_and_source_recovery_required"):t.require_adopted()

    def test_composition_calls_actual_enrolled_check_then_same_pinned_apply(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_,_=self.downstream_fixture(Path(temp));t.require_adopted=lambda:None
            comp=t.run/"actual-composition.json";dep=t.run/"actual-deployment.json"
            m.save(comp,{"Version":"enrolled-bootstrap-production-composition.v4"});m.save(dep,{"actual":"producer"})
            m.save(t.run/"bootstrap-consumption.json",{"actual":"retained-original-request"})
            t.a.composition_file=comp;t.a.deployment_file=dep;calls=[]
            t.invoke=lambda stage,argv,**kw:calls.append(argv) or ({"status":"disabled_config_initialized"},t.run/"receipt")
            t.composition("composition-check")
            self.recorded(t,"composition-check",{"status":"check"})
            t.composition("composition")
            self.assertEqual(calls[0][1],"--check");self.assertEqual(calls[1][1],"--apply")
            self.assertEqual(calls[0][2:],calls[1][2:])
            self.assertEqual(calls[1][calls[1].index("--composition-sha256")+1],m.sha(comp))
            comp.write_bytes(b"changed")
            with self.assertRaisesRegex(m.Stop,"pin_changed"):t.composition("composition")
            self.assertEqual(len(calls),2)

    def test_enable_uses_fixed_private_password_and_only_interactive_totp(self):
        with tempfile.TemporaryDirectory() as temp:
            t,password,binding=self.downstream_fixture(Path(temp));t.require_adopted=lambda:None
            self.recorded(t,"composition",{"status":"disabled_config_initialized"})
            ca=t.run/"actual-web-ca.pem";m.create(ca,b"INDEPENDENT_CA");t.a.web_ca_file=ca
            calls=[];order=[]
            production,bridge,native=object(),object(),object()
            def capacity_start(operator,actual_production,actual_bridge,actual_native):
                self.assertIs(operator,t)
                self.assertIs(actual_production,production);self.assertIs(actual_bridge,bridge);self.assertIs(actual_native,native)
                order.append("capacity-start")
                # Model only the new dependency's durable start marker so
                # the second enable observes it rather than dispatching again.
                directory=t.run/"production-adoption";directory.mkdir(mode=0o700)
                m.save(directory/"capacity-collector-start-intent.json",{"fixture":"original-capacity-start"})
            def capacity_query(operator):
                self.assertIs(operator,t);order.append("capacity-query")
            capacity=types.SimpleNamespace(start=capacity_start,query=capacity_query)
            def authenticate(*args):
                order.append("authenticate");return object(),"actual-original-installation"
            def enable(api,installation,journal,check,prompt,verify_readiness=True):
                order.append("enable")
                self.assertFalse(verify_readiness)
                check();calls.append((installation,journal,prompt("Existing local admin password (hidden): "),prompt("Current enrolled TOTP code (hidden): ")))
                return {"status":"ENABLED_AND_API_READBACK_VERIFIED"}
            t.web_modules=lambda:(types.SimpleNamespace(enable=enable),None)
            t.authenticated_api=authenticate
            with (patch.object(m,"PASSWORD",password),
                  patch.object(m.getpass,"getpass",lambda msg:"123456"),
                  patch.object(m,"live_capacity_module",return_value=capacity),
                  patch.object(m,"production_adoption_module",return_value=production),
                  patch.object(m,"c1_mysql_bridge_module",return_value=bridge),
                  patch.object(m,"c1_native_module",return_value=native)):
                t.normal_api("enable")
                with self.assertRaises(FileExistsError):t.normal_api("enable")
            self.assertEqual(len(calls),1);self.assertEqual(calls[0][2],password.read_text());self.assertEqual(calls[0][3],"123456")
            self.assertEqual(order,["capacity-start","authenticate","enable","capacity-query"])
            for file in t.run.glob("*.json"):self.assertNotIn(password.read_text(),file.read_text())

    def test_enable_unknown_resolution_only_invokes_original_get_resolver(self):
        with tempfile.TemporaryDirectory() as temp:
            t,_,_=self.downstream_fixture(Path(temp));ca=t.run/"actual-web-ca.pem";m.create(ca,b"INDEPENDENT_CA")
            m.save(t.run/"web-ca-binding.json",{"File":str(ca),"SHA256":m.sha(ca)})
            calls=[]
            resolver=types.SimpleNamespace(journal=lambda directory,installation:({"same":"original-request"},{"same":"actor"}),resolve=lambda api,original,binding:calls.append((original,binding)) or {"status":"ORIGINAL_ENABLE_COMMIT_VERIFIED","deployment_readiness_verified":False})
            t.web_modules=lambda:(object(),resolver);t.authenticated_api=lambda *a:(object(),"actual-installation")
            result=t.normal_api("enable-resolve")
            self.assertEqual(len(calls),1);self.assertFalse(result["deployment_readiness_verified"])
            self.assertFalse((t.run/"enable.send-unknown.json").exists())

# Keep helper reuse while declaring only six new test roots.
for _name in list(OperatorEntryTests.__dict__):
    if _name.startswith("test_"):setattr(OperatorDownstreamTests,_name,None)


class OriginalBootstrapResolutionTests(unittest.TestCase):
    def test_bootstrap_query_uses_same_request_and_seals_exact_observation_only(self):
        with tempfile.TemporaryDirectory() as temp:
            helper=OperatorEntryTests();t,_=helper.fixture(Path(temp))
            t.owner_common=lambda:["-actual-original-owner","file"]
            files={}
            for key in ("composition","deployment","consumption"):
                file=t.run/(key+".json");m.save(file,{"actual_producer":key})
                files[key]={"File":str(file),"SHA256":m.sha(file)}
            m.save(t.run/"composition-input-pins.json",files);m.save(t.run/"composition.send-unknown.json",{})
            out=t.run/"query-result.private";m.save(out,{"State":"original_bootstrap_commit_exact_readback_only_no_new_write","Result":{"version":1,"operation_public_id":"actual-original-operation"}})
            calls=[]
            t.invoke=lambda stage,argv,**kw:calls.append((argv,kw)) or (m.load(out),out)
            result=t.composition_query()
            self.assertEqual(calls[0][0][1],"query-original");self.assertNotIn("--apply",calls[0][0])
            self.assertTrue(calls[0][1]["repeat"])
            self.assertEqual(calls[0][0][calls[0][0].index("-consumption-file")+1],files["consumption"]["File"])
            self.assertFalse(result["resubmit_allowed"])
            t.require_configuration()
            out.write_bytes(b'{"State":"foreign"}')
            with self.assertRaisesRegex(m.Stop,"pin_changed"):t.require_configuration()

    def test_bootstrap_query_requires_original_dispatch_and_never_creates_apply(self):
        with tempfile.TemporaryDirectory() as temp:
            helper=OperatorEntryTests();t,_=helper.fixture(Path(temp));t.owner_common=lambda:[];calls=[]
            t.invoke=lambda *a,**kw:calls.append(a)
            with self.assertRaisesRegex(m.Stop,"no_original_configuration_dispatch"):t.composition_query()
            self.assertFalse(calls);self.assertFalse((t.run/"composition.send-unknown.json").exists())

if __name__=="__main__":unittest.main(verbosity=2)
