//go:build systembackup_minio_september_native

package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	probe "clawreef/internal/systembackupreferenceprobe"
)

type r20PolicyAudit struct {
	nameSHA256 string
	status int
}

func startR20PolicyAudit(t *testing.T) <-chan r20PolicyAudit {
	t.Helper()
	observed := make(chan r20PolicyAudit, 16)
	listener, err := net.Listen("tcp", ":18080")
	if err != nil {
		t.Fatal("operation=audit_start reason=listener_failed")
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		defer clear(raw)
		var event struct {
			API struct {
				Name string `json:"name"`
				StatusCode int `json:"statusCode"`
			} `json:"api"`
			RequestPath string `json:"requestPath"`
			RequestQuery map[string]string `json:"requestQuery"`
		}
		if err == nil && json.Unmarshal(raw, &event) == nil && event.API.Name == "AddCannedPolicy" &&
			event.RequestPath == "/minio/admin/v3/add-canned-policy" && event.RequestQuery["name"] != "" {
			select {
			case observed <- r20PolicyAudit{hash([]byte(event.RequestQuery["name"])), event.API.StatusCode}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return observed
}

// Report known schema names only. A response value is never printed.
func r20ResponseFieldNames(raw []byte) []string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	var names []string
	unknown := false
	for key := range fields {
		switch key {
		case "PolicyName", "Policy", "CreateDate", "UpdateDate", "policyName", "policy", "createDate", "updateDate", "Code", "Message", "Resource", "RequestId", "HostId", "Region", "BucketName", "Key", "Version", "Statement", "Id":
			names = append(names, key)
		default:
			unknown = true
		}
	}
	if unknown {
		names = append(names, "unknown_field")
	}
	sort.Strings(names)
	return names
}

// Create four permutations of the exact generated two-by-two read policy.
// Each permutation changes only the order of the two specified arrays.
func r20PolicyPermutations(raw []byte) ([][]byte, error) {
	var doc map[string]json.RawMessage
	var statements []map[string]json.RawMessage
	if minioPermissionUniqueJSON(raw) != nil || json.Unmarshal(raw, &doc) != nil ||
		json.Unmarshal(doc["Statement"], &statements) != nil || len(statements) != 1 {
		return nil, errors.New("policy_shape")
	}
	var actions, resources []string
	if json.Unmarshal(statements[0]["Action"], &actions) != nil || len(actions) != 2 || actions[0] == actions[1] ||
		json.Unmarshal(statements[0]["Resource"], &resources) != nil || len(resources) != 2 || resources[0] == resources[1] {
		return nil, errors.New("expected_two_distinct_actions_and_arns")
	}
	sort.Strings(actions)
	sort.Strings(resources)
	var out [][]byte
	for i := 0; i < 4; i++ {
		a, r := append([]string(nil), actions...), append([]string(nil), resources...)
		if i&1 != 0 {
			a[0], a[1] = a[1], a[0]
		}
		if i&2 != 0 {
			r[0], r[1] = r[1], r[0]
		}
		var err error
		statements[0]["Action"], err = ce.Canonical(a)
		if err != nil {
			return nil, err
		}
		statements[0]["Resource"], err = ce.Canonical(r)
		if err != nil {
			return nil, err
		}
		doc["Statement"], err = ce.Canonical(statements)
		if err != nil {
			return nil, err
		}
		variant, err := ce.Canonical(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, variant)
	}
	return out, nil
}

func r20AuditStatus(ctx context.Context, audit <-chan r20PolicyAudit, name string) int {
	nameSHA := hash([]byte(name))
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case event := <-audit:
			if event.nameSHA256 == nameSHA {
				return event.status
			}
		case <-deadline.C:
			return 0
		case <-ctx.Done():
			return 0
		}
	}
}

func TestR20DeleteCompatMultiActionARNOrderReadback(t *testing.T) {
	audit := startR20PolicyAudit(t)
	f, proof := loadCOnceNativeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var root nativePublicationCredential
	cOnceNativeRead(t, "secrets/root.json", &root)
	n := cOnceNativeClient(t, f, root)
	defer n.close()
	if proof.ImageID != ma.DeleteCompatImageManifest || !ma.MatchesDeleteCompatImageReference(f.MinioImage) {
		t.Fatal("operation=fixture_setup reason=actual_final_oci_image_proof_required")
	}
	n.provider.ImageID = proof.ImageID
	rawInfo, infoStatus, e := n.get(ctx, "/minio/admin/v3/info", url.Values{"metrics": {"false"}})
	var info struct {
		DeploymentID string
	}
	if e != nil || infoStatus != http.StatusOK || minioPermissionUniqueJSON(rawInfo) != nil || json.Unmarshal(rawInfo, &info) != nil || info.DeploymentID == "" {
		t.Fatal("operation=fixture_setup reason=authenticated_deployment_discovery_failed")
	}
	id := info.DeploymentID
	n.provider.DeploymentID = id
	if _, e := n.serverBuiltinFlat(ctx, ma.DeleteCompatPermissionProfile); e != nil {
		t.Fatal("operation=fixture_setup reason=final_image_server_profile_failed")
	}
	if _, e := n.serverSeptember(ctx); e == nil {
		t.Fatal("operation=fixture_setup reason=final_image_entered_september_profile")
	}
	wrongImage := *n
	wrongImage.provider.ImageID = "sha256:52dfd5c0bbd38d3219f2058c7af216d9f9a27a994b7b5baad09bbd38866015ff"
	if _, e := wrongImage.serverBuiltinFlat(ctx, ma.DeleteCompatPermissionProfile); e == nil {
		t.Fatal("operation=fixture_setup reason=old_image_accepted_under_new_profile")
	}
	if _, e := wrongImage.serverSeptember(ctx); e == nil {
		t.Fatal("operation=fixture_setup reason=new_server_commit_accepted_under_september_with_old_image_pin")
	}
	p := probe.MinIOProvider{Endpoint: f.Endpoint, Region: f.Region, CAFile: f.CAFile, CASHA256: f.CASHA256, SPKISHA256: f.SPKISHA256, DeploymentID: id, Deployment: probe.ObjectPin{"native", "deployment-uid"}, ReplicaSet: probe.ObjectPin{"native-rs", "rs-uid"}, Pod: probe.ObjectPin{"native-pod", "pod-uid"}, Service: probe.ObjectPin{"native", "service-uid"}, ServiceAccount: probe.ObjectPin{"native", "sa-uid"}, Container: "minio", ImageID: proof.ImageID, Node: "owned-node", NodeUID: "node-uid"}
	profile, ok := ma.NativeProfile(ma.DeleteCompatPermissionProfile)
	if !ok {
		t.Fatal("operation=fixture_setup reason=new_profile_missing")
	}
	model := newMinioSeptemberTerminalComponent(t, "")
	var definition install.MinIOPermissionDefinition
	raw, e := pinnedDeploymentFile(model.input.DefinitionFile, model.input.DefinitionSHA256, 262144)
	if e != nil || decodePublicationCanonical(raw, &definition) != nil {
		t.Fatal("operation=fixture_setup reason=fixture_definition_data_unavailable")
	}
	definition.Version = profile.Definition
	definition.Grant.Profile = profile.Permission
	definition.Grant.Namespace, definition.Grant.NamespaceUID = "owned-native", "owned-namespace-uid"
	definition.Grant.NotBefore, definition.Grant.Until = f.NotBefore, f.Until
	raw, e = ce.Canonical(p)
	if e != nil || decodePublicationCanonical(raw, &definition.Grant.Provider) != nil {
		t.Fatal("operation=fixture_setup reason=fixture_provider_data_cannot_bind")
	}
	target, catalog := model.protocol.p.target, model.protocol.p.catalog
	target.Endpoint, target.Region, target.CAFile, target.CASHA256 = f.Endpoint, f.Region, f.CAFile, f.CASHA256
	catalog.Endpoint, catalog.Region, catalog.CAFile, catalog.CASHA256 = f.Endpoint, f.Region, f.CAFile, f.CASHA256
	target.Bucket, catalog.Bucket = "cp-"+f.Owner[:12], "cc-"+f.Owner[:12]
	templateDirectory := firstInstallPrivateDirectory(t)
	write := func(name string, data any) (string, string) {
		file, sha, err := nativeInstallSave(templateDirectory, name, data)
		if err != nil {
			t.Fatal("operation=fixture_setup reason=fixture_material_write_failed")
		}
		return file, sha
	}
	target.CatalogMaterialsFile, target.CatalogMaterialsSHA256 = write("compat-catalog.json", catalog)
	definition.TargetFile, definition.TargetSHA256 = write("compat-target.json", target)
	template, templateSHA := write("compat-definition.json", definition)
	admin := MinIONativeAdminFiles{UserFile: "/fixture/secrets/root-user", PasswordFile: "/fixture/secrets/root-password"}
	observed, e := InspectOriginalMinIONativeProvider(ctx, template, templateSHA, admin)
	if e != nil || observed["ServerCommit"] != profile.ServerCommit || observed["ServerVersion"] != profile.ServerVersion || observed["DeploymentID"] != p.DeploymentID {
		t.Fatal("operation=fixture_setup reason=native_installer_probe_did_not_observe_new_server")
	}
	directory := firstInstallPrivateDirectory(t)
	out, e := GenerateOriginalMinIONativeMaterials(template, templateSHA, directory)
	if e != nil {
		t.Fatal("operation=fixture_setup reason=new_profile_material_generation_failed")
	}
	var materials MinIONativeInstallMaterials
	raw, e = pinnedDeploymentFile(out.File, out.SHA256, 262144)
	if e != nil || decodePublicationCanonical(raw, &materials) != nil || len(materials.Roles) != 6 {
		t.Fatal("operation=fixture_setup reason=generated_six_role_materials_unavailable")
	}
	for _, bucket := range []string{target.Bucket, catalog.Bucket} {
		for _, args := range [][]string{{"mb", "native/" + bucket}, {"version", "enable", "native/" + bucket}} {
			if e := nativeInstallWriteOnce(ctx, directory, n, nil, args...); e != nil {
				t.Fatal("operation=fixture_setup reason=versioned_bucket_setup_failed")
			}
		}
	}

	var role MinIONativeInstallRole
	for _, entry := range materials.Roles {
		if entry.Purpose == "artifact_read" {
			role = entry
		}
	}
	expected, err := pinnedDeploymentFile(role.PolicyFile, role.PolicySHA256, 65536)
	if err != nil || role.Purpose != "artifact_read" {
		t.Fatal("operation=policy_preflight reason=original_read_policy_unavailable")
	}
	rules, err := minioPermissionObjectRulesForProfile(ma.DeleteCompatPermissionProfile, role.Purpose, target.Bucket, target.Root, target.RemoteStagingRoot)
	if err != nil {
		t.Fatal("operation=policy_preflight reason=original_read_rules_unavailable")
	}
	variants, err := r20PolicyPermutations(expected)
	if err != nil {
		t.Fatal("operation=policy_preflight reason=two_action_two_arn_shape_required")
	}
	names := []string{"forward_actions_forward_arns", "reverse_actions_forward_arns", "forward_actions_reverse_arns", "reverse_actions_reverse_arns"}
	for index, variant := range variants {
		t.Run(names[index], func(t *testing.T) {
			if _, err := minioPermissionNormalizedPolicyV2(variant, role.PolicySHA256, rules); err != nil {
				t.Fatal("operation=policy_preflight reason=permutation_changed_original_policy")
			}
			suffix := string(rune('a' + index))
			name := "r20-"+f.Owner[:12]+"-"+suffix
			file, _, err := nativeInstallSaveRaw(directory, "r20-policy-"+suffix+".json", variant)
			if err != nil {
				t.Fatal("operation=policy_preflight reason=private_file_write_failed")
			}
			writeErr := nativeInstallWriteOnce(ctx, directory, n, nil, "admin", "policy", "create", "native", name, file)
			status := r20AuditStatus(ctx, audit, name)
			if status < 200 || status >= 300 {
				t.Fatalf("operation=add_canned_policy http=%d reason=success_audit_unconfirmed", status)
			}
			t.Logf("operation=add_canned_policy http=%d reason=server_audit", status)
			if writeErr != nil {
				t.Fatalf("operation=policy_create_once reason=readback_refused commit_unknown=%t", errors.Is(writeErr, install.ErrCommitUnknown))
			}
			t.Log("operation=policy_create_once reason=original_readback_accepted")
			read := *n
			read.requests = 0
			raw, status, err := read.get(ctx, "/minio/admin/v3/info-canned-policy", url.Values{"name": {name}, "v": {"2"}})
			defer clear(raw)
			var value struct {
				PolicyName string
				Policy json.RawMessage
				CreateDate, UpdateDate time.Time
			}
			if err != nil || status != http.StatusOK || minioPermissionDecode(raw, &value) != nil || value.PolicyName != name {
				t.Fatalf("operation=info_canned_policy http=%d reason=typed_readback_failed fields=%v", status, r20ResponseFieldNames(raw))
			}
			if _, err := minioPermissionNormalizedPolicyV2(value.Policy, role.PolicySHA256, rules); err != nil {
				t.Fatalf("operation=info_canned_policy http=%d reason=original_pin_or_rules_mismatch fields=%v policy_fields=%v", status, r20ResponseFieldNames(raw), r20ResponseFieldNames(value.Policy))
			}
			matches := 0
			for _, alternative := range variants {
				if sourceGatePolicySame(value.Policy, alternative) {
					matches++
					continue
				}
				if !nativeInstallPolicyReadbackSame(ctx, n, value.Policy, alternative) || nativeInstallPolicyReadbackSame(ctx, &wrongImage, value.Policy, alternative) {
					t.Fatal("operation=order_comparison reason=image_scope_mismatch")
				}
				wrongServer := *n
				wrongServer.provider.DeploymentID = "wrong-deployment-id"
				if nativeInstallPolicyReadbackSame(ctx, &wrongServer, value.Policy, alternative) {
					t.Fatal("operation=order_comparison reason=server_identity_scope_mismatch")
				}
			}
			if matches != 1 {
				t.Fatalf("operation=info_canned_policy http=%d reason=readback_not_exactly_one_permutation fields=%v policy_fields=%v", status, r20ResponseFieldNames(raw), r20ResponseFieldNames(value.Policy))
			}
			reason := "actual_order_matches_submitted"
			if !sourceGatePolicySame(value.Policy, variant) {
				reason = "actual_order_differs_from_submitted"
			}
			t.Logf("operation=info_canned_policy http=%d reason=%s fields=%v policy_fields=%v", status, reason, r20ResponseFieldNames(raw), r20ResponseFieldNames(value.Policy))
			if index == 0 {
				r20RefusePolicyDrift(t, ctx, n, directory, name, target.Bucket, variant)
			}
		})
	}
}

// Query the real existing policy with intentionally different local intents.
// The observation path refuses drift before it can authorize a mutation.
func r20RefusePolicyDrift(t *testing.T, ctx context.Context, n *minioPermissionHTTP, directory, policyName, bucket string, expected []byte) {
	t.Helper()
	statement, prefixOK := bytes.CutPrefix(expected, []byte(`{"Statement":[`))
	statement, suffixOK := bytes.CutSuffix(statement, []byte(`],"Version":"2012-10-17"}`))
	if !prefixOK || !suffixOK {
		t.Fatal("operation=negative_fixture reason=expected_canonical_generated_policy")
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"action", `"s3:GetObjectVersion"`, `"s3:PutObject"`},
		{"resource", "arn:aws:s3:::" + bucket + "/", "arn:aws:s3:::different-bucket/"},
		{"condition", `"Effect":"Allow"`, `"Condition":{"Bool":{"aws:SecureTransport":"true"}},"Effect":"Allow"`},
		{"duplicate_action", `"s3:GetObjectVersion"`, `"s3:GetObjectVersion","s3:GetObjectVersion"`},
		{"duplicate_statement", string(statement), string(statement) + "," + string(statement)},
		{"extra_field", `"Effect":"Allow"`, `"Effect":"Allow","Sid":"different-statement"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drift := bytes.Replace(expected, []byte(tc.old), []byte(tc.replacement), 1)
			if bytes.Equal(drift, expected) || minioPermissionUniqueJSON(drift) != nil {
				t.Fatal("operation=negative_fixture reason=expected_valid_distinct_json")
			}
			file, _, err := nativeInstallSaveRaw(directory, "r20-negative-"+tc.name+".json", drift)
			if err != nil {
				t.Fatal("operation=negative_fixture reason=private_file_write_failed")
			}
			op, err := nativeInstallOncePlan(n, nil, []string{"admin", "policy", "create", "native", policyName, file})
			if err != nil {
				t.Fatal("operation=negative_fixture reason=observe_plan_failed")
			}
			defer clear(op.plain)
			if matched, err := op.observe(ctx); matched || !errors.Is(err, install.ErrInstall) {
				t.Fatal("operation=info_canned_policy reason=drift_not_refused")
			}
		})
	}
}
