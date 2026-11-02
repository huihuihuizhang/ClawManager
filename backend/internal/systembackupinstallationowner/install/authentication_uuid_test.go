package install

import (
	"strings"
	"testing"

	owner "clawreef/internal/systembackupinstallationowner"
)

func TestOwnerEnrollRequiresFullOriginalServerUUID(t *testing.T) {
	h := strings.Repeat("a", 64)
	p := Plan{SchemaVersion: PlanVersion, EnrollmentName: "owner-enrollment", EnrollmentID: "enrollment-1", IssuerID: "owner-1", EnrollmentRevision: 1, Target: owner.Target{InstallationID: "installation_test", ServerUUID: "01234567-89ab-cdef-0123-456789abcdef", Database: "owner_fixture", DatabaseAccount: "bootstrap@localhost", ClusterID: "cluster-uid", Namespace: "backup-system", NamespaceUID: "namespace-uid"}, InstallerDatabaseAccount: "installer@localhost", LocalAdminUsername: "actual-admin", OwnerUsername: "original-kube-owner", OwnerUID: "owner-uid", OwnerGroups: []string{"system:authenticated", "system:masters"}, IssuerPublicKeySHA256: h, KubernetesAPI: "https://api.original.invalid", KubernetesCASHA256: h, DatabaseCASHA256: h, DatabaseTLSServerName: "mysql.original.invalid"}
	if !validPlan(p) {
		t.Fatal("complete original 8-4-4-4-12 UUID rejected")
	}
	for _, uuid := range []string{"01234567-89ab-cdef-456789abcdef", "01234567-89ab-cdef-0123-456789abcde", "01234567-89ab-cdef-0123-456789abcdeg", "01234567-89AB-cdef-0123-456789abcdef", "0123456789abcdef0123456789abcdef"} {
		p.Target.ServerUUID = uuid
		if validPlan(p) {
			t.Fatal("malformed original UUID accepted", uuid)
		}
	}
}
