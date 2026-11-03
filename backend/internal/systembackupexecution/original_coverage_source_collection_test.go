package systembackupexecution

import (
	"encoding/json"
	"testing"
)

func TestOriginalMinIOCoverageScopesPreserveAllThreePinnedRoots(t *testing.T) {
	p := &minioPermissionProductionInputs{}
	p.grant.Provider.Endpoint = "https://original-minio:9000"
	p.grant.Provider.Region = "us-east-1"
	p.grant.Provider.CASHA256 = hash([]byte("original-ca"))
	p.definition.TargetSHA256 = hash([]byte("original-target"))
	p.target.Bucket = "original-artifact"
	p.target.Root = "original/"
	p.target.RemoteStagingRoot = "original_staging/"
	p.catalog.Bucket = "original-catalog"
	p.catalog.Root = "original/catalog/"
	credentialSHA := hash([]byte("original-private-credential"))
	scopes, e := originalMinIOCoverageScopes(p, credentialSHA)
	if e != nil || len(scopes) != 3 {
		t.Fatal("original three scopes lost", e)
	}
	wanted := map[string]string{"artifact": "original", "staging_unknown": "original_staging", "catalog_holds": "original/catalog"}
	for _, scope := range scopes {
		raw, e := json.Marshal(scope.Census.Scope)
		if e != nil || scope.Census.Scope.Prefix != wanted[scope.Purpose] || scope.Census.Scope.CredentialSHA256 != credentialSHA || scope.Census.Source.ContentSHA256 != hash(raw) || len(scope.Census.Members) != 0 || len(scope.Census.Pages) != 0 {
			t.Fatal("scope pin changed or unobserved members invented")
		}
	}
	p.target.RemoteStagingRoot = ""
	if _, e := originalMinIOCoverageScopes(p, credentialSHA); e == nil {
		t.Fatal("missing original staging scope guessed empty")
	}
	p.target.RemoteStagingRoot = "original_staging/"
	p.catalog.Bucket = p.target.Bucket
	if _, e := originalMinIOCoverageScopes(p, credentialSHA); e == nil {
		t.Fatal("artifact/catalog scope alias admitted")
	}
}
