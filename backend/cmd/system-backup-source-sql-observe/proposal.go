package main

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/schemaobjects"
)

type sourceAccountProposal struct {
	Version, Status, Database, ServerUUID, ServiceUID string
	SourceAccount, LockedCensusDefiner                string
	SourceGrants, LockedDefinerGrants                 []string
	CreateLockedDefinerSQL, CreateCensusRoutineSQL    string
	ExpectedCensus                                    domain.SchemaCensusSpec
	OptionalTables                                    []string
	SourceCredentialDelivery, ExistingObjectsPolicy   string
	DatabaseMutated, PermissionsApplied, Ready        bool
}

// Pure proposal from the SAME production census/table policy. It never opens
// SQL, reads a password, grants permissions, creates a user or replaces a routine.
func sourceProposal(p sourcePlan) (sourceAccountProposal, error) {
	var zero sourceAccountProposal
	source := strings.Split(p.Account, "@")
	definer := strings.Split(p.Census.Definer, "@")
	projection, err := domain.SchemaCensusProjection(p.Database, p.Census.Definer, p.Census.PartialRevokes)
	if err != nil || !regexp.MustCompile(`^[A-Za-z0-9_]+@[A-Za-z0-9_.:%-]+$`).MatchString(p.Account) || len(source) != 2 || len(definer) != 2 || p.Account == p.Census.Definer || source[0] == "root" || source[1] == "%" || definer[0] == "root" || definer[1] == "%" {
		return zero, errObserve
	}
	account := "'" + source[0] + "'@'" + source[1] + "'"
	owner := "'" + definer[0] + "'@'" + definer[1] + "'"
	definition := "BEGIN " + projection + "; END"
	expected := domain.SchemaCensusSpec{Version: domain.SchemaCensusVersion, Definer: p.Census.Definer, DefinitionSHA256: hash([]byte(definition)), PartialRevokes: p.Census.PartialRevokes}
	if p.Census.DefinitionSHA256 != "" && p.Census.DefinitionSHA256 != expected.DefinitionSHA256 {
		return zero, errObserve
	}
	result := sourceAccountProposal{Version: "original-production-source-account-proposal.v1", Status: "REVIEW_REQUIRED_NO_SQL_EXECUTED", Database: p.Database, ServerUUID: p.ServerUUID, ServiceUID: p.ServiceUID, SourceAccount: p.Account, LockedCensusDefiner: p.Census.Definer, ExpectedCensus: expected, OptionalTables: schemaobjects.OptionalBusinessTables(), SourceCredentialDelivery: "DBA creates/delivers the separate finite source account using its existing secure credential workflow, with REQUIRE SSL; no password or user creation is generated for this login.", ExistingObjectsPolicy: "No IF NOT EXISTS, ALTER, DROP, replace or grant execution is performed. DBA first verifies actual server UUID/schema/account/partial_revokes and optional table existence; locked definer is distinct, never a controller/installer/source login. Reject conflicts instead of overwriting original objects."}
	for _, table := range domain.BusinessCaptureTables() {
		result.SourceGrants = append(result.SourceGrants, "GRANT SELECT ON `"+p.Database+"`.`"+table+"` TO "+account+";")
	}
	result.SourceGrants = append(result.SourceGrants, "GRANT SHOW_ROUTINE ON *.* TO "+account+";", "GRANT EXECUTE ON PROCEDURE `"+p.Database+"`.`"+domain.SchemaCensusRoutine+"` TO "+account+";")
	grantSchema := p.Database
	if !p.Census.PartialRevokes {
		grantSchema = strings.ReplaceAll(grantSchema, "_", `\_`)
	}
	result.LockedDefinerGrants = []string{"GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON `" + grantSchema + "`.* TO " + owner + ";", "GRANT SHOW_ROUTINE ON *.* TO " + owner + ";", "GRANT SELECT ON mysql.global_grants TO " + owner + ";", "GRANT SELECT ON mysql.role_edges TO " + owner + ";"}
	result.CreateLockedDefinerSQL = "CREATE USER " + owner + " ACCOUNT LOCK;"
	result.CreateCensusRoutineSQL = "CREATE DEFINER=" + owner + " PROCEDURE `" + p.Database + "`.`" + domain.SchemaCensusRoutine + "`() READS SQL DATA SQL SECURITY DEFINER " + definition
	return result, nil
}

func writeSourceProposal(p sourcePlan, out io.Writer) int {
	proposal, err := sourceProposal(p)
	if err != nil || json.NewEncoder(out).Encode(proposal) != nil {
		return 1
	}
	return 0
}
