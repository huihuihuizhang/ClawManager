package systembackupexecution

import (
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	sh "clawreef/internal/systembackupskillhub"
	"testing"
	"time"
)

func TestBootstrapSourceSQLChangeClassifiesWithoutRelaxingComparison(t *testing.T) {
	for _, name := range []string{"none", "missing", "clock", "users", "instances", "team", "skills", "inventory_other", "metadata", "bindings", "pods"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			first := &bootstrapSourceSQLFacts{clock: now}
			last := &bootstrapSourceSQLFacts{clock: now.Add(time.Second)}
			switch name {
			case "missing":
				last = nil
			case "clock":
				last.clock = now.Add(-time.Second)
			case "users":
				last.inventory.Users = []int{1}
			case "instances":
				last.inventory.Instances = []b.InstanceIdentity{{ID: 1}}
			case "team":
				last.inventory.TeamFacts = &team.SourceFacts{}
			case "skills":
				last.inventory.Skills = &sh.CaptureInventory{}
			case "inventory_other":
				last.inventory.Database = "changed"
			case "metadata":
				last.metadata.DatabaseHostname = "changed"
			case "bindings":
				last.bindings = []observedSourceRuntimeBinding{{Instance: 1}}
			case "pods":
				last.pods = []observedSourceRuntimePod{{ID: 1}}
			}
			if got := bootstrapSourceSQLChange(first, last); got != name {
				t.Fatalf("category: %s", got)
			}
			if sameBootstrapSourceSQL(first, last) != (name == "none") {
				t.Fatal("exact source comparison changed")
			}
		})
	}
}
