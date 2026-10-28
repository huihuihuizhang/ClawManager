package systembackupcontroller

import "testing"

func TestControllerDatabaseIdentityRejectsKnownSharedAccounts(t *testing.T) {
	for _, user := range []string{"", " ", "root", "ROOT", "clawmanager", " ClawManager ", "clawreef"} {
		if err := ValidateControllerDatabaseUser(user); err == nil {
			t.Fatalf("shared database user %q was accepted", user)
		}
	}
	for _, user := range []string{"sbk_controller", "clawmanager_backup_controller"} {
		if err := ValidateControllerDatabaseUser(user); err != nil {
			t.Fatalf("dedicated database user %q was rejected: %v", user, err)
		}
	}
}

func TestControllerDatabaseCredentialsMustBeExplicit(t *testing.T) {
	for _, input := range [][3]string{
		{"", "secret", "sbk_controller"},
		{"sbk_controller", "", "sbk_controller"},
		{"clawmanager", "secret", "clawmanager"},
		{"sbk_controller", "secret", "other_controller"},
	} {
		if err := ValidateControllerDatabaseCredentials(input[0], input[1], input[2]); err == nil {
			t.Fatalf("unsafe credential source accepted: %#v", input)
		}
	}
	if err := ValidateControllerDatabaseCredentials("sbk_controller", "secret", "sbk_controller"); err != nil {
		t.Fatal(err)
	}
}
