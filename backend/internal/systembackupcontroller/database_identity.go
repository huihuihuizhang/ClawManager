package systembackupcontroller

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateControllerDatabaseUser rejects the database identities shipped for
// the application or local development. A distinct name is only a prerequisite;
// deployment must still prove the user's exact grants with positive and
// negative permission tests before enabling system backup.
func ValidateControllerDatabaseUser(user string) error {
	normalized := strings.ToLower(strings.TrimSpace(user))
	if normalized == "" {
		return errors.New("system backup controller requires a dedicated database user")
	}
	switch normalized {
	case "root", "clawmanager", "clawreef":
		return fmt.Errorf("system backup controller cannot use shared database user %q", user)
	default:
		return nil
	}
}

// ValidateControllerDatabaseCredentials prevents config-file or development
// defaults from silently supplying credentials when the controller is enabled.
// The password is only checked for presence and is never included in errors.
func ValidateControllerDatabaseCredentials(explicitUser, explicitPassword, configuredUser string) error {
	if strings.TrimSpace(explicitUser) == "" || explicitPassword == "" {
		return errors.New("enabled system backup controller requires explicit DB_USER and DB_PASSWORD")
	}
	if explicitUser != configuredUser {
		return errors.New("controller database user differs from explicit DB_USER")
	}
	return ValidateControllerDatabaseUser(configuredUser)
}
