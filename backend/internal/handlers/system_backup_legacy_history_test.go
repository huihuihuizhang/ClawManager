package handlers

import (
	"database/sql"
	"net/http/httptest"
	"testing"

	"clawreef/internal/systembackup"
	"github.com/gin-gonic/gin"
)

// Exercise the same registration used by the server, not the retired Team
// controller. Authorization must run before any history database access.
func TestLegacyTeamHistoryReadOnlyRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		method, path, role string
		actor, want        int
	}{
		{"GET", "/team-data/jobs", "", 0, 401},
		{"GET", "/team-data/jobs/sbk_00000000000000000000000000000000", "", 0, 401},
		{"GET", "/team-data/jobs", "unknown", 7, 403},
		{"GET", "/team-data/jobs/not-an-id", "viewer", 7, 404},
		{"POST", "/team-data/jobs", "operator", 7, 404},
		{"POST", "/team-data/jobs/sbk_00000000000000000000000000000000/retry", "operator", 7, 404},
	} {
		t.Run(tc.method+tc.path+tc.role, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) { c.Set("userID", tc.actor) })
			NewSystemBackupHandler(systembackup.Store{DB: &sql.DB{}, InstallationID: "test"}, systembackup.RoleBindings{tc.actor: tc.role}).Register(r.Group(""))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
