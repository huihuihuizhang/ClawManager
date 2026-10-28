package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestBrokerOwnerTeamCreateReplayDoesNotRotateOrAdoptForeignSecret(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview).DeepCopy()
		review.Status = authenticationv1.TokenReviewStatus{Authenticated: true, User: authenticationv1.UserInfo{Username: "system:serviceaccount:cm-fixture-system:app"}, Audiences: []string{defaultSecretBrokerAudience}}
		return true, review, nil
	})
	handler, err := NewSecretBrokerHandler(client, SecretBrokerConfig{NamespacePrefix: "cm-fixture", SystemNamespace: "cm-fixture-system", AppNamespace: "cm-fixture-system", AppServiceAccount: "app"})
	if err != nil {
		t.Fatal(err)
	}
	post := func(token string, authenticated bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(SecretRecord{Namespace: "cm-fixture-user-7", Name: "clawreef-team-17-bus", Type: "Opaque", Labels: map[string]string{"managed-by": "clawreef", "team-id": "17"}, Data: map[string][]byte{"CLAWMANAGER_TEAM_TOKEN": []byte(token)}})
		r := httptest.NewRequest(http.MethodPost, "/v1/secrets/create", bytes.NewReader(body))
		if authenticated {
			r.Header.Set("Authorization", "Bearer synthetic-projected-token")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, token := range []string{"first-synthetic-token", "replacement-synthetic-token"} {
		w := post(token, true)
		if w.Code != http.StatusOK {
			t.Fatalf("create returned %d", w.Code)
		}
		var record SecretRecord
		if err = json.Unmarshal(w.Body.Bytes(), &record); err != nil || string(record.Data["CLAWMANAGER_TEAM_TOKEN"]) != "first-synthetic-token" {
			t.Fatal("create replay rotated token", err)
		}
	}
	if w := post("unauthorized", false); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous create admitted")
	}
	secret, err := client.CoreV1().Secrets("cm-fixture-user-7").Get(context.Background(), "clawreef-team-17-bus", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret.Labels["team-id"] = "99"
	if _, err = client.CoreV1().Secrets(secret.Namespace).Update(context.Background(), secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	denied := post("must-not-replace", true)
	if denied.Code != http.StatusForbidden || bytes.Contains(denied.Body.Bytes(), []byte("first-synthetic-token")) {
		t.Fatal("foreign Secret was adopted or leaked")
	}
}
