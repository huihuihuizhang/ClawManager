package install

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// The HTTP page tests exercise actual bounded reads and the unchanged raw
// consumer definition. They create NO original holder/metadata/NoS3 authority.
func historyControllerRESTFixture(t *testing.T, handler http.HandlerFunc) rest.Interface {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, e := rest.RESTClientFor(&rest.Config{Host: server.URL, APIPath: "/apis", ContentConfig: rest.ContentConfig{GroupVersion: &schema.GroupVersion{Group: "apps", Version: "v1"}, NegotiatedSerializer: scheme.Codecs.WithoutConversion()}, QPS: 1000, Burst: 1000})
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func historyControllerPageFixture(name, rv, next string) string {
	items := "[]"
	if name != "" {
		items = fmt.Sprintf(`[{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":%q,"namespace":"original","uid":%q,"resourceVersion":"member-v1"},"spec":{"replicas":0,"futureUnknownField":9007199254740993}}]`, name, "uid-"+name)
	}
	return fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"ReplicaSetList","metadata":{"resourceVersion":%q,"continue":%q},"items":%s}`, rv, next, items)
}

func TestOriginalHistoryControllerInventoryActualPagesPreserveUnknownBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	client := historyControllerRESTFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Query().Get("limit") != "128" {
			t.Error("wrong actual LIST request")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("continue") {
		case "":
			fmt.Fprint(w, historyControllerPageFixture("retired-a", "9", "next"))
		case "next":
			fmt.Fprint(w, historyControllerPageFixture("retired-b", "9", ""))
		default:
			t.Error("wrong continue token")
			w.WriteHeader(500)
		}
	})
	items, rv, e := readOriginalHistoryControllerPages(ctx, originalHistoryControllerResource{"ReplicaSet", "replicasets", "apps/v1", client}, "original")
	if e != nil || rv != "9" || len(items) != 2 || calls != 2 {
		t.Fatal("actual EOF page chain failed", e, len(items), calls)
	}
	defer func() {
		for n := range items {
			clear(items[n].body)
		}
	}()
	for _, item := range items {
		if !strings.Contains(string(item.body), `"futureUnknownField":9007199254740993`) {
			t.Fatal("unknown field or exact number dropped")
		}
	}
}

func TestOriginalHistoryControllerInventoryRejectsPartialAndChangedPages(t *testing.T) {
	for _, mode := range []string{"changed-rv", "replayed-member", "loop-token", "truncated", "null-items", "unknown-list-field", "positive-remaining-at-eof", "duplicate-json-key", "wrong-namespace", "null-continue"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client := historyControllerRESTFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				first := r.URL.Query().Get("continue") == ""
				body := historyControllerPageFixture("member-a", "9", "next")
				if !first {
					body = historyControllerPageFixture("member-b", "9", "")
				}
				switch mode {
				case "changed-rv":
					if !first {
						body = historyControllerPageFixture("member-b", "10", "")
					}
				case "replayed-member":
					if !first {
						body = historyControllerPageFixture("member-a", "9", "")
					}
				case "loop-token":
					if !first {
						body = historyControllerPageFixture("member-b", "9", "next")
					}
				case "truncated":
					body = body[:len(body)-1]
				case "null-items":
					body = strings.Replace(body, `"items":[`, `"items":null,"extra":[`, 1)
				case "unknown-list-field":
					body = strings.Replace(body, `"items":`, `"extra":1,"items":`, 1)
				case "positive-remaining-at-eof":
					body = historyControllerPageFixture("", "9", "")
					body = strings.Replace(body, `"continue":""`, `"continue":"","remainingItemCount":1`, 1)
				case "duplicate-json-key":
					body = strings.Replace(body, `"kind":"ReplicaSetList"`, `"kind":"ReplicaSetList","kind":"ReplicaSetList"`, 1)
				case "wrong-namespace":
					body = strings.Replace(body, `"namespace":"original"`, `"namespace":"other"`, 1)
				case "null-continue":
					body = strings.Replace(body, `"continue":"next"`, `"continue":null`, 1)
				}
				fmt.Fprint(w, body)
			})
			if items, _, e := readOriginalHistoryControllerPages(ctx, originalHistoryControllerResource{"ReplicaSet", "replicasets", "apps/v1", client}, "original"); e == nil || items != nil {
				t.Fatal("partial/changed input became completed inventory", e)
			}
		})
	}
}

func TestOriginalHistoryControllerInventoryStrictJSONAndOriginalOwners(t *testing.T) {
	for _, body := range []string{`{"x":1,"x":2}`, `{"x":"\ud800"}`, `{"x":"\udc00"}`, `{} {}`, strings.Repeat("[", 66) + strings.Repeat("]", 66)} {
		if originalHistoryControllerJSON([]byte(body)) {
			t.Fatal("unknown JSON accepted")
		}
	}
	if !originalHistoryControllerJSON([]byte(`{"x":"\ud83d\ude00","exact":9007199254740993,"escaped":"\\ud800"}`)) {
		t.Fatal("valid raw JSON lost")
	}
	if r, e := readOriginalHistoryControllerInventoryLocked(context.Background(), nil, nil, nil); e == nil || r != nil {
		t.Fatal("zero owners created inventory")
	}
	var nilClient *rest.RESTClient
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if items, _, e := readOriginalHistoryControllerPages(ctx, originalHistoryControllerResource{"ReplicaSet", "replicasets", "apps/v1", nilClient}, "original"); e == nil || items != nil {
		t.Fatal("typed nil native client accepted")
	}
}
