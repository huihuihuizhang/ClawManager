package systembackupexecution

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// A finite TLS/RESP protocol fixture, not a real Redis server or Lua/DUMP
// acceptance. It exercises the original client's AUTH/SELECT/INFO boundaries.
func startDMetadataRedis(t *testing.T, f *dProductionSourceFixture) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", f.server.TLS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(line, "*") {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
					if err != nil || n < 1 || n > 4 {
						return
					}
					args := make([]string, n)
					for index := range args {
						line, err = reader.ReadString('\n')
						if err != nil || !strings.HasPrefix(line, "$") {
							return
						}
						length, err := strconv.Atoi(strings.TrimSpace(line[1:]))
						if err != nil || length < 0 || length > 4096 {
							return
						}
						buf := make([]byte, length+2)
						if _, err := io.ReadFull(reader, buf); err != nil || string(buf[length:]) != "\r\n" {
							return
						}
						args[index] = string(buf[:length])
					}
					switch {
					case reflect.DeepEqual(args, []string{"AUTH", "d-redis", "named-local-fixture"}), reflect.DeepEqual(args, []string{"SELECT", "0"}):
						fmt.Fprint(conn, "+OK\r\n")
					case reflect.DeepEqual(args, []string{"INFO", "server"}):
						body := "run_id:" + strings.Repeat("a", 40) + "\r\n"
						fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(body), body)
					default:
						fmt.Fprint(conn, "-NOPERM finite metadata fixture\r\n")
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func TestProductionSourceOriginalClientsAndFiniteMetadataAPIWithTLSMySQL(t *testing.T) {
	var mode atomic.Value
	mode.Store("valid")
	var f *dProductionSourceFixture
	var metadataRequests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer named-d-metadata-token" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		namespace := f.base.x.history.service.Config.Namespace
		selected := mode.Load().(string)
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			if r.Method != "POST" {
				w.WriteHeader(403)
				return
			}
			uid := "d-metadata-uid"
			if selected == "wrong-source-actor" {
				uid = "replacement"
			}
			json.NewEncoder(w).Encode(authnv1.SelfSubjectReview{TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authnv1.SelfSubjectReviewStatus{UserInfo: authnv1.UserInfo{Username: "system:serviceaccount:" + namespace + ":d-metadata", UID: uid}}})
		case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
			if r.Method != "POST" {
				w.WriteHeader(403)
				return
			}
			rules := authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{{APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}, Verbs: []string{"get", "list"}}}}
			if selected == "write-permission" {
				rules.ResourceRules[0].Verbs = append(rules.ResourceRules[0].Verbs, "patch")
			}
			json.NewEncoder(w).Encode(authzv1.SelfSubjectRulesReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectRulesReview"}, Status: rules})
		case "/api/v1/namespaces/" + namespace + "/configmaps", "/api/v1/namespaces/" + namespace + "/secrets":
			metadataRequests.Add(1)
			if r.Method != "GET" || !strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadataList") || r.URL.Query().Get("limit") != "1000" {
				w.WriteHeader(403)
				return
			}
			uid := "d-source-object-uid"
			if selected == "replacement" {
				uid = "replacement"
			}
			object := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "original", Namespace: namespace, UID: types.UID(uid)}}
			if selected == "foreign-namespace" {
				object.Namespace = "foreign"
			}
			if selected == "deleting" {
				now := metav1.Now()
				object.DeletionTimestamp = &now
			}
			list := metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, Items: []metav1.PartialObjectMetadata{object}}
			if selected == "duplicate" {
				list.Items = append(list.Items, object)
			}
			if selected == "revoke-during-final-response" {
				if err := os.WriteFile(f.base.x.history.service.captureMaterials.Discovery.SourceAPI.TokenFile, []byte("replacement"), 0600); err != nil {
					t.Error(err)
				}
			}
			json.NewEncoder(w).Encode(list)
		default:
			w.WriteHeader(403)
		}
	})
	f = newDProductionSourceFixture(t, handler)
	s, owner := f.base.x.history.service, f.base.x.history.owner
	s.captureMaterials.Redis.Redis.Address = startDMetadataRedis(t, f)
	s.captureMaterials.ResourceTypes = []productionResourceType{{Part: "deployment_resources", Version: "v1", Resource: "configmaps"}, {Part: "secret_bundle", Version: "v1", Resource: "secrets"}}
	f.repinScope(t)
	ctx := context.Background()
	for _, actor := range s.captureMaterials.Discovery.ResourceActors {
		if _, err := owner.Client.CoreV1().ServiceAccounts(s.Config.Namespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: actor.Name, UID: types.UID(actor.UID)}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	authority, err := s.sourceMetadataAuthority(ctx, owner, f.base.in)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := authority.openClients(ctx)
	if err != nil {
		t.Fatal("original TLS Redis/object/API client construction", err)
	}
	defer clients.Close()
	deployment, secrets, err := authority.resourceMetadata(ctx, clients)
	if err != nil || len(deployment.Selections) != 1 || len(secrets.Selections) != 1 {
		t.Fatal("finite original metadata selection", err)
	}
	for _, fault := range []string{"replacement", "foreign-namespace", "deleting", "duplicate", "write-permission", "wrong-source-actor", "revoke-during-final-response"} {
		t.Run(fault, func(t *testing.T) {
			mode.Store(fault)
			if fault == "wrong-source-actor" {
				opened, err := authority.openClients(ctx)
				if opened != nil {
					opened.Close()
				}
				if err == nil {
					t.Fatal("source SA identity replacement accepted")
				}
				return
			}
			actual, _, err := authority.resourceMetadata(ctx, clients)
			if fault == "replacement" {
				if err != nil || reflect.DeepEqual(actual.Selections, deployment.Selections) {
					t.Fatal("UID replacement lost from frozen selection", err)
				}
			} else if err == nil {
				t.Fatal("invalid current metadata returned selection", fault)
			}
		})
	}
	if metadataRequests.Load() < 2 {
		t.Fatal("actual TLS PartialObjectMetadata client not used")
	}
}
