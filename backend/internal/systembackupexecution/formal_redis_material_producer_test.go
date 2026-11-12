package systembackupexecution

import (
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

// Delivery identity checks only; these values are not native observations,
// credential validation, account creation or a Redis source hold.
func TestFormalRedisDeliveryPreservesAlreadySelectedKeeper(t *testing.T) {
	selected := install.OriginalRedisReadKeeperSelection{Deployment: "redis", DeploymentUID: "original", ServerName: "redis.example", Port: 6380,
		CA:               install.BootstrapSourceFilePin{File: "/fixture/ca", SHA256: "selected-ca"},
		ReaderCredential: install.BootstrapSourceFilePin{File: "/fixture/reader", SHA256: "selected-reader"},
		KeeperCredential: install.BootstrapSourceFilePin{File: "/fixture/keeper", SHA256: "selected-keeper"},
		CustodyKey:       install.BootstrapSourceFilePin{File: "/fixture/custody", SHA256: "selected-custody"}}
	if !formalRedisKeeperDeliveryMatches(nil, selected) || !formalRedisKeeperDeliveryMatches([]install.OriginalRedisReadKeeperSelection{selected}, selected) {
		t.Fatal("first delivery or exact previously selected keeper rejected")
	}
	if formalRedisKeeperDeliveryMatches([]install.OriginalRedisReadKeeperSelection{selected, selected}, selected) {
		t.Fatal("multiple existing keepers accepted")
	}
	for name, mutate := range map[string]func(*install.OriginalRedisReadKeeperSelection){
		"source-uid":        func(k *install.OriginalRedisReadKeeperSelection) { k.DeploymentUID = "other" },
		"tls-identity":      func(k *install.OriginalRedisReadKeeperSelection) { k.ServerName = "other.example" },
		"ca-bytes":          func(k *install.OriginalRedisReadKeeperSelection) { k.CA.SHA256 = "other" },
		"reader-credential": func(k *install.OriginalRedisReadKeeperSelection) { k.ReaderCredential.SHA256 = "other" },
		"keeper-credential": func(k *install.OriginalRedisReadKeeperSelection) { k.KeeperCredential.SHA256 = "other" },
		"custody-key":       func(k *install.OriginalRedisReadKeeperSelection) { k.CustodyKey.SHA256 = "other" },
		"unsolicited-task":  func(k *install.OriginalRedisReadKeeperSelection) { k.Native.Operation = "other-operation" },
		"client-certificate": func(k *install.OriginalRedisReadKeeperSelection) {
			k.ClientCertificate = &install.BootstrapSourceFilePin{File: "/fixture/client", SHA256: "other"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := selected
			mutate(&changed)
			if formalRedisKeeperDeliveryMatches([]install.OriginalRedisReadKeeperSelection{changed}, selected) {
				t.Fatal("delivery replaced the original selected identity or custody")
			}
		})
	}
}
