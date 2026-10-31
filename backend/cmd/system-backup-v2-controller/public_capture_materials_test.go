package main

import "testing"

func TestConfiguredPublicStartupCarriesIndependentCapturePin(t *testing.T) {
	t.Setenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE", "")
	t.Setenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_SHA256", "")
	if len(configuredPublicStartupInputs().CaptureModules) != 0 {
		t.Fatal("absent capture pin manufactured")
	}
	t.Setenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE", "original-capture.json")
	got := configuredPublicStartupInputs().CaptureModules
	if len(got) != 1 || got[0].File != "original-capture.json" || got[0].SHA256 != "" {
		t.Fatal("incomplete material pin silently discarded")
	}
	t.Setenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_SHA256", "independently-injected-sha")
	got = configuredPublicStartupInputs().CaptureModules
	if len(got) != 1 || got[0].File != "original-capture.json" || got[0].SHA256 != "independently-injected-sha" {
		t.Fatal("actual CLI lost original capture material input")
	}
}
