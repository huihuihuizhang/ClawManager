package host

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestDeploymentTemplatesDecodeWithoutApplying(t *testing.T) {
	directory := filepath.Join("..", "..", "..", "..", "examples", "backup-controller")
	for _, name := range []string{"controller.yaml", "quarantine.yaml"} {
		t.Run(name, func(t *testing.T) {
			file, e := os.Open(filepath.Join(directory, name))
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
			count := 0
			for {
				var object unstructured.Unstructured
				e = decoder.Decode(&object)
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				if object.GetName() == "" || object.GetAPIVersion() == "" || object.GetKind() == "" {
					t.Fatal("incomplete manifest")
				}
				count++
			}
			if count < 3 {
				t.Fatal("missing deployment resources")
			}
		})
	}
	file, e := os.Open(filepath.Join(directory, "controller.example.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var cfg Config
	if e = decoder.Decode(&cfg); e != nil {
		t.Fatal(e)
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Config.Validate() != nil {
		t.Fatal("example profile schema invalid")
	}
}
