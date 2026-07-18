package payloads

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerateContainerEscapeYAML_ConfiguresDinDAndHostCommand(t *testing.T) {
	t.Parallel()

	command := "id; hostname; printenv | sort"
	rendered := GenerateContainerEscapeYAML(ContainerEscapeOptions{
		Common:       CommonOptions{Image: "docker:latest", Tags: []string{"docker"}},
		EscapeMethod: "docker",
		HostCommand:  command,
		MountPath:    "/",
	})

	for _, want := range []string{
		"name: docker:dind",
		"DOCKER_HOST: tcp://docker:2375",
		"docker info",
		"chroot /hostfs",
		base64.StdEncoding.EncodeToString([]byte(command)),
		"escape_host_output.txt",
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
