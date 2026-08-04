package config

import (
	"path/filepath"
	"testing"
)

// The repository ships example configuration files that people copy. The
// parser rejects unknown keys, so an example with a typo or a renamed field is
// a broken copy-paste for every newcomer. This loads each shipped example
// through the real loader and validator, so an example cannot drift from the
// config it is supposed to demonstrate.
func TestShippedExampleConfigsAreValid(t *testing.T) {
	examples := []string{
		filepath.Join("..", "..", "deploy", "examples", "docker-compose", "config.json"),
	}
	for _, path := range examples {
		t.Run(path, func(t *testing.T) {
			c := Default()
			if err := c.LoadFile(path); err != nil {
				t.Fatalf("the example does not load: %v", err)
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("the example does not validate: %v", err)
			}
		})
	}
}
