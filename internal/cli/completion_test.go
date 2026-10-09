package cli

import (
	"strings"
	"testing"
)

func TestCompletion(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"bash"}, 0, "complete -o default"},
		{[]string{"powershell"}, 0, "Register-ArgumentCompleter"},
		{[]string{"--help"}, 0, "Usage:"},
		{[]string{"fish"}, 1, ""},
		{nil, 1, ""},
		{[]string{"bash", "extra"}, 1, ""},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			code, out := runCLI(t, append([]string{"completion"}, tc.args...)...)
			if code != tc.code || !strings.Contains(out, tc.want) {
				t.Fatalf("completion %v: code %d, output %q", tc.args, code, out)
			}
			if code == 0 && tc.want != "Usage:" {
				for _, cmd := range commandNames {
					if !strings.Contains(out, cmd) {
						t.Errorf("completion is missing %s", cmd)
					}
				}
			}
		})
	}
}
