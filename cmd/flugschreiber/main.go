// Command flugschreiber is the proxy and the evidence toolchain in one binary.
//
// One binary rather than two keeps the operational story simple: the artifact
// that recorded the evidence can also verify it, and an auditor needs to obtain
// exactly one thing.
package main

import (
	"os"

	"github.com/flugschreiber/flugschreiber/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
