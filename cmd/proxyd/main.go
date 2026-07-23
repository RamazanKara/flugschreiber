// Command proxyd runs only the recording proxy.
//
// It exists for deployments that want a container entrypoint that cannot do
// anything but serve: no verification, no report generation, no reading of the
// evidence directory beyond appending to it. Everything it does is also
// available as "flugschreiber serve".
package main

import (
	"fmt"
	"os"

	"github.com/RamazanKara/flugschreiber/internal/cli"
)

func main() {
	if err := cli.Serve(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "proxyd: %v\n", err)
		os.Exit(1)
	}
}
