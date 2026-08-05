package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/audit"
)

// Inspect reconstructs a session or a single request in readable form.
func Inspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber inspect [flags]

Reconstructs what happened, in chain order: the model interactions and any human
decisions recorded around them.

How much can be shown depends on the content mode that was in force when the
records were written. In the default hash mode there is no transcript to show,
and the output says so rather than appearing empty.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir     = fs.String("dir", "", "evidence directory to read (or FLUGSCHREIBER_DATA_DIR)")
		session = fs.String("session", "", "reconstruct one session by id")
		request = fs.String("request", "", "reconstruct one request, and anything referring to it")
		limit   = fs.Int("limit", 0, "stop after this many records (0 means no limit)")
		asJSON  = fs.Bool("json", false, "emit the result as JSON")
	)
	fs.StringVar(request, "request-id", "", "alias of --request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveDir(fs, "inspect", dir); err != nil {
		return err
	}
	if *session != "" && *request != "" {
		return errors.New("inspect: use --session or --request, not both")
	}

	s, err := audit.Reconstruct(*dir, audit.Query{
		SessionID: *session,
		RequestID: *request,
		Limit:     *limit,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(s)
	}

	var b strings.Builder
	s.Render(&b)
	fmt.Print(b.String())
	return nil
}
