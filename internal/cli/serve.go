package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/flugschreiber/flugschreiber/internal/config"
	"github.com/flugschreiber/flugschreiber/internal/evidence"
	"github.com/flugschreiber/flugschreiber/internal/mockupstream"
	"github.com/flugschreiber/flugschreiber/internal/proxy"
	"github.com/flugschreiber/flugschreiber/internal/version"
)

func Serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: flugschreiber serve [flags]

Runs the recording proxy. Point your application's OPENAI_BASE_URL at it and
every model interaction is recorded to a tamper-evident log.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), `
Every flag can also be set as an environment variable, for example
%sUPSTREAM. Flags win over the environment, which wins over the config file.
`, config.EnvPrefix)
	}

	var (
		configPath = fs.String("config", "", "path to a JSON config file")
		listen     = fs.String("listen", "", "address to listen on (default :8080)")
		upstream   = fs.String("upstream", "", "upstream OpenAI-compatible base URL, e.g. http://vllm:8000")
		mock       = fs.Bool("mock-upstream", false, "serve a built-in deterministic mock instead of a real upstream")
		dataDir    = fs.String("data-dir", "", "evidence directory (default /var/lib/flugschreiber)")
		mode       = fs.String("content-mode", "", "content capture mode: store, hash or redact (default hash)")
		redact     = fs.String("redact-patterns", "", "comma-separated redaction patterns, used when content-mode is redact")
		retention  = fs.Int("retention-days", 0, "minimum retention in days (floor 180)")
		tlsCert    = fs.String("tls-cert", "", "TLS certificate file")
		tlsKey     = fs.String("tls-key", "", "TLS key file")
		logLevel   = fs.String("log-level", "", "debug, info, warn or error")
		org        = fs.String("organisation", "", "organisation name, used to pre-fill generated documentation")
		system     = fs.String("system-name", "", "system name, used to pre-fill generated documentation")
		purpose    = fs.String("purpose", "", "intended purpose, used to pre-fill generated documentation")
		contact    = fs.String("contact", "", "accountable contact, used to pre-fill generated documentation")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Default()
	if *configPath != "" {
		if err := cfg.LoadFile(*configPath); err != nil {
			return err
		}
	}
	if err := cfg.ApplyEnv(); err != nil {
		return err
	}

	setString(&cfg.Listen, *listen)
	setString(&cfg.Upstream, *upstream)
	setString(&cfg.DataDir, *dataDir)
	setString(&cfg.ContentMode, *mode)
	setString(&cfg.TLSCertFile, *tlsCert)
	setString(&cfg.TLSKeyFile, *tlsKey)
	setString(&cfg.LogLevel, *logLevel)
	setString(&cfg.Deployment.Organisation, *org)
	setString(&cfg.Deployment.SystemName, *system)
	setString(&cfg.Deployment.Purpose, *purpose)
	setString(&cfg.Deployment.Contact, *contact)
	if *mock {
		cfg.MockUpstream = true
	}
	if *retention != 0 {
		cfg.RetentionDays = *retention
	}
	if *redact != "" {
		cfg.RedactPatterns = strings.Split(*redact, ",")
	}

	log := newLogger(cfg.LogLevel)

	// The mock runs in-process on a loopback port. This is what lets the
	// quickstart and CI exercise the whole path — proxy, capture, chain,
	// verify, report — with no model server and no network.
	var mockServer *http.Server
	if cfg.MockUpstream {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("start mock upstream: %w", err)
		}
		mockServer = &http.Server{Handler: mockupstream.Handler(mockupstream.Options{ChunkDelay: 15 * time.Millisecond})}
		go func() {
			if err := mockServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("mock upstream stopped", slog.String("error", err.Error()))
			}
		}()
		cfg.Upstream = "http://" + ln.Addr().String()
		log.Info("mock upstream started",
			slog.String("addr", cfg.Upstream),
			slog.String("model", mockupstream.ModelName))
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	store, err := evidence.Open(evidence.Options{
		Dir:             cfg.DataDir,
		SegmentMaxBytes: cfg.SegmentMaxBytes,
	})
	if err != nil {
		return err
	}
	defer store.Close()

	srv, err := proxy.New(cfg, store, log)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:    cfg.Listen,
		Handler: srv.Handler(),
		// No write timeout: a streamed completion can legitimately run for
		// minutes, and cutting it off would corrupt the very thing being
		// recorded. Idle and header timeouts still bound abusive connections.
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLSCertFile != "" {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	log.Info("flugschreiber listening",
		slog.String("version", version.String()),
		slog.String("listen", cfg.Listen),
		slog.String("upstream", cfg.Upstream),
		slog.String("data_dir", cfg.DataDir),
		slog.String("content_mode", cfg.ContentMode),
		slog.Int("retention_days", cfg.RetentionDays))

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down, draining evidence queue")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout.Std())
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("graceful shutdown timed out", slog.String("error", err.Error()))
	}
	if mockServer != nil {
		mockServer.Shutdown(shutdownCtx)
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("close evidence store: %w", err)
	}
	log.Info("stopped", slog.Uint64("records_written", store.Appended()))
	return nil
}

func setString(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
