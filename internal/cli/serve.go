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

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/custody"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
	"github.com/RamazanKara/flugschreiber/internal/metrics"
	"github.com/RamazanKara/flugschreiber/internal/mockupstream"
	"github.com/RamazanKara/flugschreiber/internal/proxy"
	"github.com/RamazanKara/flugschreiber/internal/version"
)

// Serve runs the recording proxy until it is signalled to stop.
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

		eventsToken = fs.String("events-token", "",
			"bearer token for the oversight events endpoint; while this is empty the endpoint stays disabled")
		noSign = fs.Bool("no-sign", false,
			"do not sign checkpoints; the chain then proves internal consistency only")
		checkpointEvery = fs.Duration("checkpoint-interval", 0,
			"how often to sign the chain head while writing (default 5m)")
		upstreamCA = fs.String("upstream-ca", "",
			"PEM bundle of additional roots trusted for the upstream connection")
		upstreamSkipVerify = fs.Bool("upstream-tls-skip-verify", false,
			"do not verify the upstream certificate; the evidence then attests to bytes from whoever answered")

		signer = fs.String("signer", "",
			"sign checkpoints through an external helper, as exec:<command>; the private key then never has to live beside the evidence")
		signerPublicKey = fs.String("signer-public-key", "",
			"PEM of the public key the external helper holds, so that a helper signing with the wrong key is caught at once")
		tsaURL = fs.String("tsa-url", "",
			"RFC 3161 timestamping authority; anchoring upgrades a checkpoint's time from this host's claim to a third party's")
		tsaInterval = fs.Duration("tsa-interval", 0,
			"how often to anchor a checkpoint (default 1h); an authority is somebody else's rate-limited service")
		maxBytes = fs.Int64("retention-max-bytes", 0,
			"size cap for the evidence directory, reported as a gauge; it never overrides the retention floor")
		forceWriterLock = fs.Bool("force-writer-lock", false,
			"take the evidence directory even when another writer appears to hold it; only for a holder on another host that is known to be stopped")
		contentEncryption = fs.Bool("content-encryption", false,
			"encrypt stored content at rest, so an erasure request can destroy a key rather than the chain")
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
	setString(&cfg.EventsToken, *eventsToken)
	setString(&cfg.UpstreamCAFile, *upstreamCA)
	setString(&cfg.Signer, *signer)
	setString(&cfg.SignerPublicKey, *signerPublicKey)
	setString(&cfg.TSAURL, *tsaURL)
	if *tsaInterval != 0 {
		cfg.TSAInterval = config.Duration(*tsaInterval)
	}
	if *maxBytes != 0 {
		cfg.RetentionMaxBytes = *maxBytes
	}
	if *contentEncryption {
		cfg.ContentEncryption = true
	}
	if *upstreamSkipVerify {
		cfg.UpstreamTLSSkipVerify = true
	}
	if *noSign {
		cfg.SigningDisabled = true
	}
	if *checkpointEvery != 0 {
		cfg.CheckpointInterval = config.Duration(*checkpointEvery)
	}
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
	// quickstart and CI exercise the whole path (proxy, capture, chain, verify,
	// report) with no model server and no network.
	var mockServer *http.Server
	if cfg.MockUpstream {
		ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
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
	if cfg.UpstreamTLSSkipVerify {
		log.Warn("upstream TLS verification is DISABLED; the evidence will attest to bytes from whoever answers the upstream address")
	}

	// The signing key is generated on first start alongside the client salt,
	// both at mode 0600. Checkpoints are what raise the chain from "nobody
	// edited this without rewriting all of it" to "nobody rewrote this without
	// also holding the signing key", so they are on unless switched off.
	//
	// An external signer replaces the local key entirely: nothing private is
	// written to the evidence directory, which is the point of configuring one.
	var keys *evidence.KeyPair
	var extSigner evidence.Signer
	switch {
	case cfg.SigningDisabled:
	case cfg.Signer != "":
		command := strings.TrimSpace(strings.TrimPrefix(cfg.Signer, config.SignerExecPrefix))
		s, err := custody.NewExecSigner(command, cfg.SignerPublicKey)
		if err != nil {
			return err
		}
		extSigner = s
		log.Info("signing checkpoints through an external helper",
			slog.String("key_id", s.KeyID()),
			slog.String("public_key", cfg.SignerPublicKey))
	default:
		kp, err := evidence.LoadOrCreateKeyPair(cfg.DataDir)
		if err != nil {
			return err
		}
		keys = kp
	}

	var timestamper evidence.Timestamper
	if cfg.TSAURL != "" {
		tsa, err := custody.NewHTTPTimestamper(cfg.TSAURL, 0)
		if err != nil {
			return err
		}
		timestamper = tsa
		// The effective interval is logged, not the configured one: zero means
		// "the built-in default", and a log line saying 0 would read as
		// "anchor every checkpoint", which is the opposite of what happens.
		interval := cfg.TSAInterval.Std()
		if interval <= 0 {
			interval = evidence.DefaultTSAInterval
		}
		log.Info("anchoring checkpoints to a timestamping authority",
			slog.String("tsa", cfg.TSAURL),
			slog.Duration("interval", interval))
	}

	archiver, err := buildArchiver(cfg, log)
	if err != nil {
		return err
	}

	store, err := evidence.Open(evidence.Options{
		Dir:                cfg.DataDir,
		ForceWriterLock:    *forceWriterLock,
		SegmentMaxBytes:    cfg.SegmentMaxBytes,
		Keys:               keys,
		Signer:             extSigner,
		CheckpointInterval: cfg.CheckpointInterval.Std(),
		Timestamper:        timestamper,
		TSAInterval:        cfg.TSAInterval.Std(),
		Archiver:           archiver,
		ArchivePrefix:      cfg.Archive.Prefix,
	})
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Verifying at startup answers the question an operator would otherwise
	// only ask after an incident, and it costs a single pass over files that
	// are about to be appended to anyway. It never blocks startup: a proxy that
	// refuses to record because yesterday's log is damaged would turn one
	// problem into two.
	var recordsAtStart uint64
	if verified, verr := evidence.Verify(cfg.DataDir); verr == nil && verified.Records > 0 {
		recordsAtStart = verified.Records
		attrs := []any{
			slog.Uint64("records", verified.Records),
			slog.String("head_hash", verified.HeadHash),
			slog.Bool("pruned", verified.Pruned),
			slog.Int("checkpoints", verified.Checkpoints),
		}
		if verified.OK() {
			log.Info("existing evidence verified", attrs...)
		} else {
			log.Error("existing evidence FAILED verification, recording continues",
				append(attrs, slog.Int("problems", len(verified.Problems)))...)
			for _, p := range verified.Problems {
				log.Error("evidence problem",
					slog.String("segment", p.Segment),
					slog.Int("line", p.Line),
					slog.String("kind", p.Kind),
					slog.String("severity", p.Severity),
					slog.String("detail", p.Detail))
			}
		}
	}

	srv, err := proxy.New(cfg, store, log)
	if err != nil {
		return err
	}

	srv.SetMetricsCollector(evidenceCollector(srv.Metrics(), store, cfg.DataDir, recordsAtStart, cfg.RetentionMaxBytes))

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

	// An authority that stops answering costs anchors and never records, so it
	// is reported at shutdown rather than turned into a failure at the time.
	defer func() {
		if err := store.TimestampErr(); err != nil {
			log.Warn("checkpoint anchoring had failures; the checkpoints are signed and on disk either way",
				slog.String("error", err.Error()))
		}
	}()

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
	// Whatever was still being relayed when the grace period ran out is
	// recorded now, as a partial capture that says it is partial. Dropping it
	// would mean the interaction happened, the client saw most of an answer,
	// and the evidence says the traffic never existed.
	if n := srv.AbandonInFlight(); n > 0 {
		log.Warn("interactions were still in flight at shutdown and are recorded as truncated",
			slog.Int("count", n))
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

// evidenceCollector reports the state of the evidence directory as it is on
// disk. The proxy knows what it wrote this run; only the filesystem knows what
// every run before it left behind.
func evidenceCollector(m *metrics.Metrics, store *evidence.Store, dir string, baseRecords uint64, maxBytes int64) func() {
	var lastCheckpoints, lastUploaded, lastSkipped, lastFailed uint64
	var lastAnchored, lastAnchorFailed uint64
	return func() {
		segs, err := evidence.Segments(dir)
		if err == nil {
			var bytes int64
			for _, s := range segs {
				if info, statErr := os.Stat(s.Path); statErr == nil {
					bytes += info.Size()
				}
			}
			m.SetEvidenceBytes(bytes)
			if maxBytes > 0 {
				m.SetEvidenceBytesOverCap(bytes - maxBytes)
			}
		}
		m.SetEvidenceRecords(baseRecords + store.Appended())

		// Checkpoints and archive uploads are counters, and the store reports
		// running totals, so only the increment since the last scrape is added.
		if written := store.Checkpoints(); written > lastCheckpoints {
			for i := lastCheckpoints; i < written; i++ {
				m.CheckpointWritten()
			}
			lastCheckpoints = written
		}

		anchors := store.TimestampStats()
		advance(&lastAnchored, anchors.Anchored, func() { m.TimestampAnchored(true) })
		advance(&lastAnchorFailed, anchors.Failed, func() { m.TimestampAnchored(false) })

		stats := store.ArchiveStats()
		if stats.Backend == "" {
			return
		}
		advance(&lastUploaded, stats.Uploaded, func() {
			m.ArchiveUpload(stats.Backend, metrics.ArchiveSuccess)
		})
		advance(&lastSkipped, stats.Skipped, func() {
			m.ArchiveUpload(stats.Backend, metrics.ArchiveSkipped)
		})
		advance(&lastFailed, stats.Failed, func() {
			m.ArchiveUpload(stats.Backend, metrics.ArchiveFailure)
		})
	}
}

// advance carries a running total forward onto a counter, calling inc once for
// each unit of progress since the last scrape.
func advance(seen *uint64, total uint64, inc func()) {
	for ; *seen < total; *seen++ {
		inc()
	}
}
