package custody

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// maxTSAResponseBytes bounds what an authority may return. A token is a few
// kilobytes, so this is ample headroom and exists only so that a server
// answering with an endless stream cannot exhaust memory.
const maxTSAResponseBytes = 1 << 20

// HTTPTimestamper asks an RFC 3161 authority to anchor a prepared request over
// HTTP. It is pure transport: it posts the bytes it is handed and returns the
// bytes it gets back, so every ASN.1 concern, including checking that the token
// covers the hash that was asked about, stays in the evidence package where the
// verifier can be read on its own.
type HTTPTimestamper struct {
	url    string
	client *http.Client
}

// NewHTTPTimestamper returns a Timestamper for the authority at rawURL.
func NewHTTPTimestamper(rawURL string, timeout time.Duration) (*HTTPTimestamper, error) {
	if rawURL == "" {
		return nil, errors.New("custody: timestamping authority URL is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("custody: timestamping authority %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("custody: timestamping authority %q must be an http or https URL", rawURL)
	}
	if timeout <= 0 {
		timeout = evidence.DefaultTSATimeout
	}
	return &HTTPTimestamper{url: rawURL, client: &http.Client{Timeout: timeout}}, nil
}

// Name returns the authority's URL, which is what the timestamp record names as
// the party that issued the token.
func (t *HTTPTimestamper) Name() string { return t.url }

// Timestamp posts a prepared TimeStampReq and returns the raw TimeStampResp.
//
// It checks only what the transport can check: that the server answered, that
// it answered with a success status, and that the reply is small enough to hold
// in memory. Whether the reply is a well-formed token over the right imprint is
// the caller's business, because the caller is what a verifier reads.
func (t *HTTPTimestamper) Timestamp(ctx context.Context, request []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("custody: timestamp request to %s: %w", t.url, err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("custody: timestamp request to %s: %w", t.url, err)
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("custody: read timestamp reply from %s: %w", t.url, err)
	}
	if len(answer) > maxTSAResponseBytes {
		return nil, fmt.Errorf("custody: timestamp reply from %s is larger than %d bytes", t.url, maxTSAResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("custody: timestamping authority %s answered %s", t.url, resp.Status)
	}
	return answer, nil
}
