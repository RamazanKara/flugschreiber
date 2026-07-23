package proxy

import (
	"bytes"
	"encoding/json"
	"io"
)

// modelPeekCap bounds how much of a request body is read to find the model
// before the router dials. The model sits at the top of an OpenAI-shaped request
// object, so 1 MiB is generous even for a large multimodal turn. This is the
// bounded, deliberate exception to the tee-never-buffer rule (D5), recorded as
// D33: only the prefix is held, only long enough to route, and the body is then
// replayed unchanged so the stream that follows is untouched.
const modelPeekCap = 1 << 20

// peekModel reads up to modelPeekCap bytes from body to find the request's
// model, then returns a ReadCloser that replays those bytes followed by the
// unread remainder, so the body the upstream receives is byte-for-byte the
// original. truncated is true only when the model could not be found within the
// cap, meaning it may lie beyond it; prefix is the bytes that were read, so a
// caller with no upstream to forward to can still hash and parse what it saw.
func peekModel(body io.ReadCloser) (model string, truncated bool, prefix []byte, rebuilt io.ReadCloser) {
	if body == nil {
		return "", false, nil, nil
	}
	prefix, _ = io.ReadAll(io.LimitReader(body, modelPeekCap))
	rebuilt = &peekReadCloser{prefix: prefix, rc: body}
	model, found := scanModel(prefix)
	if !found && len(prefix) == modelPeekCap {
		truncated = true
	}
	return model, truncated, prefix, rebuilt
}

// peekReadCloser replays a peeked prefix, then continues from the underlying
// reader, then closes it. It lets the router read the head of a request body
// without buffering the whole body or breaking the stream that follows.
type peekReadCloser struct {
	prefix []byte
	off    int
	rc     io.ReadCloser
}

func (p *peekReadCloser) Read(b []byte) (int, error) {
	if p.off < len(p.prefix) {
		n := copy(b, p.prefix[p.off:])
		p.off += n
		return n, nil
	}
	return p.rc.Read(b)
}

func (p *peekReadCloser) Close() error {
	return p.rc.Close()
}

// scanModel returns the top-level "model" string from a JSON object using a
// streaming token scan, so it still finds the model when body is a truncated
// prefix of a larger request. It reads only as far as the model, and treats any
// malformed or missing field as simply not found, never as an error, because a
// request the proxy cannot fully parse must still be routed and recorded.
func scanModel(body []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return "", false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", false
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", false
		}
		key, ok := keyTok.(string)
		if !ok {
			return "", false
		}
		if key == "model" {
			valTok, err := dec.Token()
			if err != nil {
				return "", false
			}
			s, ok := valTok.(string)
			return s, ok
		}
		if err := skipValue(dec); err != nil {
			return "", false
		}
	}
	return "", false
}

// skipValue consumes exactly one JSON value from dec, descending through a
// nested object or array in full so that the next token read is the following
// object key.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if d == '{' || d == '[' {
		depth := 1
		for depth > 0 {
			t, err := dec.Token()
			if err != nil {
				return err
			}
			if dd, ok := t.(json.Delim); ok {
				if dd == '{' || dd == '[' {
					depth++
				} else {
					depth--
				}
			}
		}
	}
	return nil
}
