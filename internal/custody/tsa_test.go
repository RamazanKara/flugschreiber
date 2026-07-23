package custody

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The transport's job is to carry the bytes and to refuse an answer it cannot
// carry. It never inspects a token, so these tests do not build one.
func TestHTTPTimestamperCarriesTheQueryAndTheReply(t *testing.T) {
	var gotBody []byte
	var gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		buf := make([]byte, 64)
		n, _ := r.Body.Read(buf)
		gotBody = buf[:n]
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write([]byte("the reply, verbatim"))
	}))
	defer srv.Close()

	tsa, err := NewHTTPTimestamper(srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tsa.Name() != srv.URL {
		t.Errorf("Name = %q, want the authority's URL %q", tsa.Name(), srv.URL)
	}

	reply, err := tsa.Timestamp(context.Background(), []byte("the query"))
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if string(reply) != "the reply, verbatim" {
		t.Errorf("reply = %q, the transport altered what the authority sent", reply)
	}
	if string(gotBody) != "the query" {
		t.Errorf("the authority received %q, want the query it was handed", gotBody)
	}
	if gotType != "application/timestamp-query" {
		t.Errorf("Content-Type = %q, want application/timestamp-query", gotType)
	}
}

func TestHTTPTimestamperRefusesAnAnswerItCannotUse(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		wants   string
	}{
		{
			name: "an error status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wants: "503",
		},
		{
			name: "a reply larger than any token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				chunk := make([]byte, 1<<16)
				for range (maxTSAResponseBytes / len(chunk)) + 2 {
					if _, err := w.Write(chunk); err != nil {
						return
					}
				}
			},
			wants: "larger than",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			tsa, err := NewHTTPTimestamper(srv.URL, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tsa.Timestamp(context.Background(), []byte("the query"))
			if err == nil {
				t.Fatal("the transport accepted an answer it cannot use")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error does not say what went wrong: %v", err)
			}
		})
	}
}

func TestNewHTTPTimestamperRefusesAnUnusableURL(t *testing.T) {
	for _, raw := range []string{"", "tsa.example.com", "ftp://tsa.example.com", "://nonsense"} {
		if _, err := NewHTTPTimestamper(raw, time.Second); err == nil {
			t.Errorf("%q was accepted as a timestamping authority", raw)
		}
	}
}
