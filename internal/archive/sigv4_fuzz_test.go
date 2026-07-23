package archive

import (
	"net/http"
	"testing"
	"time"
)

// FuzzSigV4 drives the canonical-request and signing path with an arbitrary
// method, path, query, one header and a payload hash. This code is hand-rolled
// and security-critical, so the properties worth a fuzzer are the ones a fuzzer
// is good at breaking: it must never panic on any input, and it must be
// deterministic, because a signature that varied for identical bytes would turn
// a correct upload into a sporadic 403 that names no cause.
//
// The seeds are the published AWS vectors the vector tests already pin, so the
// corpus starts from request shapes a store is known to accept rather than from
// noise.
func FuzzSigV4(f *testing.F) {
	seeds := []struct {
		method, path, query, headerName, headerValue, payloadHash string
	}{
		{http.MethodGet, "/", "", "X-Amz-Date", "20150830T123600Z", EmptyPayloadSHA256},
		{http.MethodGet, "/test.txt", "", "Range", "bytes=0-9", EmptyPayloadSHA256},
		{http.MethodPut, "/test$file.text", "", "X-Amz-Storage-Class", "REDUCED_REDUNDANCY", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"},
		{http.MethodGet, "/", "lifecycle", "X-Amz-Content-Sha256", EmptyPayloadSHA256, EmptyPayloadSHA256},
		{http.MethodGet, "/", "max-keys=2&prefix=J", "X-Amz-Date", "20130524T000000Z", EmptyPayloadSHA256},
		{http.MethodPut, "/prod 2026/seg+1$a.jsonl", "delimiter=%2F&k=a+b", "X-Amz-Meta-Note", "  spaced   out  ", UnsignedPayload},
	}
	for _, s := range seeds {
		f.Add(s.method, s.path, s.query, s.headerName, s.headerValue, s.payloadHash)
	}

	// Credentials and time are fixed so that the only thing varying between the
	// two signings below is nothing at all: any difference in the output is a
	// determinism bug, not an input difference.
	creds := Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	signTime := time.Unix(1_600_000_000, 0).UTC()

	f.Fuzz(func(t *testing.T, method, path, query, headerName, headerValue, payloadHash string) {
		// One signing attempt, isolated so it can be run twice from identical
		// inputs against fresh requests. A build the standard library rejects
		// (an invalid method token) or a hash SignRequest refuses (an empty one)
		// is a legitimate non-result, not a panic; it only has to be reported the
		// same way both times.
		sign := func() (auth, canonical string, ok bool) {
			req, err := http.NewRequest(method, "https://bucket.example.com", nil)
			if err != nil {
				return "", "", false
			}
			req.URL.Path = path
			req.URL.RawQuery = query
			req.Header.Set(headerName, headerValue)
			if err := SignRequest(req, creds, "us-east-1", "s3", payloadHash, signTime); err != nil {
				return "", "", false
			}
			// canonicalRequest is rebuilt from the signed request the way a store
			// rebuilds it, so the fuzz exercises it directly as well as through
			// the Authorization header.
			c := canonicalRequest(req, payloadHash, "s3", signedHeaderNames(req))
			return req.Header.Get("Authorization"), c, true
		}

		auth1, canon1, ok1 := sign()
		auth2, canon2, ok2 := sign()
		if ok1 != ok2 {
			t.Fatalf("signing succeeded %v then %v for identical input", ok1, ok2)
		}
		if ok1 && (auth1 != auth2 || canon1 != canon2) {
			t.Fatalf("signing is not deterministic for identical input:\n auth: %q vs %q\ncanon: %q vs %q",
				auth1, auth2, canon1, canon2)
		}
	})
}
