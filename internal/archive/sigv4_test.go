package archive

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The vectors below are published by AWS. Two sources are used, both with
// fixed credentials that exist only in documentation:
//
//   - the "aws4_testsuite" conformance suite, which covers the generic rules
//     (get-vanilla), and
//   - the worked examples in the Amazon S3 API reference, "Examples: Signature
//     Calculations for the Authorization Header", which cover the S3-specific
//     path encoding and the single-chunk payload hash.
//
// Every stage is asserted separately, so a failure says which rule is wrong
// rather than only that the signature does not match.

const (
	// docAccessKey and docSecret appear verbatim in the S3 documentation.
	docAccessKey = "AKIAIOSFODNN7EXAMPLE"
	docSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// suiteAccessKey and suiteSecret are the aws4_testsuite credentials. The
	// secret differs from the S3 one by a single character ('+' where the S3
	// example has '/'), which is exactly the kind of thing a hand-typed vector
	// gets wrong, so they are kept apart.
	suiteAccessKey = "AKIDEXAMPLE"
	suiteSecret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(amzDateFormat, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

func newVectorRequest(t *testing.T, method, rawURL string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestCanonicalRequestMatchesPublishedVectors checks the first and hardest
// stage against strings AWS prints in full.
func TestCanonicalRequestMatchesPublishedVectors(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		url         string
		service     string
		headers     map[string]string
		payloadHash string
		want        string
	}{
		{
			name:    "aws4_testsuite get-vanilla",
			method:  http.MethodGet,
			url:     "https://example.amazonaws.com/",
			service: "service",
			headers: map[string]string{
				"X-Amz-Date": "20150830T123600Z",
			},
			payloadHash: EmptyPayloadSHA256,
			want: "GET\n" +
				"/\n" +
				"\n" +
				"host:example.amazonaws.com\n" +
				"x-amz-date:20150830T123600Z\n" +
				"\n" +
				"host;x-amz-date\n" +
				EmptyPayloadSHA256,
		},
		{
			name:    "s3 documentation GET Object",
			method:  http.MethodGet,
			url:     "https://examplebucket.s3.amazonaws.com/test.txt",
			service: "s3",
			headers: map[string]string{
				"Range":                "bytes=0-9",
				"X-Amz-Content-Sha256": EmptyPayloadSHA256,
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash: EmptyPayloadSHA256,
			want: "GET\n" +
				"/test.txt\n" +
				"\n" +
				"host:examplebucket.s3.amazonaws.com\n" +
				"range:bytes=0-9\n" +
				"x-amz-content-sha256:" + EmptyPayloadSHA256 + "\n" +
				"x-amz-date:20130524T000000Z\n" +
				"\n" +
				"host;range;x-amz-content-sha256;x-amz-date\n" +
				EmptyPayloadSHA256,
		},
		{
			name:    "s3 documentation PUT Object encodes the dollar sign",
			method:  http.MethodPut,
			url:     "https://examplebucket.s3.amazonaws.com/test$file.text",
			service: "s3",
			headers: map[string]string{
				"Date":                 "Fri, 24 May 2013 00:00:00 GMT",
				"X-Amz-Storage-Class":  "REDUCED_REDUNDANCY",
				"X-Amz-Content-Sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			want: "PUT\n" +
				"/test%24file.text\n" +
				"\n" +
				"date:Fri, 24 May 2013 00:00:00 GMT\n" +
				"host:examplebucket.s3.amazonaws.com\n" +
				"x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\n" +
				"x-amz-date:20130524T000000Z\n" +
				"x-amz-storage-class:REDUCED_REDUNDANCY\n" +
				"\n" +
				"date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n" +
				"44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
		},
		{
			name:    "s3 documentation GET Bucket lifecycle keeps the empty query value",
			method:  http.MethodGet,
			url:     "https://examplebucket.s3.amazonaws.com/?lifecycle",
			service: "s3",
			headers: map[string]string{
				"X-Amz-Content-Sha256": EmptyPayloadSHA256,
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash: EmptyPayloadSHA256,
			want: "GET\n" +
				"/\n" +
				"lifecycle=\n" +
				"host:examplebucket.s3.amazonaws.com\n" +
				"x-amz-content-sha256:" + EmptyPayloadSHA256 + "\n" +
				"x-amz-date:20130524T000000Z\n" +
				"\n" +
				"host;x-amz-content-sha256;x-amz-date\n" +
				EmptyPayloadSHA256,
		},
		{
			name:    "s3 documentation GET Bucket sorts the query",
			method:  http.MethodGet,
			url:     "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
			service: "s3",
			headers: map[string]string{
				"X-Amz-Content-Sha256": EmptyPayloadSHA256,
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash: EmptyPayloadSHA256,
			want: "GET\n" +
				"/\n" +
				"max-keys=2&prefix=J\n" +
				"host:examplebucket.s3.amazonaws.com\n" +
				"x-amz-content-sha256:" + EmptyPayloadSHA256 + "\n" +
				"x-amz-date:20130524T000000Z\n" +
				"\n" +
				"host;x-amz-content-sha256;x-amz-date\n" +
				EmptyPayloadSHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newVectorRequest(t, tt.method, tt.url, tt.headers)
			pinEscapedPath(req.URL)
			got := canonicalRequest(req, tt.payloadHash, tt.service, signedHeaderNames(req))
			if got != tt.want {
				t.Errorf("canonical request mismatch\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestSignatureMatchesPublishedVectors checks the remaining stages, the
// credential scope, the string to sign and the derived signing key chain,
// against the signatures AWS publishes for the same requests.
func TestSignatureMatchesPublishedVectors(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		url               string
		region            string
		service           string
		accessKey, secret string
		headers           map[string]string
		payloadHash       string
		wantCanonicalHash string
		wantSignature     string
	}{
		{
			name:        "aws4_testsuite get-vanilla",
			method:      http.MethodGet,
			url:         "https://example.amazonaws.com/",
			region:      "us-east-1",
			service:     "service",
			accessKey:   suiteAccessKey,
			secret:      suiteSecret,
			headers:     map[string]string{"X-Amz-Date": "20150830T123600Z"},
			payloadHash: EmptyPayloadSHA256,
			// The suite publishes this vector as a canonical request file and
			// an Authorization header. The canonical request is asserted in
			// full by the test above and the signature below, which between
			// them pin every stage, so the intermediate hash is left
			// unasserted rather than filled in from our own output.
			wantSignature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			name:      "s3 documentation GET Object",
			method:    http.MethodGet,
			url:       "https://examplebucket.s3.amazonaws.com/test.txt",
			region:    "us-east-1",
			service:   "s3",
			accessKey: docAccessKey,
			secret:    docSecret,
			headers: map[string]string{
				"Range":                "bytes=0-9",
				"X-Amz-Content-Sha256": EmptyPayloadSHA256,
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash:       EmptyPayloadSHA256,
			wantCanonicalHash: "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
			wantSignature:     "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name:      "s3 documentation PUT Object",
			method:    http.MethodPut,
			url:       "https://examplebucket.s3.amazonaws.com/test$file.text",
			region:    "us-east-1",
			service:   "s3",
			accessKey: docAccessKey,
			secret:    docSecret,
			headers: map[string]string{
				"Date":                 "Fri, 24 May 2013 00:00:00 GMT",
				"X-Amz-Storage-Class":  "REDUCED_REDUNDANCY",
				"X-Amz-Content-Sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash:       "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			wantCanonicalHash: "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d",
			wantSignature:     "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name:      "s3 documentation GET Bucket lifecycle",
			method:    http.MethodGet,
			url:       "https://examplebucket.s3.amazonaws.com/?lifecycle",
			region:    "us-east-1",
			service:   "s3",
			accessKey: docAccessKey,
			secret:    docSecret,
			headers: map[string]string{
				"X-Amz-Content-Sha256": EmptyPayloadSHA256,
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash:       EmptyPayloadSHA256,
			wantCanonicalHash: "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca",
			wantSignature:     "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name:      "s3 documentation GET Bucket with prefix and max-keys",
			method:    http.MethodGet,
			url:       "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
			region:    "us-east-1",
			service:   "s3",
			accessKey: docAccessKey,
			secret:    docSecret,
			headers: map[string]string{
				"X-Amz-Content-Sha256": EmptyPayloadSHA256,
				"X-Amz-Date":           "20130524T000000Z",
			},
			payloadHash:       EmptyPayloadSHA256,
			wantCanonicalHash: "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7",
			wantSignature:     "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newVectorRequest(t, tt.method, tt.url, tt.headers)
			pinEscapedPath(req.URL)
			ts := mustTime(t, tt.headers["X-Amz-Date"])

			canonical := canonicalRequest(req, tt.payloadHash, tt.service, signedHeaderNames(req))
			scope := credentialScope(ts, tt.region, tt.service)
			sts := stringToSign(ts, scope, canonical)

			lines := strings.Split(sts, "\n")
			if len(lines) != 4 {
				t.Fatalf("string to sign has %d lines, want 4: %q", len(lines), sts)
			}
			if lines[0] != Algorithm {
				t.Errorf("algorithm line = %q, want %q", lines[0], Algorithm)
			}
			if lines[1] != tt.headers["X-Amz-Date"] {
				t.Errorf("date line = %q, want %q", lines[1], tt.headers["X-Amz-Date"])
			}
			wantScope := ts.Format(shortDateFormat) + "/" + tt.region + "/" + tt.service + "/aws4_request"
			if lines[2] != wantScope {
				t.Errorf("scope line = %q, want %q", lines[2], wantScope)
			}
			if tt.wantCanonicalHash != "" && lines[3] != tt.wantCanonicalHash {
				t.Errorf("hashed canonical request = %q, want %q\ncanonical request was:\n%s",
					lines[3], tt.wantCanonicalHash, canonical)
			}

			key := signingKey(tt.secret, ts, tt.region, tt.service)
			got := hex.EncodeToString(hmacSHA256(key, sts))
			if got != tt.wantSignature {
				t.Errorf("signature = %q, want %q", got, tt.wantSignature)
			}

			// The scope advertised in the credential must be the scope the key
			// was derived for. Signing with one and declaring the other is a
			// 403 with no diagnostic beyond "signature does not match".
			creds := Credentials{AccessKeyID: tt.accessKey, SecretAccessKey: tt.secret}
			signable := newVectorRequest(t, tt.method, tt.url, tt.headers)
			if err := SignRequest(signable, creds, tt.region, tt.service, tt.payloadHash, ts); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			wantCredential := "Credential=" + tt.accessKey + "/" + wantScope
			if auth := signable.Header.Get("Authorization"); !strings.Contains(auth, wantCredential) {
				t.Errorf("Authorization %q does not carry %q", auth, wantCredential)
			}
		})
	}
}

// TestSignRequestProducesTheDocumentedAuthorizationHeader exercises the
// exported entry point end to end, including the headers it sets itself.
func TestSignRequestProducesTheDocumentedAuthorizationHeader(t *testing.T) {
	req := newVectorRequest(t, http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", map[string]string{
		"Range": "bytes=0-9",
	})
	creds := Credentials{AccessKeyID: docAccessKey, SecretAccessKey: docSecret}
	if err := SignRequest(req, creds, "us-east-1", "s3", EmptyPayloadSHA256, mustTime(t, "20130524T000000Z")); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization = %q\n            want %q", got, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20130524T000000Z" {
		t.Errorf("X-Amz-Date = %q, want 20130524T000000Z", got)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != EmptyPayloadSHA256 {
		t.Errorf("X-Amz-Content-Sha256 = %q, want the empty payload hash", got)
	}
}

// A request whose wire bytes differ from the bytes that were signed is
// rejected by the store with an error that names neither cause, so the escaped
// path the signature covers has to be the escaped path Go sends.
func TestSignedPathIsThePathSentOnTheWire(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "dollar is escaped where Go would not escape it", key: "/test$file.text", want: "/test%24file.text"},
		{name: "space becomes percent twenty", key: "/two words.jsonl", want: "/two%20words.jsonl"},
		{name: "unreserved characters are left alone", key: "/seg-00000001_a.b~c", want: "/seg-00000001_a.b~c"},
		{name: "plus is escaped", key: "/a+b", want: "/a%2Bb"},
		{name: "colon and at sign are escaped", key: "/a:b@c", want: "/a%3Ab%40c"},
		{name: "non-ascii is escaped per utf-8 byte", key: "/prüfung", want: "/pr%C3%BCfung"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "https://bucket.example.com", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.URL.Path = tt.key
			creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
			if err := SignRequest(req, creds, "us-east-1", "s3", EmptyPayloadSHA256, time.Unix(0, 0)); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			if got := req.URL.RequestURI(); got != tt.want {
				t.Errorf("request URI = %q, want %q", got, tt.want)
			}
			canonical := canonicalRequest(req, EmptyPayloadSHA256, "s3", signedHeaderNames(req))
			if line := strings.Split(canonical, "\n")[1]; line != tt.want {
				t.Errorf("canonical URI = %q, want %q", line, tt.want)
			}
		})
	}
}

// S3 keys are opaque byte strings, so the canonical URI must not be normalised
// or encoded twice. Every other service does encode twice, and getting the two
// the wrong way round produces a 403 nobody can explain.
func TestS3PathIsEncodedOnceAndOtherServicesTwice(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.URL.Path = "/a b/c"

	if got := canonicalURI(req.URL, "s3"); got != "/a%20b/c" {
		t.Errorf("s3 canonical URI = %q, want /a%%20b/c", got)
	}
	if got := canonicalURI(req.URL, "execute-api"); got != "/a%2520b/c" {
		t.Errorf("non-s3 canonical URI = %q, want /a%%2520b/c", got)
	}
}

func TestCanonicalQueryIsSortedByNameThenValue(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "sorted by name", raw: "prefix=J&max-keys=2", want: "max-keys=2&prefix=J"},
		{name: "empty value keeps its equals sign", raw: "lifecycle", want: "lifecycle="},
		{name: "repeated name sorted by value", raw: "k=b&k=a", want: "k=a&k=b"},
		{name: "reserved characters are encoded", raw: "delimiter=%2F", want: "delimiter=%2F"},
		{name: "uppercase sorts before lowercase", raw: "a=1&B=2", want: "B=2&a=1"},
		{name: "no query", raw: "", want: ""},

		// A plus is a plus. Form encoding reads it as a space, and a signer
		// that does the same signs a value the caller never asked for.
		{name: "a plus is a literal plus, not a space", raw: "prefix=a+b", want: "prefix=a%2Bb"},
		{name: "an encoded space stays an encoded space", raw: "prefix=a%20b", want: "prefix=a%20b"},
		{name: "an existing escape is raised to upper case, not decoded", raw: "delimiter=%2f", want: "delimiter=%2F"},
		{name: "a space on the wire is encoded", raw: "prefix=a b", want: "prefix=a%20b"},
		{name: "a lone percent is escaped", raw: "k=100%", want: "k=100%25"},

		// SigV4 orders by the encoded bytes, and escaping puts a '%' where the
		// original byte was. So "." sorts before "/" decoded, and after it
		// once "/" has become "%2F".
		{name: "repeated values sort by the encoded value", raw: "k=.&k=%2F", want: "k=%2F&k=."},
		{name: "names sort by the encoded name", raw: "a.b=1&a%2Fb=2", want: "a%2Fb=2&a.b=1"},
		{name: "an escaped unreserved character folds to the character", raw: "%7Ea=1&~a=2", want: "~a=1&~a=2"},
		{name: "an escaped separator stays inside its value", raw: "k=a%26b=c", want: "k=a%26b%3Dc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalQuery(tt.raw); got != tt.want {
				t.Errorf("canonicalQuery(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCanonicalHeadersAreLowercasedTrimmedAndJoined(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "https://bucket.example.com:9000/k", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Amz-Meta-Note", "  spaced    out  ")
	req.Header.Add("X-Amz-Meta-Multi", "b")
	req.Header.Add("X-Amz-Meta-Multi", "a")
	req.Header.Set("User-Agent", "should-not-be-signed")
	req.Header.Set("Authorization", "should-not-be-signed")
	req.Header.Set("Content-Length", "7")

	names := signedHeaderNames(req)
	if strings.Join(names, ";") != "host;x-amz-meta-multi;x-amz-meta-note" {
		t.Fatalf("signed headers = %v, want host;x-amz-meta-multi;x-amz-meta-note", names)
	}
	if got := canonicalHeaderValue(req, "host"); got != "bucket.example.com:9000" {
		t.Errorf("host value = %q, want the port to be included", got)
	}
	if got := canonicalHeaderValue(req, "x-amz-meta-note"); got != "spaced out" {
		t.Errorf("whitespace not collapsed: %q", got)
	}
	// The values went in as b then a, and that is the order the store sees on
	// the wire. Sorting them here would sign a header nobody sent.
	if got := canonicalHeaderValue(req, "x-amz-meta-multi"); got != "b,a" {
		t.Errorf("repeated header value = %q, want b,a, the order of the request", got)
	}
}

// A store rebuilds the canonical request from the header values in the order
// they arrived, so a signer that reorders them produces a signature that only
// matches when the request happened to be sorted already.
func TestRepeatedHeaderValuesKeepTheRequestOrder(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "descending", values: []string{"zulu", "alpha"}, want: "zulu,alpha"},
		{name: "ascending", values: []string{"alpha", "zulu"}, want: "alpha,zulu"},
		{name: "three out of order", values: []string{"m", "a", "z"}, want: "m,a,z"},
		{name: "each value is still trimmed", values: []string{"  b  ", "\ta   c "}, want: "b,a c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "https://bucket.example.com/k", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			for _, v := range tt.values {
				req.Header.Add("X-Amz-Meta-Multi", v)
			}
			if got := canonicalHeaderValue(req, "x-amz-meta-multi"); got != tt.want {
				t.Errorf("canonical value = %q, want %q", got, tt.want)
			}
		})
	}
}

// The query the signature covers has to be the query the request carries, for
// the same reason the path does.
func TestSignedQueryIsTheQuerySentOnTheWire(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "a plus is not turned into a space", raw: "prefix=a+b", want: "prefix=a%2Bb"},
		{name: "sorted by the encoded value", raw: "k=.&k=%2F", want: "k=%2F&k=."},
		{name: "an empty value gains its equals sign", raw: "lifecycle", want: "lifecycle="},
		{name: "an already canonical query is left alone", raw: "max-keys=2&prefix=J", want: "max-keys=2&prefix=J"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://bucket.example.com/k", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.URL.RawQuery = tt.raw
			creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
			if err := SignRequest(req, creds, "us-east-1", "s3", EmptyPayloadSHA256, time.Unix(0, 0)); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			if got := req.URL.RawQuery; got != tt.want {
				t.Errorf("query on the wire = %q, want %q", got, tt.want)
			}
			canonical := canonicalRequest(req, EmptyPayloadSHA256, "s3", signedHeaderNames(req))
			if line := strings.Split(canonical, "\n")[2]; line != tt.want {
				t.Errorf("canonical query = %q, want %q", line, tt.want)
			}
		})
	}
}

func TestSignRequestRefusesIncompleteCredentials(t *testing.T) {
	tests := []struct {
		name  string
		creds Credentials
	}{
		{name: "nothing at all", creds: Credentials{}},
		{name: "key without secret", creds: Credentials{AccessKeyID: "AKID"}},
		{name: "secret without key", creds: Credentials{SecretAccessKey: "s"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newVectorRequest(t, http.MethodGet, "https://example.com/k", nil)
			if err := SignRequest(req, tt.creds, "us-east-1", "s3", EmptyPayloadSHA256, time.Now()); err == nil {
				t.Fatal("expected an error, got a signed request")
			}
			if req.Header.Get("Authorization") != "" {
				t.Error("an unsigned request must not carry an Authorization header")
			}
		})
	}
}

// The secret is an input to an HMAC and must never appear in the output of one.
func TestSignedRequestCarriesNoSecret(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	req := newVectorRequest(t, http.MethodPut, "https://bucket.example.com/seg-00000001.jsonl", nil)
	creds := Credentials{AccessKeyID: docAccessKey, SecretAccessKey: secret, SessionToken: "session-token"}
	if err := SignRequest(req, creds, "eu-central-1", "s3", EmptyPayloadSHA256, time.Now()); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	for name, values := range req.Header {
		for _, v := range values {
			if strings.Contains(v, secret) {
				t.Errorf("header %s leaks the secret access key", name)
			}
		}
	}
	if req.Header.Get("X-Amz-Security-Token") != "session-token" {
		t.Error("a session token must be sent, and signed, when one is configured")
	}
	if !strings.Contains(strings.Join(signedHeaderNames(req), ";"), "x-amz-security-token") {
		t.Error("the session token must be covered by the signature")
	}
}

func TestCredentialsFromEnvReadsTheStandardVariables(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-from-env")
	t.Setenv("AWS_SESSION_TOKEN", "token-from-env")

	creds := CredentialsFromEnv()
	if creds.AccessKeyID != "AKIDFROMENV" || creds.SecretAccessKey != "secret-from-env" || creds.SessionToken != "token-from-env" {
		t.Fatalf("CredentialsFromEnv did not read the environment: %+v", creds.AccessKeyID)
	}
	if !creds.Complete() {
		t.Error("credentials with both halves present should be complete")
	}
}
