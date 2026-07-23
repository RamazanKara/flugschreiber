package archive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Algorithm is the only signature algorithm this package implements.
const Algorithm = "AWS4-HMAC-SHA256"

// EmptyPayloadSHA256 is the SHA-256 of zero bytes, used as the payload hash of
// a request with no body.
const EmptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// UnsignedPayload tells S3 that the body is not covered by the signature. It
// is accepted over TLS only, and it means an interception between this process
// and the bucket could alter the bytes without invalidating the request. The
// default is a signed single-chunk payload, where the whole body is hashed
// before the request is sent.
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// StreamingPayloadSHA256 marks a body sent as signed chunks. Flugschreiber
// uploads sealed files whose length and hash are both known before the request
// starts, so it always signs the payload in a single chunk and never emits
// this. The constant is here so that a reader comparing this implementation
// against the AWS specification can see the case was considered.
const StreamingPayloadSHA256 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

const (
	terminator      = "aws4_request"
	amzDateFormat   = "20060102T150405Z"
	shortDateFormat = "20060102"
	upperhex        = "0123456789ABCDEF"
)

// ignoredHeaders are never signed. Each is either added by the transport after
// signing, or rewritten by intermediaries often enough that including it turns
// a working upload into a 403 that is very hard to diagnose.
var ignoredHeaders = map[string]bool{
	"authorization":   true,
	"user-agent":      true,
	"content-length":  true,
	"expect":          true,
	"connection":      true,
	"x-amzn-trace-id": true,
}

// Credentials are the long-lived or session credentials used to sign requests.
// The secret is never rendered by this package, in an error, a log line, or a
// signature.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// Complete reports whether both halves of the key pair are present.
func (c Credentials) Complete() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != ""
}

// CredentialsFromEnv reads the standard AWS environment variables. It is the
// fallback when nothing is configured explicitly, so that a deployment can use
// the same secret injection as everything else in its cluster.
func CredentialsFromEnv() Credentials {
	return Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
}

// SignRequest adds the SigV4 headers to req: x-amz-date, x-amz-content-sha256,
// x-amz-security-token when the credentials are temporary, and Authorization.
//
// payloadHash is the lowercase hex SHA-256 of the body, or UnsignedPayload.
// The caller computes it, because it also has to decide whether the body can
// be read twice.
//
// SignRequest pins req.URL.RawPath to the encoding it signed. Go leaves
// sub-delimiters such as '$' unescaped in a path where SigV4 requires them
// percent-encoded, and a request whose wire bytes differ from its signed bytes
// is rejected with an error that names neither cause.
func SignRequest(req *http.Request, creds Credentials, region, service, payloadHash string, signTime time.Time) error {
	if !creds.Complete() {
		return errors.New("archive: signing needs an access key id and a secret access key")
	}
	if payloadHash == "" {
		return errors.New("archive: signing needs a payload hash")
	}

	t := signTime.UTC()
	req.Header.Set("X-Amz-Date", t.Format(amzDateFormat))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	pinEscapedPath(req.URL)
	// The query is pinned for the same reason as the path. The store rebuilds
	// the canonical request from the bytes it received, so anything the
	// canonical form normalises has to be normalised on the wire as well.
	req.URL.RawQuery = canonicalQuery(req.URL.RawQuery)

	signed := signedHeaderNames(req)
	canonical := canonicalRequest(req, payloadHash, service, signed)
	scope := credentialScope(t, region, service)
	sts := stringToSign(t, scope, canonical)
	sig := hex.EncodeToString(hmacSHA256(signingKey(creds.SecretAccessKey, t, region, service), sts))

	req.Header.Set("Authorization", Algorithm+
		" Credential="+creds.AccessKeyID+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+
		", Signature="+sig)
	return nil
}

// pinEscapedPath makes EscapedPath return the SigV4 encoding of the path.
func pinEscapedPath(u *url.URL) {
	esc := uriEncode(u.Path, false)
	if esc == u.Path {
		u.RawPath = ""
		return
	}
	u.RawPath = esc
}

// canonicalRequest renders the canonical request over exactly the header names
// in signed, which must be lowercase and sorted. Taking the list as an
// argument rather than deriving it lets a verifier reproduce the string from
// the SignedHeaders it was given, which is what a server does and what the
// tests do.
func canonicalRequest(req *http.Request, payloadHash, service string, signed []string) string {
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteByte('\n')
	b.WriteString(canonicalURI(req.URL, service))
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(req.URL.RawQuery))
	b.WriteByte('\n')
	for _, name := range signed {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(canonicalHeaderValue(req, name))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(strings.Join(signed, ";"))
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String()
}

// canonicalURI encodes the path. S3 is the documented exception to the SigV4
// rule that the path is encoded twice and normalised: object keys are opaque
// byte strings, so "a//b" and "a/../b" are distinct keys and must survive
// signing unchanged.
func canonicalURI(u *url.URL, service string) string {
	p := u.Path
	if p == "" {
		return "/"
	}
	esc := uriEncode(p, false)
	if service != "s3" {
		esc = uriEncode(esc, false)
	}
	return esc
}

// canonicalQuery sorts parameters by encoded name and then by encoded value,
// with each component percent-encoded by the strict rules. A parameter with no
// value keeps its '='.
//
// The raw query is split on the wire separators and never decoded. Running it
// through url.ParseQuery would turn '+' into a space, which is form encoding
// and not the URI encoding SigV4 specifies, would unescape %XX before
// re-escaping it, and would order the parameters by their decoded text where
// the signature is computed over the encoded text. Each of those signs a string
// the store will not arrive at.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type param struct{ name, value string }
	params := make([]param, 0, strings.Count(raw, "&")+1)
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		params = append(params, param{encodeQueryComponent(name), encodeQueryComponent(value)})
	}
	sort.Slice(params, func(i, j int) bool {
		if params[i].name != params[j].name {
			return params[i].name < params[j].name
		}
		return params[i].value < params[j].value
	})

	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = p.name + "=" + p.value
	}
	return strings.Join(parts, "&")
}

// encodeQueryComponent applies the strict SigV4 encoding to one query name or
// value that is already in wire form. It is what a store computes when it
// re-encodes the component it decoded, without ever decoding the whole query:
// an escape of an unreserved character folds to that character, because %7E and
// '~' have to reach the same canonical byte, every other escape is kept with
// its hex digits in upper case, and everything else outside the unreserved set
// is escaped. Splitting the query first is what keeps an escaped separator such
// as %26 from being read as one.
//
// The result encodes to itself, which is what lets SignRequest pin the query on
// the wire to the query it signed.
func encodeQueryComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			c = hexByte(s[i+1], s[i+2])
			i += 2
		}
		if unreservedByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0x0f])
	}
	return b.String()
}

func unreservedByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexByte(hi, lo byte) byte { return hexDigit(hi)<<4 | hexDigit(lo) }

func hexDigit(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// signedHeaderNames lists the lowercase header names to sign, sorted.
func signedHeaderNames(req *http.Request) []string {
	names := []string{"host"}
	for name := range req.Header {
		lower := strings.ToLower(name)
		if lower == "host" || ignoredHeaders[lower] {
			continue
		}
		names = append(names, lower)
	}
	sort.Strings(names)
	return names
}

// canonicalHeaderValue joins repeated headers with a comma and collapses runs
// of whitespace, which is what the signature is computed over.
//
// The values are joined in the order they appear in the request. Sorting them
// would be signing a header the store never received: the store rebuilds the
// canonical request from the wire order, so a request carrying "b" then "a"
// must be signed as "b,a".
func canonicalHeaderValue(req *http.Request, name string) string {
	var vals []string
	if name == "host" {
		host := req.Host
		if host == "" {
			host = req.URL.Host
		}
		vals = []string{host}
	} else {
		vals = req.Header.Values(name)
	}
	trimmed := make([]string, len(vals))
	for i, v := range vals {
		trimmed[i] = collapseSpaces(v)
	}
	return strings.Join(trimmed, ",")
}

func collapseSpaces(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "  ") && !strings.Contains(s, "\t") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(c)
	}
	return b.String()
}

func credentialScope(t time.Time, region, service string) string {
	return t.UTC().Format(shortDateFormat) + "/" + region + "/" + service + "/" + terminator
}

func stringToSign(t time.Time, scope, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return Algorithm + "\n" +
		t.UTC().Format(amzDateFormat) + "\n" +
		scope + "\n" +
		hex.EncodeToString(sum[:])
}

// signingKey derives the date, region and service scoped key. Each step throws
// away the previous secret, so a key that leaks is only usable for one day, in
// one region, against one service.
func signingKey(secret string, t time.Time, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), t.UTC().Format(shortDateFormat))
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, terminator)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// uriEncode percent-encodes s per RFC 3986, where only A-Z a-z 0-9 - . _ ~ are
// left alone. This is stricter than Go's URL escaping, which is why the
// package does its own. encodeSlash is false for paths and true for query
// components.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
}
