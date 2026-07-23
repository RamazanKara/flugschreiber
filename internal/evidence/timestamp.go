package evidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TimestampsFile holds one line per checkpoint that has been anchored to an
// RFC 3161 timestamping authority. It sits beside checkpoints.jsonl and is
// append-only for the same reason: an anchor that can be rewritten anchors
// nothing.
const TimestampsFile = "timestamps.jsonl"

// DefaultTSAInterval bounds how often a timestamp is requested while the log
// is being written. Checkpoints are cheap and local; a timestamp is a network
// round trip to somebody else's service, usually rate limited and sometimes
// billed, so anchoring every checkpoint is the wrong default.
const DefaultTSAInterval = time.Hour

// DefaultTSATimeout bounds one round trip to the authority.
const DefaultTSATimeout = 30 * time.Second

// Timestamper anchors a prepared RFC 3161 request with an authority and returns
// whatever the authority answered.
//
// It is an interface, and the HTTP implementation lives in internal/custody,
// for the same reason Archiver is one: this package is what a third party reads
// to satisfy themselves that a chain is intact, and that reading is easier when
// its closure holds no network client. Everything that decides whether an
// answer is acceptable stays here.
//
// Implementations must respect ctx and must be safe for use from one goroutine.
type Timestamper interface {
	// Timestamp posts a DER-encoded TimeStampReq and returns the reply, either
	// as a TimeStampResp or as a bare TimeStampToken.
	Timestamp(ctx context.Context, request []byte) ([]byte, error)

	// Name identifies the authority in the timestamp record. For the HTTP
	// implementation this is its URL.
	Name() string
}

// Object identifiers from RFC 3161, RFC 5652 and RFC 5754.
var (
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// PKIStatus values from RFC 3161 section 2.4.2. Anything else means the
// authority declined.
const (
	pkiStatusGranted         = 0
	pkiStatusGrantedWithMods = 1
)

// Timestamp is one RFC 3161 token, recorded against the checkpoint it covers.
//
// The token is stored verbatim, base64 encoded because it is binary DER and
// this file is JSON. Storing it unaltered is what lets a third party check it
// with their own tools years from now, including the full CMS signature
// validation this package deliberately does not attempt.
type Timestamp struct {
	Seq         uint64 `json:"seq"`
	RecordHash  string `json:"record_hash"`
	TokenBase64 string `json:"token_base64"`
	TSAURL      string `json:"tsa_url"`
	RequestedAt string `json:"requested_at"`
}

// Token decodes the stored token.
func (t Timestamp) Token() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(t.TokenBase64)
	if err != nil {
		return nil, fmt.Errorf("evidence: timestamp for seq %d is not valid base64: %w", t.Seq, err)
	}
	return raw, nil
}

// TimestampInfo is everything the built-in structural check establishes about
// a token.
//
// It says what the token claims, not that the claim is signed by anyone in
// particular. Validating the CMS signature and the authority's certificate
// chain needs a trust store and a policy decision about which authorities
// count, both of which belong to the person doing the checking rather than to
// this binary; VERIFY.md gives the openssl command that does it.
type TimestampInfo struct {
	// Imprint is the digest the authority timestamped, hex encoded. For a
	// checkpoint anchor it is the checkpoint's record_hash.
	Imprint string `json:"imprint"`

	HashAlgorithm string `json:"hash_algorithm"`
	SerialNumber  string `json:"serial_number,omitempty"`

	// GenTime is the time the authority says it issued the token, best effort:
	// it is left empty rather than guessed when the encoding is one this
	// parser does not read, because the imprint is the part that has to be
	// exact.
	GenTime string `json:"gen_time,omitempty"`
}

// ASN.1 shapes. Only the fields this package reads are declared; Go's asn1
// allows trailing elements in a SEQUENCE, which is what lets a small parser
// read a structure as large as CMS SignedData without reimplementing it.
type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapsulatedContentInfo
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        asn1.RawValue
}

// BuildTimestampRequest renders the RFC 3161 request that anchors one
// checkpoint.
//
// The message imprint is the checkpoint's record_hash itself, which is already
// a SHA-256 digest of the record it names. Anyone holding the log can
// therefore compare a token's imprint against the chain head byte for byte,
// with no intermediate hashing step to reproduce or to get wrong.
//
// The request asks the authority to include its certificate, so that the
// stored token carries what a later verification needs rather than sending
// whoever checks it looking for a certificate that may by then be hard to find.
func BuildTimestampRequest(recordHash string) ([]byte, error) {
	digest, err := hex.DecodeString(recordHash)
	if err != nil {
		return nil, fmt.Errorf("evidence: timestamp request: record hash %q is not hex: %w", recordHash, err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("evidence: timestamp request: record hash is %d bytes, expected %d", len(digest), sha256.Size)
	}

	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("evidence: timestamp request: %w", err)
	}

	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidSHA256,
				// RFC 5754 permits absent parameters for SHA-2, but authorities
				// in the field are more consistently happy with an explicit
				// NULL, and both are accepted on the way back.
				Parameters: asn1.NullRawValue,
			},
			HashedMessage: digest,
		},
		Nonce:   nonce,
		CertReq: true,
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("evidence: timestamp request: %w", err)
	}
	return der, nil
}

// RequestTimestamp asks a timestamper to anchor recordHash and returns the
// token it issued.
//
// The token is checked before it is returned: an authority that answers with
// a token over a different imprint has anchored something other than what was
// asked for, and storing it would create an anchor that only looks like one.
func RequestTimestamp(ctx context.Context, tsa Timestamper, recordHash string) ([]byte, error) {
	request, err := BuildTimestampRequest(recordHash)
	if err != nil {
		return nil, err
	}
	answer, err := tsa.Timestamp(ctx, request)
	if err != nil {
		return nil, err
	}
	token, err := tokenFromReply(answer)
	if err != nil {
		return nil, fmt.Errorf("evidence: timestamping authority %s: %w", tsa.Name(), err)
	}
	if err := VerifyTimestampImprint(token, recordHash); err != nil {
		return nil, fmt.Errorf("evidence: timestamping authority %s: %w", tsa.Name(), err)
	}
	return token, nil
}

// tokenFromReply accepts either shape an authority may answer with: the
// TimeStampResp that RFC 3161 specifies, or the bare token some tools hand
// back once they have unwrapped it themselves.
func tokenFromReply(der []byte) ([]byte, error) {
	token, respErr := tokenFromResponse(der)
	if respErr == nil {
		return token, nil
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err == nil && ci.ContentType.Equal(oidSignedData) {
		return der, nil
	}
	return nil, respErr
}

// tokenFromResponse pulls the token out of a TimeStampResp.
func tokenFromResponse(der []byte) ([]byte, error) {
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, fmt.Errorf("its reply is not a well-formed TimeStampResp: %w", err)
	}
	switch resp.Status.Status {
	case pkiStatusGranted, pkiStatusGrantedWithMods:
	default:
		return nil, fmt.Errorf("declined the request with PKIStatus %d", resp.Status.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("granted the request but sent no token")
	}
	return resp.TimeStampToken.FullBytes, nil
}

// ParseTimestampToken reads what a token claims, without checking who signed
// it. It accepts either a bare TimeStampToken or a whole TimeStampResp, since
// both shapes are produced by tools in the field and telling them apart costs
// one parse.
//
// It returns an error rather than a partial answer on anything it does not
// understand, and it never panics on arbitrary bytes: a token arrives over the
// network from a third party, so hostile input is the expected case rather
// than an unlikely one.
func ParseTimestampToken(token []byte) (*TimestampInfo, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("evidence: timestamp token is empty")
	}

	body := token
	var ci contentInfo
	if _, err := asn1.Unmarshal(body, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		// Not a ContentInfo, so try the enclosing response shape before giving
		// up: openssl writes .tsr files in exactly that form.
		inner, respErr := tokenFromResponse(body)
		if respErr != nil {
			return nil, fmt.Errorf("evidence: timestamp token is neither a CMS SignedData nor a TimeStampResp: %w", respErr)
		}
		body = inner
		if _, err := asn1.Unmarshal(body, &ci); err != nil {
			return nil, fmt.Errorf("evidence: timestamp token is not a well-formed ContentInfo: %w", err)
		}
		if !ci.ContentType.Equal(oidSignedData) {
			return nil, fmt.Errorf("evidence: timestamp token holds content type %v, expected CMS SignedData", ci.ContentType)
		}
	}

	// Content is [0] EXPLICIT, and encoding/asn1 leaves the wrapper on a
	// RawValue's FullBytes, so the SignedData is what the wrapper contains.
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("evidence: timestamp token does not hold a well-formed SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("evidence: timestamp token encapsulates %v, expected TSTInfo", sd.EncapContentInfo.EContentType)
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return nil, fmt.Errorf("evidence: timestamp token carries no TSTInfo")
	}

	var info tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return nil, fmt.Errorf("evidence: timestamp token holds a TSTInfo this build cannot read: %w", err)
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return nil, fmt.Errorf(
			"evidence: timestamp token uses hash algorithm %v, but the chain is SHA-256, so the two cannot be compared",
			info.MessageImprint.HashAlgorithm.Algorithm)
	}

	out := &TimestampInfo{
		Imprint:       hex.EncodeToString(info.MessageImprint.HashedMessage),
		HashAlgorithm: "sha256",
		GenTime:       generalizedTime(info.GenTime.Bytes),
	}
	if info.SerialNumber != nil {
		out.SerialNumber = info.SerialNumber.String()
	}
	return out, nil
}

// VerifyTimestampImprint is the structural check: it confirms that the token
// covers the record hash it is filed against.
//
// That is a narrower claim than "this log existed at this time" and the
// difference is worth being exact about. It establishes that the token and the
// checkpoint are about the same bytes. Whether the token was really issued by
// an authority, and when, is settled by validating its CMS signature against a
// trust store, which is out of scope here and documented in VERIFY.md.
func VerifyTimestampImprint(token []byte, recordHash string) error {
	info, err := ParseTimestampToken(token)
	if err != nil {
		return err
	}
	if !strings.EqualFold(info.Imprint, recordHash) {
		return fmt.Errorf(
			"evidence: the timestamp token covers %s, but it is filed against %s; the token anchors a different record",
			short(info.Imprint), short(recordHash))
	}
	return nil
}

// generalizedTime renders an ASN.1 GeneralizedTime as RFC 3339, best effort.
// Authorities differ on fractional seconds, so a value this does not
// recognise yields the empty string rather than a wrong time.
func generalizedTime(raw []byte) string {
	for _, layout := range []string{"20060102150405Z0700", "20060102150405.9Z0700", "20060102150405.999999999Z0700"} {
		if t, err := time.Parse(layout, string(raw)); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}

// AppendTimestamp adds one line to timestamps.jsonl and fsyncs it, on the same
// reasoning as AppendCheckpoint: an anchor that is not on disk when the machine
// dies anchors nothing.
func AppendTimestamp(dir string, t Timestamp) error {
	line, err := json.Marshal(&t)
	if err != nil {
		return fmt.Errorf("evidence: marshal timestamp: %w", err)
	}
	line = append(line, '\n')

	path := filepath.Join(dir, TimestampsFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("evidence: open %s: %w", TimestampsFile, err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("evidence: write timestamp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("evidence: fsync %s: %w", TimestampsFile, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// tsaQueueDepth bounds outstanding timestamp requests. It is small because a
// store that is producing checkpoints faster than an authority can answer has
// a configuration problem, and the useful response is to say so rather than to
// grow a queue.
const tsaQueueDepth = 8

// timestampJob is one checkpoint to anchor. The time is captured on the writer
// goroutine, which owns the clock, so that the background worker never calls
// Options.Now.
type timestampJob struct {
	seq        uint64
	recordHash string
	at         time.Time
}

// TimestampStats reports what anchoring has done since the store was opened.
type TimestampStats struct {
	TSA      string `json:"tsa,omitempty"`
	Anchored uint64 `json:"anchored"`
	Failed   uint64 `json:"failed"`
}

// TimestampStats reports anchoring progress. It is safe to call at any time
// and returns zeroes when no authority is configured.
func (s *Store) TimestampStats() TimestampStats {
	return TimestampStats{
		TSA:      s.tsaName(),
		Anchored: s.timestamped.Load(),
		Failed:   s.tsaFailed.Load(),
	}
}

// TimestampErr reports the most recent anchoring failure, or nil.
//
// It is separate from Err for the same reason ArchiveErr is: an authority that
// is down is not a failing store. The checkpoint is written, signed and
// fsynced whatever the authority does, and it stands on its own; the anchor
// upgrades its timestamp from this host's claim to a third party's, and losing
// that upgrade must never cost a record.
func (s *Store) TimestampErr() error {
	if err := s.tsaErr.Load(); err != nil {
		return *err
	}
	return nil
}

// maybeTimestamp queues an anchor for a checkpoint that has just been written,
// if enough time has passed since the last one. It runs on the writer
// goroutine and never blocks there: the round trip happens elsewhere.
func (s *Store) maybeTimestamp(c Checkpoint) {
	if s.tsaJobs == nil {
		return
	}
	now := s.opts.Now()
	if !s.lastTimestampAt.IsZero() && now.Sub(s.lastTimestampAt) < s.opts.TSAInterval {
		return
	}
	s.lastTimestampAt = now

	select {
	case s.tsaJobs <- timestampJob{seq: c.Seq, recordHash: c.RecordHash, at: now}:
	default:
		s.tsaFailed.Add(1)
		s.recordTSAErr(fmt.Errorf(
			"evidence: the timestamp queue is full, the checkpoint at seq %d was not anchored; it is signed and on disk either way",
			c.Seq))
	}
}

func (s *Store) timestampLoop() {
	defer s.tsaWG.Done()
	for job := range s.tsaJobs {
		s.anchor(job)
	}
}

// anchor performs one round trip and records the token. Every failure is
// counted and reported, and none of them touches the chain.
func (s *Store) anchor(job timestampJob) {
	ctx, cancel := context.WithTimeout(s.tsaCtx, s.opts.TSATimeout)
	defer cancel()

	token, err := RequestTimestamp(ctx, s.opts.Timestamper, job.recordHash)
	if err != nil {
		s.tsaFailed.Add(1)
		s.recordTSAErr(err)
		return
	}
	err = AppendTimestamp(s.opts.Dir, Timestamp{
		Seq:         job.seq,
		RecordHash:  job.recordHash,
		TokenBase64: base64.StdEncoding.EncodeToString(token),
		TSAURL:      s.tsaName(),
		RequestedAt: job.at.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		s.tsaFailed.Add(1)
		s.recordTSAErr(err)
		return
	}
	s.timestamped.Add(1)
}

// stopTimestamps drains outstanding requests, bounded by one round trip, and
// then abandons them. An authority that has stopped answering costs anchors,
// never records and never a shutdown that will not finish.
func (s *Store) stopTimestamps() {
	if s.tsaJobs == nil {
		return
	}
	close(s.tsaJobs)
	if drainWithin(&s.tsaWG, s.tsaStop, s.opts.TSATimeout) {
		return
	}
	s.recordTSAErr(fmt.Errorf(
		"evidence: timestamping through %s did not finish within %s of shutdown; the checkpoints it would have anchored are signed and on disk",
		s.tsaName(), s.opts.TSATimeout))
}

// tsaName identifies the configured authority, and is empty when there is
// none, so that it is safe to call from the stats and shutdown paths that run
// whether or not anchoring is on.
func (s *Store) tsaName() string {
	if s.opts.Timestamper == nil {
		return ""
	}
	return s.opts.Timestamper.Name()
}

func (s *Store) recordTSAErr(err error) {
	s.tsaErr.Store(&err)
}

// ReadTimestamps returns every timestamp in dir, in the order written. A
// missing file is not an error: anchoring is off by default and most logs will
// never have one.
//
// A line that does not parse is an error rather than a skipped line, for the
// same reason as in ReadCheckpoints: corrupting a record must not be a way to
// make it quietly disappear.
func ReadTimestamps(dir string) ([]Timestamp, error) {
	f, err := os.Open(filepath.Join(dir, TimestampsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []Timestamp
	sc := newLineScanner(f)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var t Timestamp
		if err := json.Unmarshal(line, &t); err != nil {
			return nil, fmt.Errorf("evidence: %s:%d: %w", TimestampsFile, sc.Line(), err)
		}
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", TimestampsFile, err)
	}
	return out, nil
}
