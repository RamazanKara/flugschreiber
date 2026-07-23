package evidence

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The marshalling side of the token shapes. They are separate from the types
// the parser reads because a parser declares only the fields it needs, while a
// fixture has to produce a structure with everything a real token carries,
// including the elements the parser is supposed to skip.
type (
	tstInfoOut struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint messageImprint
		SerialNumber   *big.Int
		//nolint:misspell // an encoding/asn1 tag keyword, not prose
		GenTime time.Time `asn1:"generalized"`
	}

	encapOut struct {
		EContentType asn1.ObjectIdentifier
		EContent     []byte `asn1:"explicit,tag:0"`
	}

	signedDataOut struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		EncapContentInfo encapOut

		// A real token carries the authority's certificates and one SignerInfo
		// after the content. The parser has to walk past them, so the fixture
		// has to have them.
		Certificates asn1.RawValue
		SignerInfos  asn1.RawValue
	}

	contentInfoOut struct {
		ContentType asn1.ObjectIdentifier
		Content     signedDataOut `asn1:"explicit,tag:0"`
	}

	statusOut struct {
		Status int
	}

	respOut struct {
		Status statusOut
		Token  asn1.RawValue
	}
)

// timestampTokenOver builds a syntactically real RFC 3161 token over imprint.
// Nothing signs it: this package checks what a token says, and a test of that
// check needs a token that says something, not one that is trusted.
func timestampTokenOver(t testing.TB, imprint []byte) []byte {
	t.Helper()

	infoDER, err := asn1.Marshal(tstInfoOut{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: imprint,
		},
		SerialNumber: big.NewInt(4711),
		GenTime:      time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("marshal TSTInfo: %v", err)
	}

	tokenDER, err := asn1.Marshal(contentInfoOut{
		ContentType: oidSignedData,
		Content: signedDataOut{
			Version:          3,
			DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}},
			EncapContentInfo: encapOut{EContentType: oidTSTInfo, EContent: infoDER},
			Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x30, 0x02, 0x05, 0x00}},
			SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: 17, IsCompound: true, Bytes: []byte{0x30, 0x02, 0x05, 0x00}},
		},
	})
	if err != nil {
		t.Fatalf("marshal TimeStampToken: %v", err)
	}
	return tokenDER
}

func timestampResponseOver(t testing.TB, imprint []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(respOut{
		Status: statusOut{Status: pkiStatusGranted},
		Token:  asn1.RawValue{FullBytes: timestampTokenOver(t, imprint)},
	})
	if err != nil {
		t.Fatalf("marshal TimeStampResp: %v", err)
	}
	return der
}

// tsaStub is a timestamping authority that is real enough to test against: it
// parses the query it is sent and answers over the imprint it finds there, so
// a malformed request fails the test rather than passing unnoticed.
//
// It implements Timestamper directly rather than over HTTP, because what this
// package is responsible for is deciding whether an answer is acceptable. The
// transport that carries the answer belongs to internal/custody and is tested
// there.
type tsaStub struct {
	t    *testing.T
	name string

	mu       sync.Mutex
	requests int
	imprints []string

	// answer replaces the normal reply, which is how a test makes an authority
	// misbehave.
	answer func(t *testing.T, imprint []byte) ([]byte, error)
}

func newTSAStub(t *testing.T) *tsaStub {
	t.Helper()
	return &tsaStub{t: t, name: "https://tsa.test.invalid/anchor"}
}

func (s *tsaStub) Name() string { return s.name }

func (s *tsaStub) Timestamp(_ context.Context, request []byte) ([]byte, error) {
	var query timeStampReq
	if _, err := asn1.Unmarshal(request, &query); err != nil {
		s.t.Errorf("the query is not a well-formed TimeStampReq: %v", err)
		return nil, err
	}
	imprint := query.MessageImprint.HashedMessage

	s.mu.Lock()
	s.requests++
	s.imprints = append(s.imprints, hex.EncodeToString(imprint))
	answer := s.answer
	s.mu.Unlock()

	if answer != nil {
		return answer(s.t, imprint)
	}
	return timestampResponseOver(s.t, imprint), nil
}

func (s *tsaStub) seen() (int, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, append([]string(nil), s.imprints...)
}

func hashOf(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

// The query has to be an RFC 3161 request over the chain head, or an authority
// will reject it and the anchors will never exist.
func TestTimestampRequestIsAWellFormedQueryOverTheRecordHash(t *testing.T) {
	head := hashOf(0xab)
	der, err := BuildTimestampRequest(head)
	if err != nil {
		t.Fatalf("BuildTimestampRequest: %v", err)
	}

	var req timeStampReq
	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		t.Fatalf("the request is not a well-formed TimeStampReq: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("%d trailing bytes after the request", len(rest))
	}
	if req.Version != 1 {
		t.Errorf("version = %d, want 1", req.Version)
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("hash algorithm = %v, want SHA-256", req.MessageImprint.HashAlgorithm.Algorithm)
	}
	if got := hex.EncodeToString(req.MessageImprint.HashedMessage); got != head {
		t.Errorf("imprint = %s, want the record hash %s", got, head)
	}
	if !req.CertReq {
		t.Error("the request does not ask for the authority's certificate, which whoever verifies the token will need")
	}
	if req.Nonce == nil || req.Nonce.Sign() < 0 {
		t.Errorf("nonce = %v, want a non-negative random value", req.Nonce)
	}
}

func TestBuildTimestampRequestRefusesSomethingThatIsNotAChainHash(t *testing.T) {
	for _, bad := range []string{"", "not hex", strings.Repeat("ab", 16)} {
		if _, err := BuildTimestampRequest(bad); err == nil {
			t.Errorf("BuildTimestampRequest(%q) was accepted", bad)
		}
	}
}

// The structural check is the only claim this package makes about a token, so
// it has to be exact: the token covers this record hash, or it does not.
func TestTokenImprintIsCheckedAgainstTheRecordHash(t *testing.T) {
	head := hashOf(0x11)
	raw, err := hex.DecodeString(head)
	if err != nil {
		t.Fatal(err)
	}
	token := timestampTokenOver(t, raw)

	info, err := ParseTimestampToken(token)
	if err != nil {
		t.Fatalf("ParseTimestampToken: %v", err)
	}
	if info.Imprint != head {
		t.Errorf("Imprint = %s, want %s", info.Imprint, head)
	}
	if info.HashAlgorithm != "sha256" {
		t.Errorf("HashAlgorithm = %q, want sha256", info.HashAlgorithm)
	}
	if info.SerialNumber != "4711" {
		t.Errorf("SerialNumber = %q, want 4711", info.SerialNumber)
	}
	if info.GenTime != "2026-03-01T12:00:00Z" {
		t.Errorf("GenTime = %q, want the time in the token", info.GenTime)
	}

	if err := VerifyTimestampImprint(token, head); err != nil {
		t.Errorf("a token over this record hash did not check out: %v", err)
	}
	if err := VerifyTimestampImprint(token, hashOf(0x22)); err == nil {
		t.Error("a token over a different record hash was accepted")
	}
}

// openssl writes .tsr files as a whole response. Accepting both shapes costs
// one parse and saves whoever holds the log a conversion step.
func TestParseTimestampTokenAcceptsABareTokenOrAWholeResponse(t *testing.T) {
	raw, err := hex.DecodeString(hashOf(0x33))
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"bare token":    timestampTokenOver(t, raw),
		"full response": timestampResponseOver(t, raw),
	} {
		t.Run(name, func(t *testing.T) {
			info, err := ParseTimestampToken(der)
			if err != nil {
				t.Fatalf("ParseTimestampToken: %v", err)
			}
			if info.Imprint != hashOf(0x33) {
				t.Errorf("Imprint = %s", info.Imprint)
			}
		})
	}
}

func TestParseTimestampTokenRefusesWhatItCannotVouchFor(t *testing.T) {
	raw, err := hex.DecodeString(hashOf(0x44))
	if err != nil {
		t.Fatal(err)
	}
	wrongAlgorithm, err := asn1.Marshal(contentInfoOut{
		ContentType: oidSignedData,
		Content: signedDataOut{
			Version:          3,
			DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
			EncapContentInfo: encapOut{EContentType: oidTSTInfo, EContent: mustMarshalTSTInfo(t, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, raw)},
			Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true},
			SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: 17, IsCompound: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token []byte
	}{
		{"empty", nil},
		{"not DER at all", []byte("this is not a timestamp token")},
		{"truncated token", timestampTokenOver(t, raw)[:20]},
		{"a SHA-1 imprint the chain cannot be compared with", wrongAlgorithm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseTimestampToken(tc.token); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func mustMarshalTSTInfo(t testing.TB, algorithm asn1.ObjectIdentifier, imprint []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(tstInfoOut{
		Version:        1,
		Policy:         asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm}, HashedMessage: imprint},
		SerialNumber:   big.NewInt(1),
		GenTime:        time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A checkpoint's time is a claim about this host's clock until somebody else
// signs it. This is that upgrade, end to end.
func TestStoreAnchorsItsCheckpointsToTheAuthority(t *testing.T) {
	dir := t.TempDir()
	stub := newTSAStub(t)
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(Options{
		Dir:             dir,
		SegmentMaxBytes: 400,
		Keys:            kp,
		Timestamper:     stub,
		TSAInterval:     time.Nanosecond,
		TSATimeout:      5 * time.Second,
		Now:             fixedClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	stamps, err := ReadTimestamps(dir)
	if err != nil {
		t.Fatalf("ReadTimestamps: %v", err)
	}
	if len(stamps) == 0 {
		t.Fatal("no checkpoint was anchored")
	}
	checks, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	bySeq := map[uint64]string{}
	for _, c := range checks {
		bySeq[c.Seq] = c.RecordHash
	}
	for _, ts := range stamps {
		if ts.TSAURL != stub.Name() {
			t.Errorf("timestamp at seq %d names %q, want %q", ts.Seq, ts.TSAURL, stub.Name())
		}
		if ts.RequestedAt == "" {
			t.Errorf("timestamp at seq %d records no request time", ts.Seq)
		}
		if bySeq[ts.Seq] != ts.RecordHash {
			t.Errorf("timestamp at seq %d anchors %s, the checkpoint attests %s", ts.Seq, ts.RecordHash, bySeq[ts.Seq])
		}
		token, err := ts.Token()
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyTimestampImprint(token, ts.RecordHash); err != nil {
			t.Errorf("the stored token does not cover the record hash it is filed against: %v", err)
		}
	}

	requests, imprints := stub.seen()
	if requests != len(stamps) {
		t.Errorf("the authority saw %d requests but %d tokens were stored", requests, len(stamps))
	}
	for i, got := range imprints {
		if got != stamps[i].RecordHash {
			t.Errorf("request %d asked for %s, stored %s", i, got, stamps[i].RecordHash)
		}
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("an anchored log did not verify: %v", res.Problems)
	}
	if res.Timestamps != len(stamps) {
		t.Errorf("Timestamps = %d, want %d", res.Timestamps, len(stamps))
	}
	if res.TimestampedCheckpoints != len(stamps) {
		t.Errorf("TimestampedCheckpoints = %d, want %d", res.TimestampedCheckpoints, len(stamps))
	}

	stats := s.TimestampStats()
	if stats.Anchored != uint64(len(stamps)) || stats.Failed != 0 {
		t.Errorf("TimestampStats = %+v, want %d anchored and no failures", stats, len(stamps))
	}
	if err := s.TimestampErr(); err != nil {
		t.Errorf("TimestampErr = %v, want nil", err)
	}
}

// An authority is somebody else's service. When it is down the anchors are
// lost and nothing else is: not a record, not a checkpoint, not the chain.
func TestADownAuthorityCostsAnchorsAndNothingElse(t *testing.T) {
	answers := map[string]func(t *testing.T, imprint []byte) ([]byte, error){
		"refuses every request": func(*testing.T, []byte) ([]byte, error) {
			return nil, errors.New("custody: answered 503 Service Unavailable")
		},
		"answers with rubbish":      func(*testing.T, []byte) ([]byte, error) { return []byte("not a token"), nil },
		"anchors the wrong digest":  nil, // filled in below, it needs the helper
		"declines with a PKIStatus": func(*testing.T, []byte) ([]byte, error) { return mustMarshalRejection(), nil },
	}
	answers["anchors the wrong digest"] = func(t *testing.T, _ []byte) ([]byte, error) {
		other, err := hex.DecodeString(hashOf(0x99))
		if err != nil {
			t.Fatal(err)
		}
		return timestampResponseOver(t, other), nil
	}

	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			stub := newTSAStub(t)
			stub.answer = answer

			kp, err := LoadOrCreateKeyPair(dir)
			if err != nil {
				t.Fatal(err)
			}
			s, err := Open(Options{
				Dir:             dir,
				SegmentMaxBytes: 400,
				Keys:            kp,
				Timestamper:     stub,
				TSAInterval:     time.Nanosecond,
				TSATimeout:      2 * time.Second,
				Now:             fixedClock(),
			})
			if err != nil {
				t.Fatal(err)
			}
			appendN(t, s, 12)
			if err := s.Err(); err != nil {
				t.Fatalf("a failing authority turned into a store error: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			if s.Appended() != 12 {
				t.Errorf("Appended = %d, want 12", s.Appended())
			}
			res, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK() {
				t.Fatalf("a failing authority damaged the log: %v", res.Problems)
			}
			if res.Records != 12 {
				t.Errorf("Records = %d, want 12", res.Records)
			}
			if !res.Attested {
				t.Error("checkpoints stopped being written because the authority was down")
			}
			if res.Timestamps != 0 {
				t.Errorf("Timestamps = %d, want none: no usable token was issued", res.Timestamps)
			}

			if stats := s.TimestampStats(); stats.Failed == 0 {
				t.Error("failures were not counted, so nothing would ever alert")
			}
			if s.TimestampErr() == nil {
				t.Error("TimestampErr is nil although every request failed")
			}
		})
	}
}

func mustMarshalRejection() []byte {
	der, _ := asn1.Marshal(struct {
		Status statusOut
	}{Status: statusOut{Status: 2}})
	return der
}

// A token filed against a checkpoint it does not cover is a claim about this
// log that is demonstrably wrong, so it is a problem rather than a note.
func TestATokenThatContradictsItsCheckpointIsReported(t *testing.T) {
	dir := t.TempDir()
	s, kp := signedStore(t, dir)
	appendN(t, s, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_ = kp

	checks, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) == 0 {
		t.Fatal("no checkpoint to anchor")
	}
	head := checks[len(checks)-1]

	elsewhere, err := hex.DecodeString(hashOf(0x77))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ts   Timestamp
	}{
		{
			name: "the token covers another digest",
			ts: Timestamp{
				Seq:         head.Seq,
				RecordHash:  head.RecordHash,
				TokenBase64: base64.StdEncoding.EncodeToString(timestampTokenOver(t, elsewhere)),
				TSAURL:      "https://tsa.example",
				RequestedAt: "2026-03-01T12:00:00Z",
			},
		},
		{
			name: "the line claims a hash the checkpoint does not carry",
			ts: Timestamp{
				Seq:         head.Seq,
				RecordHash:  hashOf(0x77),
				TokenBase64: base64.StdEncoding.EncodeToString(timestampTokenOver(t, elsewhere)),
				TSAURL:      "https://tsa.example",
				RequestedAt: "2026-03-01T12:00:00Z",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stampPath := filepath.Join(dir, TimestampsFile)
			if err := os.RemoveAll(stampPath); err != nil {
				t.Fatal(err)
			}
			if err := AppendTimestamp(dir, tc.ts); err != nil {
				t.Fatal(err)
			}

			res, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK() {
				t.Fatal("a token that contradicts its checkpoint verified as fine")
			}
			if !problemKinds(res)[ProblemBadTimestamp] {
				t.Errorf("expected a bad_timestamp problem, got %v", res.Problems)
			}
			if res.TimestampedCheckpoints != 0 {
				t.Errorf("TimestampedCheckpoints = %d, want 0", res.TimestampedCheckpoints)
			}
		})
	}
}

// A token this build cannot parse is this build's limit, not the log's fault,
// so it is a note and never a failure. Full CMS validation is openssl's job.
func TestATokenThisBuildCannotParseIsANoteRatherThanAProblem(t *testing.T) {
	dir := t.TempDir()
	s, _ := signedStore(t, dir)
	appendN(t, s, 2)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	checks, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	head := checks[len(checks)-1]

	err = AppendTimestamp(dir, Timestamp{
		Seq:         head.Seq,
		RecordHash:  head.RecordHash,
		TokenBase64: base64.StdEncoding.EncodeToString([]byte("a token from an authority whose encoding we do not read")),
		TSAURL:      "https://tsa.example",
		RequestedAt: "2026-03-01T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("an unparseable token was reported as chain damage: %v", res.Problems)
	}
	if res.Timestamps != 1 || res.TimestampedCheckpoints != 0 {
		t.Errorf("Timestamps = %d, TimestampedCheckpoints = %d, want 1 and 0", res.Timestamps, res.TimestampedCheckpoints)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), TimestampsFile) {
		t.Errorf("nothing in the notes mentions the token that could not be checked: %v", res.Notes)
	}
}

func TestReadTimestampsOnAnAbsentFileIsNotAnError(t *testing.T) {
	got, err := ReadTimestamps(t.TempDir())
	if err != nil {
		t.Fatalf("ReadTimestamps: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil for a log that has never been anchored", got)
	}
}

func TestReadTimestampsReportsAnUnparseableLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, TimestampsFile), []byte("{not json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTimestamps(dir); err == nil {
		t.Fatal("a corrupt timestamp line was skipped instead of reported")
	}
}

// Anchoring is off unless an authority is configured, and off means no file,
// no goroutine and no network.
func TestNoAuthorityMeansNoAnchoring(t *testing.T) {
	dir := t.TempDir()
	s, _ := signedStore(t, dir)
	appendN(t, s, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, TimestampsFile)); !os.IsNotExist(err) {
		t.Errorf("%s exists although no authority was configured: %v", TimestampsFile, err)
	}
	if stats := s.TimestampStats(); stats != (TimestampStats{}) {
		t.Errorf("TimestampStats = %+v, want the zero value", stats)
	}
}
