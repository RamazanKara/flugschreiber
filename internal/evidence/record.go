package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// GenesisHash is the prev_hash of the first record in a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// hashDomain separates record hashing from any other use of SHA-256 in this
// project, so a hash from one context can never be replayed as another.
const hashDomain = "flugschreiber-record-v1"

// Record is one line of an evidence segment. The Event is carried as raw JSON
// so that hashing and verification operate on the exact bytes that were
// written, independent of the schema version a reader was compiled against. A
// verifier built today can therefore still check a chain written by a future
// version whose event fields it does not understand.
type Record struct {
	Seq        uint64          `json:"seq"`
	Timestamp  string          `json:"timestamp"`
	PrevHash   string          `json:"prev_hash"`
	RecordHash string          `json:"record_hash"`
	Event      json.RawMessage `json:"event"`
}

// ComputeHash derives the record hash from the fields that are covered by the
// chain. The preimage is newline-delimited with labelled fields; none of the
// values can contain a newline (seq is decimal, timestamp is RFC3339, the
// hashes are hex), so the encoding is unambiguous.
func ComputeHash(seq uint64, timestamp, prevHash string, event []byte) string {
	eventDigest := sha256.Sum256(event)

	var b strings.Builder
	b.WriteString(hashDomain)
	b.WriteString("\nseq:")
	b.WriteString(strconv.FormatUint(seq, 10))
	b.WriteString("\nts:")
	b.WriteString(timestamp)
	b.WriteString("\nprev:")
	b.WriteString(prevHash)
	b.WriteString("\nevent:")
	b.WriteString(hex.EncodeToString(eventDigest[:]))
	b.WriteString("\n")

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Hash recomputes the hash this record should carry.
func (r *Record) Hash() string {
	return ComputeHash(r.Seq, r.Timestamp, r.PrevHash, r.Event)
}

// DecodeEvent unmarshals the raw event payload.
func (r *Record) DecodeEvent() (*Event, error) {
	var e Event
	if err := json.Unmarshal(r.Event, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
