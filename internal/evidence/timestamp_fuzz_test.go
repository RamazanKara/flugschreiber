package evidence

import (
	"encoding/hex"
	"testing"
)

// FuzzParseTimestampToken drives the token parser over arbitrary bytes.
//
// A token is the one thing in an evidence directory that arrives over the
// network from a third party, so hostile or merely strange input is the
// expected case. The parser walks nested ASN.1 that it did not produce, which
// is exactly the shape of code that panics on a length field somebody made up.
//
// The properties are that it never panics, and that it never contradicts
// itself: whatever imprint it reports has to be the imprint the imprint check
// then accepts.
func FuzzParseTimestampToken(f *testing.F) {
	imprint, err := hex.DecodeString(hashOf(0x5a))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Add([]byte("not DER at all"))
	f.Add(timestampTokenOver(f, imprint))
	f.Add(timestampResponseOver(f, imprint))
	f.Add(timestampTokenOver(f, nil))
	f.Add(timestampTokenOver(f, imprint)[:16])
	f.Add(mustMarshalTSTInfo(f, oidSHA256, imprint))

	f.Fuzz(func(t *testing.T, token []byte) {
		info, err := ParseTimestampToken(token)
		if err != nil {
			if info != nil {
				t.Fatalf("both a result and an error: %+v, %v", info, err)
			}
			return
		}
		if info == nil {
			t.Fatal("neither a result nor an error")
		}
		if _, err := hex.DecodeString(info.Imprint); err != nil {
			t.Fatalf("Imprint %q is not hex: %v", info.Imprint, err)
		}
		if err := VerifyTimestampImprint(token, info.Imprint); err != nil {
			t.Fatalf("the parser reported imprint %s but the check rejects it: %v", info.Imprint, err)
		}
	})
}
