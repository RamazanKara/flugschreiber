package evidence

import (
	"strings"
	"testing"
)

// Two checkpoints that differ only in where a field boundary falls must not
// render the same signed bytes, or one signature attests to both.
func TestCheckpointFieldsCannotCarryTheDelimiter(t *testing.T) {
	kp, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	shifted := sampleCheckpoint()
	shifted.Timestamp = "2026-03-01T12:00:00Z\nkey_id:0123456789abcdef"
	honest := sampleCheckpoint()
	honest.KeyID = ""
	shifted.KeyID = ""
	if string(CheckpointPreimage(shifted)) == string(CheckpointPreimage(honest)) {
		t.Error("distinct checkpoints render identical preimages, so one signature covers both")
	}

	c := sampleCheckpoint()
	c.Segment = "seg-00000002.jsonl\nseq:99"
	if err := SignCheckpoint(kp.Private, kp.ID, &c); err == nil {
		t.Error("signed a checkpoint whose segment name contains a line break")
	}

	forged := sampleCheckpoint()
	forged.Signature = strings.Repeat("00", 64)
	forged.RecordHash = strings.Repeat("ab", 32) + "\nrecords:1"
	if err := VerifyCheckpointSignature(kp.Public, forged); err == nil {
		t.Error("verified a checkpoint whose record hash contains a line break")
	}
}

// The signed segment list is comma-joined, so a name carrying a comma would let
// one signature stand for two different lists of deleted segments.
func TestPruneAnchorSegmentNamesCannotCarryTheDelimiter(t *testing.T) {
	kp, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		segment string
	}{
		{"comma", "seg-00000001.jsonl,seg-00000002.jsonl"},
		{"newline", "seg-00000001.jsonl\nrecords:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := sampleAnchor()
			a.Segments = []string{tc.segment}
			if err := SignPruneAnchor(kp.Private, kp.ID, &a); err == nil {
				t.Fatalf("signed an anchor naming segment %q", tc.segment)
			}
		})
	}
}
