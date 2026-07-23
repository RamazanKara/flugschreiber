package pdf

import (
	"testing"
)

func TestEncodeProducesTheDocumentedWinAnsiBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []byte
	}{
		{"ascii is the identity", "Model served", []byte("Model served")},
		{"german umlauts", "Prüfen Sie Ausgänge, Überprüfung", []byte("Pr\xfcfen Sie Ausg\xe4nge, \xdcberpr\xfcfung")},
		{"sharp s", "außerdem", []byte("au\xdferdem")},
		{"german quotation marks", "„zitiert“", []byte("\x84zitiert\x93")},
		{"english quotation marks", "“quoted”", []byte("\x93quoted\x94")},
		// The generated tables use an en dash for a range and an em dash
		// for a value the evidence does not have, so both must encode.
		{"dashes", "256 \u2013 1024 \u2014 none", []byte("256 \x96 1024 \x97 none")},
		{"apostrophe and bullet", "provider’s •", []byte("provider\x92s \x95")},
		{"non breaking space keeps its own code", "a b", []byte("a\xa0b")},
		{"thin space folds to a plain space", "a b", []byte("a b")},
		{"tab folds to a space", "a\tb", []byte("a b")},
		{"euro and section sign", "€ §", []byte("\x80 \xa7")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subs := map[rune]int{}
			got := encode(tc.in, subs)
			if string(got) != string(tc.want) {
				t.Errorf("encode(%q) = % x, want % x", tc.in, got, tc.want)
			}
			if len(subs) != 0 {
				t.Errorf("encode(%q) reported substitutions %v for text WinAnsi covers", tc.in, subs)
			}
		})
	}
}

func TestUnrepresentableRunesBecomeAVisibleMarker(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"check mark", "ok ✓", "ok [U+2713]"},
		{"cjk", "日本", "[U+65E5][U+672C]"},
		{"emoji beyond the basic plane", "🙂", "[U+1F642]"},
		{"control character", "a\x01b", "a[U+0001]b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subs := map[rune]int{}
			if got := string(encode(tc.in, subs)); got != tc.want {
				t.Errorf("encode(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if len(subs) == 0 {
				t.Error("a rune was replaced without being reported, which is a silent loss")
			}
		})
	}
}

func TestSubstitutionsAreCountedAndSorted(t *testing.T) {
	subs := map[rune]int{}
	encode("✓ ⚠ ✓ ✓", subs)
	got := substitutions(subs)
	if len(got) != 2 {
		t.Fatalf("expected two distinct runes, got %+v", got)
	}
	if got[0].Rune != '⚠' || got[0].Count != 1 {
		t.Errorf("entries must be ordered by code point, got %+v first", got[0])
	}
	if got[1].Rune != '✓' || got[1].Count != 3 {
		t.Errorf("second entry %+v, want three occurrences of the check mark", got[1])
	}
}

func TestEveryEncodableByteHasAWidth(t *testing.T) {
	seen := map[byte]bool{}
	for c := byte(0x20); c < 0x7F; c++ {
		seen[c] = true
	}
	for _, b := range winAnsi {
		seen[b] = true
	}
	for i := range fonts {
		f := &fonts[i]
		if f.fixed != 0 {
			continue
		}
		for c := range seen {
			if f.widths[c] == 0 {
				t.Errorf("%s has no width for the encodable byte 0x%02X", f.base, c)
			}
		}
	}
}

func TestKnownHelveticaAdvancesMatchTheAdobeMetrics(t *testing.T) {
	// Spot checks against the published Adobe Helvetica AFM, so a corrupted
	// generated table cannot pass unnoticed.
	cases := []struct {
		style Style
		b     byte
		want  uint16
	}{
		{0, ' ', 278},
		{0, 'A', 667},
		{0, 'a', 556},
		{0, 'W', 944},
		{0, 'i', 222},
		{0, 0x97, 1000}, // emdash
		{0, 0x96, 556},  // endash
		{0, 0xE4, 556},  // adieresis
		{0, 0xDF, 611},  // germandbls
		{Bold, 'A', 722},
		{Bold, 'a', 556},
		{Italic, 'A', 667},
		{Bold | Italic, 'W', 944},
	}
	for _, tc := range cases {
		f := fontFor(tc.style)
		if got := f.widths[tc.b]; got != tc.want {
			t.Errorf("%s width of 0x%02X = %d, want %d", f.base, tc.b, got, tc.want)
		}
	}
}

func TestTheObliqueFacesShareTheUprightWidths(t *testing.T) {
	// Adobe's Helvetica-Oblique is Helvetica slanted, glyph for glyph, so a
	// code whose width differs between the two is a table drawn from a
	// substitute font rather than from the metrics the viewer will use.
	pairs := []struct {
		name           string
		upright, slant *[256]uint16
	}{
		{"Helvetica", &helveticaWidths, &helveticaObliqueWidths},
		{"Helvetica-Bold", &helveticaBoldWidths, &helveticaBoldObliqueWidths},
	}
	for _, p := range pairs {
		for c := 0; c < 256; c++ {
			if p.upright[c] != p.slant[c] {
				t.Errorf("%s and its oblique disagree at 0x%02X: %d against %d",
					p.name, c, p.upright[c], p.slant[c])
			}
		}
	}
}

func TestTheCodesURWGetsWrongCarryTheAdobeWidths(t *testing.T) {
	// URW Nimbus, the usual source for a generated table, differs from Adobe
	// on exactly these codes. Pinning them stops a regeneration from
	// silently widening every line that contains one.
	cases := []struct {
		b    byte
		name string
		want [4]uint16 // regular, bold, oblique, bold oblique
	}{
		{0xB0, "degree", [4]uint16{400, 400, 400, 400}},
		{0xB2, "twosuperior", [4]uint16{333, 333, 333, 333}},
		{0xB3, "threesuperior", [4]uint16{333, 333, 333, 333}},
		{0xB9, "onesuperior", [4]uint16{333, 333, 333, 333}},
		{0xBC, "onequarter", [4]uint16{834, 834, 834, 834}},
		{0xBD, "onehalf", [4]uint16{834, 834, 834, 834}},
		{0xBE, "threequarters", [4]uint16{834, 834, 834, 834}},
		{0x92, "quoteright", [4]uint16{222, 278, 222, 278}},
		{0xDD, "Yacute", [4]uint16{667, 667, 667, 667}},
		{0xDE, "Thorn", [4]uint16{667, 667, 667, 667}},
		{0xFE, "thorn", [4]uint16{556, 611, 556, 611}},
	}
	styles := [4]Style{0, Bold, Italic, Bold | Italic}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i, st := range styles {
				f := fontFor(st)
				if got := f.widths[tc.b]; got != tc.want[i] {
					t.Errorf("%s width of %s (0x%02X) = %d, want %d",
						f.base, tc.name, tc.b, got, tc.want[i])
				}
			}
		})
	}
}

func TestCourierAdvancesEveryGlyphEqually(t *testing.T) {
	f := fontFor(Mono)
	single := f.advance([]byte("i"), 10)
	wide := f.advance([]byte("W"), 10)
	if single != wide {
		t.Fatalf("Courier is not monospaced in this table: i is %v, W is %v", single, wide)
	}
	if got := f.advance([]byte("abcde"), 10); got != 30 {
		t.Errorf("five Courier glyphs at 10pt = %v, want 30", got)
	}
}

func TestEveryStyleCombinationResolvesToAStandardFont(t *testing.T) {
	for s := Style(0); s <= Bold|Italic|Mono; s++ {
		f := fontFor(s)
		if f.base == "" || f.resource == "" {
			t.Errorf("style %d resolves to an empty font", s)
		}
		if f.fixed == 0 && f.widths == nil {
			t.Errorf("style %d resolves to %s with no metrics", s, f.base)
		}
	}
}
