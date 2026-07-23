package pdf

import "testing"

// Zero-width characters carry no ink. Folding them to an ordinary space, as an
// earlier version did, visibly changed the text: a word with a zero width
// space inside gained a gap in the middle. They are dropped, and because
// dropping loses nothing a reader could see, they are not reported as
// substitutions either.
func TestZeroWidthRunesAreDroppedNotWidened(t *testing.T) {
	cases := []struct {
		name string
		r    rune
	}{
		{"zero width space", '\u200b'},
		{"word joiner", '\u2060'},
		{"zero width no-break space", '\ufeff'},
	}
	want := string(encode("strafbar", nil))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subs := map[rune]int{}
			got := string(encode("straf"+string(tc.r)+"bar", subs))
			if got != want {
				t.Errorf("encode with %U = %q, want %q", tc.r, got, want)
			}
			if len(subs) != 0 {
				t.Errorf("dropping a zero-width rune was reported as a substitution: %v", subs)
			}
		})
	}
}

// Spacing characters with real width still fold to a space, because that is
// the width they carried.
func TestSpacingRunesStillFoldToASpace(t *testing.T) {
	for _, r := range []rune{'\u2002', '\u2003', '\u2009', '\u202f'} {
		got := string(encode("a"+string(r)+"b", nil))
		if got != "a b" {
			t.Errorf("encode with %U = %q, want %q", r, got, "a b")
		}
	}
}
